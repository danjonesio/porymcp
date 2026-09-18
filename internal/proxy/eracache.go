package proxy

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/danjonesio/porymcp/internal/mcpclient"
	"github.com/danjonesio/porymcp/internal/models"
)

// How long the proxy trusts what it learned about an upstream's era.
const (
	// eraTTL is the life of a verdict that listed. Ten minutes is the most a
	// wrong one can cost before it is asked again.
	eraTTL = 10 * time.Minute
	// eraRetry is the life of anything that did NOT list: an unusable verdict,
	// a probe nothing answered, or any listing failure. It is a floor and not
	// an eviction on purpose. memberCatalogues runs on every tools/call as well
	// as every tools/list, so evicting on failure would send a member that is
	// broken for good one probe per agent request, by any key, outside every
	// rate limit. Thirty seconds still heals a wrong verdict quickly.
	eraRetry = 30 * time.Second
	// maxEraEntries bounds the map. An entry is one per upstream id, so this
	// is reached only by an instance with more upstreams than that.
	maxEraEntries = 1024
)

// eraVerdict is what one probe learned about one upstream.
type eraVerdict struct {
	era     mcpclient.Era
	version string
	// fail is set when the upstream is modern and cannot be spoken to. Such a
	// member is skipped without being dialled until the entry expires.
	fail string
	// seen is the upstream's updated_at as it was on the struct the probe was
	// BUILT FROM, never a later read. A probe that races an edit then stores a
	// verdict stamped with the old value, and the next lookup misses.
	seen    time.Time
	expires time.Time
}

// eraCache remembers each upstream's era so a group call pays the probe once.
// It has auth.Limiter's shape: a mutex, a map and an injectable clock, and it
// degrades one entry at a time at its bound.
//
// The key is the upstream id alone, with updated_at compared inside the entry.
// That holds one entry per upstream however often it is edited, and it is safe
// because of what moves updated_at: every PATCH sets it, a no-op save included,
// while RecordUpstreamTest ("a test is not an edit") and a rekey never do. So
// it fingerprints everything the probe depends on (url, transport, auth) and a
// press of Tools does not flush the entry. It is stored as text with nine
// fractional digits and parsed back (store.tsLayout), identical on both
// drivers, and it is compared with Equal, never ==, and never by order: a
// save made after the clock stepped back carries an EARLIER value and must
// still miss.
//
// get, the probe and put are three separate calls on purpose. Folding them
// into one method would hold the mutex across a network round trip and queue
// every member of every group behind one slow upstream.
type eraCache struct {
	mu      sync.Mutex
	entries map[string]eraVerdict
	now     func() time.Time
}

func newEraCache() *eraCache {
	return &eraCache{entries: make(map[string]eraVerdict), now: time.Now}
}

// SetClock replaces the time source. Pass nil to restore time.Now. Tests use
// this to reach an expiry without sleeping, as they do with auth.Limiter.
func (c *eraCache) SetClock(now func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now == nil {
		c.now = time.Now
		return
	}
	c.now = now
}

// get returns the verdict held for id when it was learned from the upstream as
// it is now (updatedAt) and has not expired.
func (c *eraCache) get(id string, updatedAt time.Time) (eraVerdict, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.entries[id]
	if !ok || !v.seen.Equal(updatedAt) || !c.now().Before(v.expires) {
		return eraVerdict{}, false
	}
	return v, true
}

// put stores a verdict for ttl. It is the only inserter. The cache stamps the
// expiry itself because the clock lives under its mutex.
func (c *eraCache) put(id string, v eraVerdict, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	v.expires = now.Add(ttl)
	if _, replacing := c.entries[id]; !replacing {
		c.evictLocked(now)
	}
	c.entries[id] = v
}

// retrySoon brings an entry's expiry forward to the retry floor. It never
// lengthens one, and it does nothing for an id the map does not hold: a member
// refused before it was ever probed (an sse transport, a credential that will
// not decrypt) is skipped on every call, and must not grow the map. It takes
// no updated_at because shortening is always safe; the worst it costs is one
// early probe.
//
// A late put can lengthen an entry retrySoon just shortened, when two calls
// race. That corrects itself only because memberEra is called from inside
// listTools: every put is followed by that caller's own listing, whose failure
// shortens the entry again.
func (c *eraCache) retrySoon(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.entries[id]
	if !ok {
		return
	}
	if floor := c.now().Add(eraRetry); floor.Before(v.expires) {
		v.expires = floor
		c.entries[id] = v
	}
}

// evictLocked makes room for one more entry: expired ones go first, then the
// one that expires soonest, one at a time, as auth.Limiter's evictLocked does.
// Never the whole map, which would send every member of every group a probe
// on the next call.
func (c *eraCache) evictLocked(now time.Time) {
	for id, v := range c.entries {
		if !now.Before(v.expires) {
			delete(c.entries, id)
		}
	}
	for len(c.entries) >= maxEraEntries {
		var oldestID string
		var oldest time.Time
		first := true
		for id, v := range c.entries {
			if first || v.expires.Before(oldest) {
				oldestID, oldest, first = id, v.expires, false
			}
		}
		delete(c.entries, oldestID)
	}
}

// memberEra is the one lookup of an upstream's era: the cached verdict, or a
// fresh server/discover probe whose verdict is then cached. PORM-32's route
// cache is expected to absorb it, which is why nothing else reads h.eras for a
// verdict.
//
// The caller has already refused a transport it cannot dial and read the
// credential, so a member that must not be contacted is never probed. seen is
// up.UpdatedAt from the struct this was handed, the one the probe is built
// from. The probe carries PoryMCP's own constants and nothing of the inbound
// request. The log line carries no upstream string: the era is one of two
// constants.
func (h *Handler) memberEra(ctx context.Context, up *models.Upstream, plainAuth json.RawMessage) eraVerdict {
	if v, ok := h.eras.get(up.ID, up.UpdatedAt); ok {
		return v
	}
	pr := mcpclient.ProbeEra(ctx, h.client, up, plainAuth)
	v := eraVerdict{era: pr.Era, version: pr.Version, fail: pr.Fail, seen: up.UpdatedAt}
	if ctx.Err() != nil {
		// The client went away mid-probe. "Nothing answered" is then a fact
		// about the caller and not the upstream, so it is not remembered.
		return v
	}
	ttl := eraTTL
	if pr.Fail != "" || !pr.Reached {
		ttl = eraRetry
	}
	h.eras.put(up.ID, v, ttl)
	if h.log != nil {
		h.log.Debug("member era probed", "slug", up.Slug, "upstream_id", up.ID,
			"era", string(pr.Era), "reached", pr.Reached, "latency_ms", pr.LatencyMS)
	}
	return v
}
