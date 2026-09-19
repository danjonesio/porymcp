package proxy

import (
	"fmt"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/mcpclient"
)

// TestEraCache pins the cache's rules (PORM-151 security requirement 11 and the
// one expiry rule): keyed by id, invalidated by any change of updated_at,
// expired by an injected clock, shortened and never lengthened by a failure,
// silent about ids it never held, and bounded one entry at a time.
func TestEraCache(t *testing.T) {
	base := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	saved := base.Add(-time.Hour) // the upstream's updated_at
	modern := eraVerdict{era: mcpclient.EraModern, version: mcpclient.RevisionModern, seen: saved}

	newCache := func() (*eraCache, *time.Time) {
		now := base
		c := newEraCache()
		c.SetClock(func() time.Time { return now })
		return c, &now
	}

	t.Run("hit", func(t *testing.T) {
		c, _ := newCache()
		c.put("u1", modern, eraTTL)
		got, ok := c.get("u1", saved)
		if !ok || got.era != mcpclient.EraModern || got.version != mcpclient.RevisionModern {
			t.Errorf("get = %+v %v, want the stored verdict", got, ok)
		}
		if _, ok := c.get("u2", saved); ok {
			t.Error("another upstream's id hit this entry")
		}
	})

	t.Run("an edit is a miss, whichever way the clock moved", func(t *testing.T) {
		c, _ := newCache()
		c.put("u1", modern, eraTTL)
		if _, ok := c.get("u1", saved.Add(time.Second)); ok {
			t.Error("a later updated_at still hit")
		}
		// A save made after the clock stepped back carries an earlier value.
		if _, ok := c.get("u1", saved.Add(-time.Second)); ok {
			t.Error("an earlier updated_at still hit; the comparison must be Equal, not an ordering")
		}
		// The same instant in another location is the same instant.
		if _, ok := c.get("u1", saved.In(time.FixedZone("x", 3600))); !ok {
			t.Error("the same instant in another zone missed; the comparison must be Equal, not ==")
		}
	})

	t.Run("expiry", func(t *testing.T) {
		c, now := newCache()
		c.put("u1", modern, eraTTL)
		*now = base.Add(eraTTL - time.Second)
		if _, ok := c.get("u1", saved); !ok {
			t.Error("missed one second before the ten minutes were up")
		}
		*now = base.Add(eraTTL)
		if _, ok := c.get("u1", saved); ok {
			t.Error("still hit at the expiry")
		}
	})

	t.Run("retrySoon shortens and never lengthens", func(t *testing.T) {
		c, now := newCache()
		c.put("u1", modern, eraTTL)
		c.retrySoon("u1")
		*now = base.Add(eraRetry - time.Second)
		if _, ok := c.get("u1", saved); !ok {
			t.Error("missed inside the retry floor; a failing member would be probed on every call")
		}
		// Asked again late in the window: the floor must not move out.
		c.retrySoon("u1")
		*now = base.Add(eraRetry)
		if _, ok := c.get("u1", saved); ok {
			t.Error("still hit at the retry floor; a second failure lengthened the entry")
		}

		// An entry already shorter than the floor keeps its own expiry.
		c.put("u2", modern, 5*time.Second)
		c.retrySoon("u2")
		*now = now.Add(5 * time.Second)
		if _, ok := c.get("u2", saved); ok {
			t.Error("retrySoon lengthened an entry that expired sooner than the floor")
		}
	})

	t.Run("retrySoon on an id never stored inserts nothing", func(t *testing.T) {
		c, _ := newCache()
		c.retrySoon("never-probed")
		if n := len(c.entries); n != 0 {
			t.Errorf("%d entries after retrySoon on an unknown id, want 0: put is the only inserter", n)
		}
	})

	t.Run("put sweeps what has expired", func(t *testing.T) {
		c, now := newCache()
		c.put("old", modern, eraRetry)
		*now = base.Add(time.Minute)
		c.put("new", modern, eraTTL)
		if _, held := c.entries["old"]; held {
			t.Error("an expired entry survived the next insert")
		}
	})

	t.Run("at the bound it drops the soonest to expire, never the map", func(t *testing.T) {
		c, now := newCache()
		for i := 0; i < maxEraEntries; i++ {
			// Each a millisecond apart, so entry 0 expires soonest.
			*now = base.Add(time.Duration(i) * time.Millisecond)
			c.put(fmt.Sprintf("u%04d", i), modern, eraTTL)
		}
		*now = base.Add(time.Duration(maxEraEntries) * time.Millisecond)
		if base.Add(eraTTL).Before(*now) {
			t.Fatal("the fixture outran the TTL; entries would be swept, not evicted")
		}
		c.put("one-more", modern, eraTTL)
		if n := len(c.entries); n != maxEraEntries {
			t.Fatalf("%d entries, want %d", n, maxEraEntries)
		}
		if _, held := c.entries["u0000"]; held {
			t.Error("the soonest to expire was kept")
		}
		for _, id := range []string{"u0001", fmt.Sprintf("u%04d", maxEraEntries-1), "one-more"} {
			if _, ok := c.get(id, saved); !ok {
				t.Errorf("%s no longer hits; the bound must cost one entry, not the map", id)
			}
		}
		// Replacing an entry that is already held evicts nothing.
		c.put("one-more", modern, eraTTL)
		if n := len(c.entries); n != maxEraEntries {
			t.Errorf("%d entries after a replace, want %d", n, maxEraEntries)
		}
	})
}
