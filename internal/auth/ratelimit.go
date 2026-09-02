package auth

import (
	"math"
	"sync"
	"time"
)

const (
	defaultMaxBuckets = 8192
	defaultMaxIdle    = 10 * time.Minute
)

// Limiter is a keyed token bucket (requests per minute). The proxy keys it
// by virtual key; the admin-auth failure limiter keys it by client IP.
type Limiter struct {
	mu         sync.Mutex
	buckets    map[string]*bucket
	now        func() time.Time
	maxBuckets int
	maxIdle    time.Duration
}

type bucket struct {
	tokens float64
	last   time.Time
	rpm    int
}

func NewLimiter() *Limiter {
	return &Limiter{
		buckets:    make(map[string]*bucket),
		now:        time.Now,
		maxBuckets: defaultMaxBuckets,
		maxIdle:    defaultMaxIdle,
	}
}

// SetClock replaces the time source. Pass nil to restore time.Now. Tests use
// this to advance the window without sleeping.
func (l *Limiter) SetClock(now func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now == nil {
		l.now = time.Now
		return
	}
	l.now = now
}

// Allow reports whether keyID may proceed. rpm <= 0 disables the limit.
func (l *Limiter) Allow(keyID string, rpm int) bool {
	ok, _ := l.Consume(keyID, rpm)
	return ok
}

// Consume is Allow plus the wait before a rejected caller should retry.
func (l *Limiter) Consume(keyID string, rpm int) (ok bool, retryAfter time.Duration) {
	if rpm <= 0 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, exists := l.buckets[keyID]
	if !exists || b.rpm != rpm {
		if !exists {
			l.evictLocked(now)
		}
		b = &bucket{tokens: float64(rpm), last: now, rpm: rpm}
		l.buckets[keyID] = b
	} else {
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * (float64(rpm) / 60.0)
			if b.tokens > float64(rpm) {
				b.tokens = float64(rpm)
			}
			b.last = now
		}
	}
	if b.tokens < 1 {
		return false, retryAfterLocked(b)
	}
	b.tokens--
	return true, 0
}

func retryAfterLocked(b *bucket) time.Duration {
	if b.tokens >= 1 || b.rpm <= 0 {
		return 0
	}
	need := 1 - b.tokens
	perSec := float64(b.rpm) / 60.0
	sec := need / perSec
	d := time.Duration(math.Ceil(sec) * float64(time.Second))
	if d < time.Second {
		return time.Second
	}
	return d
}

func (l *Limiter) evictLocked(now time.Time) {
	if l.maxIdle > 0 {
		for k, b := range l.buckets {
			if now.Sub(b.last) > l.maxIdle {
				delete(l.buckets, k)
			}
		}
	}
	for l.maxBuckets > 0 && len(l.buckets) >= l.maxBuckets {
		var oldestKey string
		var oldest time.Time
		first := true
		for k, b := range l.buckets {
			if first || b.last.Before(oldest) {
				oldestKey = k
				oldest = b.last
				first = false
			}
		}
		delete(l.buckets, oldestKey)
	}
}
