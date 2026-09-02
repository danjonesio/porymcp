package auth

import (
	"testing"
	"time"
)

func TestLimiterDisabled(t *testing.T) {
	l := NewLimiter()
	if !l.Allow("a", 0) {
		t.Fatal("rpm 0 should allow")
	}
}

func TestLimiterBlocksBurst(t *testing.T) {
	l := NewLimiter()
	allowed := 0
	for i := 0; i < 5; i++ {
		if l.Allow("a", 3) {
			allowed++
		}
	}
	if allowed != 3 {
		t.Fatalf("allowed %d want 3", allowed)
	}
}

func TestLimiterRefillAndRetryAfter(t *testing.T) {
	l := NewLimiter()
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	l.SetClock(func() time.Time { return now })

	for i := 0; i < 10; i++ {
		ok, _ := l.Consume("ip", 10)
		if !ok {
			t.Fatalf("failure %d should be allowed", i+1)
		}
	}
	ok, retry := l.Consume("ip", 10)
	if ok {
		t.Fatal("11th consume should be rejected")
	}
	if retry < time.Second {
		t.Fatalf("retry-after %s, want at least 1s", retry)
	}

	now = now.Add(time.Minute)
	ok, _ = l.Consume("ip", 10)
	if !ok {
		t.Fatal("budget should refill after a minute")
	}
}

func TestLimiterEvictsIdleAndCapsMap(t *testing.T) {
	l := NewLimiter()
	l.maxBuckets = 3
	l.maxIdle = time.Minute
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	l.SetClock(func() time.Time { return now })

	for _, k := range []string{"a", "b", "c"} {
		if !l.Allow(k, 5) {
			t.Fatalf("seed %s", k)
		}
	}
	now = now.Add(2 * time.Minute)
	if !l.Allow("d", 5) {
		t.Fatal("new key after idle should evict the rest")
	}
	l.mu.Lock()
	n := len(l.buckets)
	_, hasA := l.buckets["a"]
	l.mu.Unlock()
	if n != 1 || hasA {
		t.Fatalf("buckets=%d hasA=%v, want only the new key", n, hasA)
	}

	now = now.Add(time.Second)
	for _, k := range []string{"e", "f", "g"} {
		if !l.Allow(k, 5) {
			t.Fatalf("cap seed %s", k)
		}
	}
	l.mu.Lock()
	n = len(l.buckets)
	l.mu.Unlock()
	if n > 3 {
		t.Fatalf("map grew to %d, cap is 3", n)
	}
}
