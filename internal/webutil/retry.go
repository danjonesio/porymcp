package webutil

import (
	"math"
	"strconv"
	"time"
)

// RetryAfterSeconds is the Retry-After value for a caller a limiter turned
// away: the wait the limiter computed, in whole seconds and never zero,
// because a client that honours a "0" backs off for no time at all, which is
// the one thing a budget exists to prevent. The management API's 429 and the
// proxy's HTTP relay door (PORM-146) both write it from here, so the rounding
// rule exists once.
func RetryAfterSeconds(d time.Duration) string {
	sec := int(math.Ceil(d.Seconds()))
	if sec < 1 {
		sec = 1
	}
	return strconv.Itoa(sec)
}
