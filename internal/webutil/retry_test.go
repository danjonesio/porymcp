package webutil

import (
	"testing"
	"time"
)

func TestRetryAfterSeconds(t *testing.T) {
	cases := map[time.Duration]string{
		0:                       "1",
		300 * time.Millisecond:  "1",
		time.Second:             "1",
		1001 * time.Millisecond: "2",
		59 * time.Second:        "59",
	}
	for d, want := range cases {
		if got := RetryAfterSeconds(d); got != want {
			t.Errorf("%v: got %q want %q", d, got, want)
		}
	}
}
