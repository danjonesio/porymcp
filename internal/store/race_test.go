//go:build race

package store

// raceBuild reports whether this test binary carries the race detector. modernc
// is Go, so the detector slows every SQLite step, and the deadline fixture
// seeds fewer rows to keep its walk near the same length.
const raceBuild = true
