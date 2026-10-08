//go:build race

package main

// raceBuild reports whether this test binary carries the race detector. The
// child binary is then built with -race too, so a race in main's wiring
// fails the run (the child exits 66), and GORACE removes the race runtime's
// one second sleep on every exit with status 0.
const raceBuild = true
