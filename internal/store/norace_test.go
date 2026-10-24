//go:build !race

package store

// raceBuild is false outside make test-race.
const raceBuild = false
