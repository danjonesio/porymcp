//go:build !race

package main

// raceBuild is false outside make test-race: the child is the shipped build.
const raceBuild = false
