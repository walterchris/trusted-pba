//go:build !hwdebug

package main

// sedDebug is off by default; the compiler dead-strips the guarded debug prints.
// Enable with -tags hwdebug (see hwdebug_on.go).
const sedDebug = false
