//go:build hwdebug

package main

// sedDebug enables per-drive Storage-Security discovery debug output in selectSED
// (build with -tags hwdebug). NEVER enabled in default/release builds.
const sedDebug = true
