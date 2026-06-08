//go:build !tamago

package boottime

import "time"

// Now returns the build-time floor on the host: there is no pre-boot RTC to read,
// and a fixed value keeps host tests deterministic.
func Now() time.Time { return Floor() }
