//go:build tamago && amd64

package boottime

import (
	"time"

	"github.com/usbarmory/go-boot/uefi/x64"
)

// Now reads the platform RTC and clamps it to the build-time floor: a failed read
// or a reading earlier than the floor (an unset/garbage clock) yields the floor,
// so chain validity is never checked against an attacker-influenced earlier time.
func Now() time.Time {
	t, err := x64.RTC.Now()
	return clamp(t, err == nil)
}
