// Package boottime supplies the wall-clock time the PBA uses for X.509 chain
// validity when verifying a second-stage image. Pre-boot, the only clock is the
// platform RTC, which may be unset or wrong; per ADR-0007 we read it but never
// trust a value below a compiled-in build-time floor, and fall back to the floor
// when no reliable reading is available.
//
// Now is platform-specific (RTC on TamaGo, the floor on the host); Floor and the
// fallback policy live here so both share one definition.
package boottime

import "time"

// buildFloor is the earliest time the PBA will trust. It must not predate the
// validity of any image the PBA is expected to accept. Override at link time with
//
//	-ldflags "-X github.com/walterchris/trusted-pba/internal/boottime.buildFloor=2026-06-01T00:00:00Z"
var buildFloor = "2026-01-01T00:00:00Z"

// Floor returns the build-time floor. A malformed override fails closed to the
// Go zero time, which imageverify rejects (ErrNoTime), rather than to time.Now().
func Floor() time.Time {
	t, err := time.Parse(time.RFC3339, buildFloor)
	if err != nil {
		return time.Time{}
	}
	return t
}

// clamp returns rtc when it is a usable reading at or after the floor, otherwise
// the floor. It is the shared fallback policy used by the platform Now.
func clamp(rtc time.Time, ok bool) time.Time {
	floor := Floor()
	if !ok || rtc.Before(floor) {
		return floor
	}
	return rtc
}
