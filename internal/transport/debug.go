package transport

// Debugf, when non-nil, receives transport diagnostics. TEMPORARY (#79) hardware
// bring-up aid — must be removed before merge.
var Debugf func(format string, args ...any)

func dbg(format string, args ...any) {
	if Debugf != nil {
		Debugf(format, args...)
	}
}
