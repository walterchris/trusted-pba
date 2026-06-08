package opal

// UID is an 8-byte TCG object/method identifier (big-endian on the wire).
type UID [8]byte

// Well-known TCG Opal UIDs. Values are byte-identical to the TCG Opal SSC and to
// the Linux kernel's sed-opal table (proven against real drives), so the encoded
// streams this package produces are accepted by real hardware (ADR-0004).
var (
	uidSMUID       = UID{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff} // Session Manager
	uidLockingSP   = UID{0x00, 0x00, 0x02, 0x05, 0x00, 0x00, 0x00, 0x02}
	uidGlobalRange = UID{0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x01} // Locking_GlobalRange
	uidMBRControl  = UID{0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x00, 0x01}

	// Authorities.
	uidAuthSID    = UID{0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x06}
	uidAuthAdmin1 = UID{0x00, 0x00, 0x00, 0x09, 0x00, 0x01, 0x00, 0x01}
	uidAuthUser1  = UID{0x00, 0x00, 0x00, 0x09, 0x00, 0x03, 0x00, 0x01}

	// Methods.
	uidMethodStartSession = UID{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x02}
	uidMethodSyncSession  = UID{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x03}
	uidMethodSet          = UID{0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x17}
)

// Authority selects the credential identity used to authenticate a session.
type Authority uint8

const (
	// AuthorityAdmin1 is the Locking SP Admin1 authority (range/MBR administration).
	AuthorityAdmin1 Authority = iota
	// AuthorityUser1 is the Locking SP User1 authority.
	AuthorityUser1
	// AuthoritySID is the Admin SP owner (SID) authority.
	AuthoritySID
)

func (a Authority) uid() (UID, bool) {
	switch a {
	case AuthorityAdmin1:
		return uidAuthAdmin1, true
	case AuthorityUser1:
		return uidAuthUser1, true
	case AuthoritySID:
		return uidAuthSID, true
	default:
		return UID{}, false
	}
}
