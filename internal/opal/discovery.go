package opal

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Level 0 Discovery feature codes (TCG Storage Opal SSC).
const (
	featLocking   = 0x0002
	featOpalV1SSC = 0x0200
	featOpalV2SSC = 0x0203

	discoveryHdrLen = 48
	featureHdrLen   = 4
)

// ErrDiscovery is returned for a malformed Level 0 Discovery response.
var ErrDiscovery = errors.New("opal: malformed Level 0 Discovery")

// Discovery is the subset of Level 0 Discovery the PBA needs: the session ComID
// and the Locking feature state.
type Discovery struct {
	OpalSSC          bool   // an Opal SSC feature descriptor is present
	BaseComID        uint16 // ComID to use for sessions
	LockingSupported bool
	LockingEnabled   bool
	Locked           bool
	MBREnabled       bool
	MBRDone          bool
}

// parseDiscovery decodes a Level 0 Discovery response, failing closed on any
// truncation or inconsistent length field.
func parseDiscovery(data []byte) (*Discovery, error) {
	if len(data) < discoveryHdrLen {
		return nil, fmt.Errorf("%w: short header", ErrDiscovery)
	}
	// Total valid length = length field + the 4 length bytes themselves.
	total := int(binary.BigEndian.Uint32(data[0:4])) + 4
	if total < discoveryHdrLen || total > len(data) {
		return nil, fmt.Errorf("%w: bad length field %d", ErrDiscovery, total)
	}

	d := &Discovery{}
	for off := discoveryHdrLen; off+featureHdrLen <= total; {
		code := binary.BigEndian.Uint16(data[off:])
		flen := int(data[off+3])
		body := off + featureHdrLen
		if body+flen > total {
			return nil, fmt.Errorf("%w: feature 0x%04x length overruns", ErrDiscovery, code)
		}
		fd := data[body : body+flen]
		switch code {
		case featLocking:
			if len(fd) < 1 {
				return nil, fmt.Errorf("%w: short Locking feature", ErrDiscovery)
			}
			b := fd[0]
			d.LockingSupported = b&0x01 != 0
			d.LockingEnabled = b&0x02 != 0
			d.Locked = b&0x04 != 0
			d.MBREnabled = b&0x10 != 0
			d.MBRDone = b&0x20 != 0
		case featOpalV1SSC, featOpalV2SSC:
			if len(fd) < 2 {
				return nil, fmt.Errorf("%w: short Opal SSC feature", ErrDiscovery)
			}
			d.OpalSSC = true
			d.BaseComID = binary.BigEndian.Uint16(fd[0:2])
		}
		off = body + flen
	}
	if !d.OpalSSC {
		return nil, fmt.Errorf("%w: no Opal SSC feature", ErrDiscovery)
	}
	return d, nil
}

// buildDiscovery encodes d as a Level 0 Discovery response (Locking feature + Opal
// SSC v2 feature). Used by the mock TPer and the golden fixture.
func buildDiscovery(d *Discovery) []byte {
	var lock byte
	if d.LockingSupported {
		lock |= 0x01
	}
	if d.LockingEnabled {
		lock |= 0x02
	}
	if d.Locked {
		lock |= 0x04
	}
	if d.MBREnabled {
		lock |= 0x10
	}
	if d.MBRDone {
		lock |= 0x20
	}

	body := make([]byte, 0, 32)
	// Locking feature (0x0002), 12 bytes of feature data.
	lf := make([]byte, featureHdrLen+12)
	binary.BigEndian.PutUint16(lf[0:], featLocking)
	lf[3] = 12
	lf[4] = lock
	body = append(body, lf...)
	// Opal SSC v2 feature (0x0203), 16 bytes; first 2 are the base ComID.
	of := make([]byte, featureHdrLen+16)
	binary.BigEndian.PutUint16(of[0:], featOpalV2SSC)
	of[3] = 16
	binary.BigEndian.PutUint16(of[4:], d.BaseComID)
	binary.BigEndian.PutUint16(of[6:], 1) // number of ComIDs
	body = append(body, of...)

	out := make([]byte, discoveryHdrLen+len(body))
	binary.BigEndian.PutUint32(out[0:], u32(discoveryHdrLen+len(body)-4)) // length field
	out[7] = 0x10                                                         // data structure revision
	copy(out[discoveryHdrLen:], body)
	return out
}
