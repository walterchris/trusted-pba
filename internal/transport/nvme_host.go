//go:build !tamago

package transport

// NVMe is the off-target placeholder so the package builds and the opal.Transport
// and credential.Serialer assertions hold on the host. The real NVMe pass-thru
// carrier exists only under TamaGo; off-target builds fail closed via
// ErrUnavailable (defined in uefi_host.go).
type NVMe struct{}

// NewAllNVMe always fails on the host (no firmware).
func NewAllNVMe() ([]*NVMe, error) { return nil, ErrUnavailable }

// Send always fails on the host.
func (n *NVMe) Send(_ uint8, _ uint16, _ []byte) error { return ErrUnavailable }

// Recv always fails on the host.
func (n *NVMe) Recv(_ uint8, _ uint16, _ int) ([]byte, error) { return nil, ErrUnavailable }

// Serial always fails on the host.
func (n *NVMe) Serial() ([]byte, error) { return nil, ErrUnavailable }
