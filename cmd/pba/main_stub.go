// Host stub: the real PBA entrypoint (main.go) is a TamaGo UEFI binary and only
// builds under GOOS=tamago. This stub lets host tooling (`go build`/`go test
// ./...`, vet, IDEs) compile the package without the tamago-only dependencies,
// and prints guidance if someone runs the host build by mistake.

//go:build !tamago

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr,
		"trusted-pba is a UEFI application and must be built with the TamaGo "+
			"toolchain (GOOS=tamago GOARCH=amd64). Use `make build`.")
	os.Exit(1)
}
