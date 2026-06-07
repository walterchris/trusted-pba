//go:build !tamago

// Command pba is the Trusted PBA UEFI application.
//
// The real entrypoint (main.go) is a TamaGo UEFI binary built under GOOS=tamago.
// This host stub lets host tooling (`go build`/`go test ./...`, vet, linters)
// compile the package without the tamago-only dependencies, and prints guidance
// if someone runs the host build by mistake.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr,
		"trusted-pba is a UEFI application and must be built with the TamaGo "+
			"toolchain (GOOS=tamago GOARCH=amd64). Use `task build`.")
	os.Exit(1)
}
