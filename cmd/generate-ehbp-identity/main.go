// generate-ehbp-identity creates a sealed EHBP receiver identity for one
// confidential proxy deployment. It intentionally writes only to a mode-0600
// file and never prints the private identity to stdout or logs.
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
)

func main() {
	out := flag.String("out", "", "mode-0600 file to receive EHBP_IDENTITY_B64")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "usage: generate-ehbp-identity --out /secure/path/ehbp-identity")
		os.Exit(2)
	}
	if _, err := os.Stat(*out); err == nil {
		fmt.Fprintln(os.Stderr, "refusing to overwrite existing output")
		os.Exit(2)
	} else if !os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	identity, err := ehbpidentity.NewIdentity()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	raw, err := identity.Export()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, []byte(base64.RawURLEncoding.EncodeToString(raw)+"\n"), 0600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
