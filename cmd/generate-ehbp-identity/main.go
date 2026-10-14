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
	// O_EXCL is atomic: it refuses any existing path, including a dangling
	// symlink, so the identity can never be steered onto an attacker-chosen
	// file (dangling-symlink creation or swap-in overwrite).
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "refusing to overwrite existing output:", err)
		os.Exit(2)
	}
	if _, err := f.WriteString(base64.RawURLEncoding.EncodeToString(raw) + "\n"); err != nil {
		_ = f.Close()
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := f.Close(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
