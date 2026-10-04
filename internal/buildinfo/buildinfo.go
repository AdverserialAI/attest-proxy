// Package buildinfo carries the proxy version, overridable at link time with
// -ldflags "-X github.com/adverserial/attest-proxy/internal/buildinfo.Version=x.y.z".
package buildinfo

// Version is reported as workload.proxy_version in attestation evidence.
var Version = "0.1.0"
