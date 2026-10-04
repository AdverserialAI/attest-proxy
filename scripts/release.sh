#!/usr/bin/env bash
# attest-proxy release builder: reproducible build + SBOM + cosign signature.
# Produces dist/ with the binary, its sha256, SBOM (SPDX), and a cosign
# signature bundle (keyless via Fulcio when CI, or COSIGN_KEY for local).
#
# Usage: bash scripts/release.sh <version-tag>   e.g. scripts/release.sh v0.1.0
set -euo pipefail
cd "$(dirname "$0")/.."
TAG="${1:?usage: release.sh <tag>}"
OUT="dist/$TAG"
mkdir -p "$OUT"

# 1. reproducible build: pinned toolchain, no CGO, trimmed paths, no VCS stamp.
export CGO_ENABLED=0 GOFLAGS="-trimpath -buildvcs=false" GOPROXY=proxy.golang.org
go build -ldflags "-s -w -X github.com/adverserial/attest-proxy/internal/buildinfo.Version=$TAG" \
  -o "$OUT/attest-proxy" ./cmd/attest-proxy
shasum -a 256 "$OUT/attest-proxy" | awk '{print $1}' > "$OUT/attest-proxy.sha256"

# 2. SBOM: module list from the binary itself (stdlib-only → this is short) + syft if available.
go version -m "$OUT/attest-proxy" > "$OUT/sbom.go-modules.txt"
if command -v syft >/dev/null; then
  syft "$OUT/attest-proxy" -o spdx-json > "$OUT/sbom.spdx.json"
else
  echo "note: syft not installed; sbom.spdx.json skipped (install: brew install syft)" >&2
fi

# 3. sign the digest. Keyless in CI (OIDC), local key via COSIGN_KEY otherwise.
if command -v cosign >/dev/null; then
  if [ -n "${COSIGN_KEY:-}" ]; then
    cosign sign-blob --key "$COSIGN_KEY" --bundle "$OUT/signature.cosign.bundle" "$OUT/attest-proxy.sha256"
  else
    cosign sign-blob --yes --bundle "$OUT/signature.cosign.bundle" "$OUT/attest-proxy.sha256" || \
      echo "note: keyless signing needs CI OIDC; skipped locally" >&2
  fi
else
  echo "note: cosign not installed; signature skipped (install: brew install cosign)" >&2
fi

# 4. build receipt: the policy-facing record.
cat > "$OUT/release.json" <<EOF
{
  "name": "adverserial-attest-proxy",
  "version": "$TAG",
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "binary_sha256": "$(cat "$OUT/attest-proxy.sha256")",
  "go_version": "$(go version | awk '{print $3}')",
  "reproduce": "CGO_ENABLED=0 GOFLAGS='-trimpath -buildvcs=false' go build -ldflags '-s -w -X .../buildinfo.Version=$TAG' ./cmd/attest-proxy"
}
EOF
echo "release written to $OUT"; ls "$OUT"
