# syntax=docker/dockerfile:1

# Runtime mounts in the dstack compose:
#   /var/run/dstack.sock  (guest agent — TDX quotes)
#   $CERT_DIR             (dstack volume — ACME account key + certs, when
#                          ACME_DOMAINS is configured)

# Go 1.26 provides the RFC 9180 HPKE implementation required by the
# standards-based EHBP reference transport.
FROM golang:1.26.9-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c AS build
WORKDIR /src

# Injected by the release workflow as the git tag; attestation evidence
# reports it as workload.proxy_version.
ARG VERSION=0.1.0

# EHBP is the pinned MIT-licensed reference implementation used by the
# browser, SDK and proxy; copy both module files for deterministic builds.
COPY go.mod go.sum ./
COPY cmd/ cmd/
COPY internal/ internal/

RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X github.com/adverserial/attest-proxy/internal/buildinfo.Version=${VERSION}" \
      -o /out/attest-proxy ./cmd/attest-proxy
RUN mkdir -p /out/state && chown 65532:65532 /out/state

FROM gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
COPY --from=build /out/attest-proxy /attest-proxy
COPY --from=build --chown=65532:65532 /out/state /state
EXPOSE 8443
USER nonroot
ENTRYPOINT ["/attest-proxy"]
