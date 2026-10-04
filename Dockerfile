# syntax=docker/dockerfile:1

# TODO(release): pin base image digests for reproducible builds:
#   golang:1.23-bookworm@sha256:<digest>
#   gcr.io/distroless/static-debian12@sha256:<digest>
# and record them in the release manifest + policy.json (WP-1/WP-5).
#
# Runtime mounts in the dstack compose:
#   /var/run/dstack.sock  (guest agent — TDX quotes)
#   $CERT_DIR             (dstack volume — ACME account key + certs, when
#                          ACME_DOMAINS is configured)

FROM golang:1.23-bookworm AS build
WORKDIR /src

# No go.sum: this module is stdlib-only by invariant.
COPY go.mod ./
COPY cmd/ cmd/
COPY internal/ internal/

RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
      -o /out/attest-proxy ./cmd/attest-proxy

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/attest-proxy /attest-proxy
EXPOSE 8443
USER nonroot
ENTRYPOINT ["/attest-proxy"]
