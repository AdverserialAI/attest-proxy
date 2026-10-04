# syntax=docker/dockerfile:1

# Runtime mounts in the dstack compose:
#   /var/run/dstack.sock  (guest agent — TDX quotes)
#   $CERT_DIR             (dstack volume — ACME account key + certs, when
#                          ACME_DOMAINS is configured)

FROM golang:1.23-bookworm@sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db AS build
WORKDIR /src

# No go.sum: this module is stdlib-only by invariant.
COPY go.mod ./
COPY cmd/ cmd/
COPY internal/ internal/

RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
      -o /out/attest-proxy ./cmd/attest-proxy

FROM gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
COPY --from=build /out/attest-proxy /attest-proxy
EXPOSE 8443
USER nonroot
ENTRYPOINT ["/attest-proxy"]
