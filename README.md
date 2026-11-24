# attest-proxy

`attest-proxy` is the single public process of an Adverserial confidential
inference deployment. It runs **inside** a Phala dstack confidential VM
(Intel TDX) in front of the SGLang inference server and:

1. terminates TLS in-enclave. The TLS key is generated inside the VM, either
   by the built-in ACME DNS-01 client (Cloudflare in the reference deployment;
   Gandi LiveDNS is also supported) or, when no ACME domain is configured, as
   an in-memory self-signed P-256 key,
2. serves nonce-bound TDX attestation evidence plus a signed ES256
   verification receipt (`GET /attestation`). In confidential mode every
   private key is generated inside the enclave and none is accepted from
   configuration (see *Where each key comes from*),
3. forwards an allowlist of model API routes to the inference server inside
   the same VM and answers 404 for everything else, and
4. never logs request or response content. The access log carries method,
   path class, status, byte count, and duration; other log lines carry
   request IDs and error reasons. There is no content-logging switch.

This README describes the code at tag `v0.1.0-rc.33` and the deployment in
[`deploy/reference/docker-compose.cyberseek-v5.yml`](./deploy/reference/docker-compose.cyberseek-v5.yml).
Start with *Where each key comes from*, *What the operator can and cannot
do*, and *Known limits* if you are assessing the trust model.

The only direct third-party dependency is the MIT-licensed Tinfoil EHBP
reference implementation (see *Third-party protocol implementation* below);
it brings `golang.org/x/crypto`, `golang.org/x/sys`, and `logrus` with it.
Everything else is the Go standard library. Requires Go 1.26+.

## Build, test, run

```sh
go build ./...
go vet ./...
go test ./...

# Local development (synthetic attestation evidence, no dstack, no billing):
DEV_MODE=1 AUTH_REQUIRED=0 go run ./cmd/attest-proxy
```

`AUTH_REQUIRED` defaults to on and then needs `BILLING_URL` and
`BILLING_WRITER_SECRET`; without them the process exits at startup. The
production shape is confidential mode inside a dstack CVM; see *Reference
deployment* for the full set of variables it needs.

Docker:

```sh
docker build -t adverserial-attest-proxy .
docker run --rm -p 8443:8443 -e DEV_MODE=1 -e AUTH_REQUIRED=0 \
  adverserial-attest-proxy
```

`Dockerfile.collector` and `Dockerfile.measurer` build the two sidecar
images (GPU evidence collector and model measurer).

## Configuration (environment)

| Variable | Default | Meaning |
| --- | --- | --- |
| `LISTEN_ADDR` | `:8443` | TLS listen address |
| `UPSTREAM` | `http://127.0.0.1:30000` | Inference server. In `CONFIDENTIAL_MODE` it must be a loopback address, or `http://<name>:<port>` where `<name>` is a single-label service name (`^[a-z][a-z0-9-]{0,62}$`, no dots) on the VM-internal Docker network with an explicit port, e.g. `http://sglang:30000` (the reference deployment). Anything else is refused. The proxy checks only the shape of the name; that the network has no route out of the VM is a property of the compose file (`internal: true`). |
| `UPSTREAM_BEARER_TOKEN_FILE` | _(empty)_ | File holding the SGLang-only credential (`^[A-Za-z0-9_-]{32,128}$`, one optional trailing newline). Required in `CONFIDENTIAL_MODE`. Written on every VM boot by a one-shot init container into a volume shared with the model runtime. Startup waits up to 120 s for a valid file; it is re-read when its mtime or size changes (checked at most once per second). It replaces the client entitlement before the upstream request and is never logged. |
| `UPSTREAM_BEARER_TOKEN` | _(empty)_ | Development only: the same credential from the environment. **Refused in `CONFIDENTIAL_MODE`**; mutually exclusive with `UPSTREAM_BEARER_TOKEN_FILE`. |
| `ENCLAVE_KEY_DIR` | _(empty)_ | Absolute directory on the encrypted state volume (e.g. `/state/keys`) for the enclave-generated receipt and meter signing keys. Required in `CONFIDENTIAL_MODE`. |
| `INFERENCE_STATUS_FILE` | _(empty)_ | Optional JSON progress file written by the model runtime's launcher; a whitelisted, sanitized copy is served under `inference` at `/statusz`. |
| `MODEL_ID` | `lordx64/cyberglm` | Served model ID (receipt claim `model_id`) |
| `POLICY_ID` | `adverserial-policy/dev` | Policy identifier from the public policy registry |
| `ENDPOINT` | `https://api.adverserial.ai` | Public base URL (receipt claim `endpoint`) |
| `RECEIPT_ISSUER` | `https://verify.adverserial.ai` | Receipt claim `iss` |
| `RECEIPT_AUDIENCE` | `https://chat.adverserial.ai` | Receipt claim `aud` |
| `RECEIPT_SIGNING_SEED` | _(empty)_ | Development only: 32-byte base64url seed for a deterministic P-256 receipt signer. **Refused in `CONFIDENTIAL_MODE`.** |
| `COMPOSE_DIGEST` | _(empty)_ | `sha256:` digest of the dstack compose config |
| `MODEL_DIGEST` | _(empty)_ | `sha256:` digest of the model artifact. `CONFIDENTIAL_MODE` requires this or `MODEL_MANIFEST_FILE`. |
| `MODEL_MANIFEST_FILE` | _(empty)_ | Manifest written by the model measurer (`sha256-tree-v1`). When set, its digest becomes the model digest at startup; the proxy exits if the file is missing, names another model, or disagrees with `MODEL_DIGEST`. |
| `RUNTIME_DIGEST` | _(empty)_ | Expected runtime measurement digest |
| `DSTACK_SOCKET` | `/var/run/dstack.sock` | dstack guest agent unix socket |
| `DEV_MODE` | `false` | Skip dstack; emit synthetic evidence with `"dev": true` |
| `CORS_ALLOW_ORIGIN` | _(empty)_ | If set, `Access-Control-Allow-Origin` on proxied API routes |
| `TLS_HOSTNAMES` | host of `ENDPOINT`, `localhost` | Comma-separated SANs for the self-signed cert |
| `PUBLIC_BASE_URL` | `ENDPOINT` | Externally reachable base URL; used for `attestation_url` and `expected.endpoint` in the `/v1/models` injection |
| `VERIFICATION_URL` | `https://verify.adverserial.ai` | Public verifier site advertised to clients |
| `ATTESTED_MODELS` | _(empty = all)_ | Comma-separated model IDs eligible for the `/v1/models` injection |
| `ACME_DOMAINS` | _(empty = self-signed)_ | Comma-separated domains to certify via ACME DNS-01 |
| `ACME_EMAIL` | — | ACME account contact (required when `ACME_DOMAINS` set) |
| `ACME_DIRECTORY_URL` | Let's Encrypt production | Use the LE **staging** directory while testing issuance |
| `DNS_PROVIDER` | `gandi` | ACME DNS-01 provider: `gandi` or `cloudflare`. The reference deployment sets `cloudflare`. |
| `GANDI_PAT` | — | Gandi LiveDNS personal access token (required for ACME with `DNS_PROVIDER=gandi`) |
| `GANDI_ZONE` | — | Gandi DNS zone owning the domains, e.g. `adverserial.ai` |
| `CLOUDFLARE_API_TOKEN` | — | Cloudflare API token with Edit-zone-DNS on the zone (required for ACME with `DNS_PROVIDER=cloudflare`) |
| `CLOUDFLARE_ZONE` | — | Cloudflare DNS zone owning the domains, e.g. `adverserial.ai` |
| `CERT_DIR` | — | Directory on the VM's state volume holding the ACME account key, the certificate, and the certificate key, all generated inside the VM |
| `AUTH_REQUIRED` | `1` (on) | Gate `POST /v1/*` behind billing `/auth/check` |
| `BILLING_URL` | — | Billing service base URL (required when `AUTH_REQUIRED` on) |
| `BILLING_WRITER_SECRET` | — | Bearer token for billing writes (required when `AUTH_REQUIRED` on) |
| `CONFIDENTIAL_MODE` | `0` | Enable local billing-entitlement verification, enclave-generated keys, the route allowlist, and the durable meter. Requires `AUTH_REQUIRED=0` and `EHBP_REQUIRED=1`; mutually exclusive with `DEV_MODE`. Raw customer API keys are rejected at this boundary. |
| `CONFIDENTIAL_ACTIVATION` | `pre-activation` | `pre-activation` or `active`. Until it is `active`, every `POST /v1/*` is answered 503 before the body is read; attestation routes work. |
| `ENTITLEMENT_JWKS_JSON` | — | Billing's public Ed25519 JWK set; parsed at startup and never fetched on the prompt path. |
| `ENTITLEMENT_ISSUER` | `https://billing.adverserial.ai` | Required entitlement issuer. |
| `ENTITLEMENT_AUDIENCE` | `https://api.adverserial.ai` | Required entitlement audience. |
| `ENTITLEMENT_REPLAY_DIR` | — | Persistent, private directory for atomically consuming one-use entitlement IDs. |
| `METER_SIGNING_SEED` | — | Removed in rc.31. **Refused in `CONFIDENTIAL_MODE`**: the meter key is generated in the enclave and published at `/.well-known/adverserial-meter-jwks.json`. |
| `EHBP_REQUIRED` | `0` | Require EHBP-encrypted request bodies. Mandatory in `CONFIDENTIAL_MODE`. The HPKE receiver identity is generated in memory on every boot. |
| `EHBP_IDENTITY_B64` | — | Removed in rc.31. **Refused in `CONFIDENTIAL_MODE`.** |
| `METER_ISSUER` | `https://api.adverserial.ai` | Meter-event issuer. |
| `METER_AUDIENCE` | `https://billing.adverserial.ai` | Meter-event audience. |
| `METER_OUTBOX_DIR` | — | Persistent, private directory for signed meter retry records. |
| `METER_DELIVERY_MODE` | `mtls-ingress` | `mtls-ingress` posts meter records to a separate ingress with a client certificate. `direct-signed` posts them straight to billing over TLS 1.3 with no client certificate. The reference deployment uses `direct-signed`. |
| `METER_URL` | — | Exact `https://host` origin for meter records. Required in confidential mode. With `direct-signed` it must be `https://billing.adverserial.ai`. |
| `METER_INGRESS_SHARED_SECRET` | — | Required for `direct-signed`: sent as the `X-Adverserial-Meter-Ingress` header on `/cc/start` and `/cc/meter`. Operator-supplied. It does not sign anything; records are still signed with the enclave meter key. |
| `METER_TLS_BUNDLE_B64` | — | `mtls-ingress` only: base64url JSON containing `client_cert_pem`, `client_key_pem`, and `ingress_ca_pem`, supplied by the operator. The proxy validates it and writes it under `/state/meter-tls`. Not used by the reference deployment; refused with `direct-signed`. |
| `METER_CLIENT_CERT_FILE` | — | `mtls-ingress` only: file alternative to the bundle; cannot be combined with `METER_TLS_BUNDLE_B64`. |
| `METER_CLIENT_KEY_FILE` | — | `mtls-ingress` only: file alternative to the bundle; cannot be combined with `METER_TLS_BUNDLE_B64`. |
| `METER_SERVER_CA_FILE` | — | `mtls-ingress` only: file alternative to the bundle; cannot be combined with `METER_TLS_BUNDLE_B64`. |
| `CHAT_HOST` | _(empty = disabled)_ | Static-chat virtual host, e.g. `chat.adverserial.ai` |
| `CHAT_DOCROOT` | _(empty = disabled)_ | SPA docroot for `CHAT_HOST` (set both or neither) |
| `GPU_EVIDENCE_FILE` | `/data/gpu-evidence.json` | Cached NRAS EAT bundle written by the collector container (embedded as `gpu_evidence`) |

The GPU evidence collector (`collector/gpu_evidence_collector.py`, a
separate container) reads its own variables; the proxy reads none of them:

| Variable | Default | Meaning |
| --- | --- | --- |
| `NV_ATTESTATION_SERVICE_KEY` | — | NVIDIA remote-attestation service key. Required. Operator-supplied. |
| `GPU_EVIDENCE_OUT` | `/data/gpu-evidence.json` | Where the bundle is written |
| `GPU_EVIDENCE_INTERVAL` | `300` | Seconds to sleep between collection rounds |
| `GPU_EVIDENCE_ROUND_TIMEOUT` | `1200` | Seconds before one round is aborted (`0` disables) |
| `GPU_EVIDENCE_MIN_GPU_COUNT` | `1` | A round fails unless NRAS returned at least this many distinct NVIDIA-signed tokens. This counts tokens, not GPUs (see *Known limits*). |
| `NRAS_URL` | `https://nras.attestation.nvidia.com/v4/attest/gpu` | Must be `https://` |

The model measurer (`cmd/model-measurer`) reads `MODEL_ROOT`, `MODEL_ID`,
and `MODEL_MANIFEST_FILE`, all required.

## Protocol

### `GET /attestation?nonce=<base64url>` (alias: `/.well-known/adverserial-attestation`)

The nonce must be base64url (padding optional) decoding to **16–64 bytes**.
Missing, malformed, duplicated, or out-of-range nonces are rejected with 400.
Every request fetches a **fresh** TDX quote; there is no quote cache.

The quote's 64-byte `report_data` is:

```
report_data[0:32]  = SHA-256("adverserial-attestation-v2" || 0x00 || nonce_raw
                             || tls_spki_der || receipt_spki_der || ehbp_public_key)
report_data[32:64] = zero padding
```

`nonce_raw` is the decoded client nonce; `tls_spki_der` / `receipt_spki_der`
are the DER PKIX SubjectPublicKeyInfo of the serving TLS certificate key and
the receipt-signing key; `ehbp_public_key` is the raw 32-byte X25519 EHBP
receiver key (empty when EHBP is off). This binds the hardware evidence to
the exact TLS key terminating the client's connection (WP-4 channel
binding), to the receipt key, and to the key request bodies are encrypted to.

The route is rate limited for everyone together, because the proxy has no
trustworthy client identity: a burst of 20 requests, refilled at one every
two seconds, then 429 with `Retry-After: 2`. At most 8 quotes are generated
at once (503 beyond that), and a query string over 512 bytes is refused.
Malformed nonces are rejected before they consume the budget.

### Response

```json
{
  "evidence": { ... },
  "verification_receipt": "<compact ES256 JWS>"
}
```

Evidence object (actual `DEV_MODE=1` output at this tag, quote shortened):

```json
{
  "attestation_state_digest": "sha256:zswxJ59_yE2NlVSfwYdjb_Fk18BUTt0rxagBLD875a0",
  "dev": true,
  "expires_at": "2026-11-24T13:05:13Z",
  "gpu_evidence": null,
  "gpu_evidence_ref": null,
  "issued_at": "2026-11-24T13:00:13Z",
  "nonce": "ZRJKYGV2XDRcABBvTRZXVUAb4f1PgqxhvLgBOXHFPV4",
  "receipt_pubkey_jwk": {
    "crv": "P-256",
    "kid": "m4jCAsQzU2ECk4UoEE-9O_b_jVDVTOvwQyN9WEcJwiI",
    "kty": "EC",
    "x": "IwGQ8P-W7xpUS4JXFtPjcx3WcWqS19sNr0nZUY01wY4",
    "y": "3eccHlkuWlnUtAmvkRxJmmL5So1oUTl5-HoJ4eKx8l8"
  },
  "tdx_event_log": "dev-mode-synthetic-event-log",
  "tdx_quote": "4445565154453030d15913db…",
  "tls_spki_der": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUww17Ue_wL5nDy94E9rnm811a7fCJ1yzcbI65JmkQdWPRSH34VyWe8IxRId5LJrOXJjjF5kVaLvShRh0mQvz9w",
  "tls_spki_sha256": "sha256:5QdD9pDWAMiCXPcYwTgCbf1XT5Qx5RfnopWmXyHCC3Y",
  "version": 1,
  "workload": {
    "compose_digest": "",
    "model_digest": "",
    "model_id": "lordx64/cyberglm",
    "policy_id": "adverserial-policy/dev",
    "proxy_version": "v0.1.0-rc.33"
  }
}
```

In confidential mode the object also carries `ehbp` and has no `dev` member.

- `version` — evidence schema version (1).
- `nonce` — the client nonce, echoed verbatim.
- `issued_at` / `expires_at` — RFC 3339; evidence is valid for 5 minutes.
- `tdx_quote` — hex TDX quote (in `DEV_MODE`, a synthetic `DEVQTE00…` blob).
- `tdx_event_log` — the dstack event log returned with the quote. A verifier
  replays it against the quote's RTMRs to learn which compose file and images
  were measured.
- `tls_spki_sha256` — `sha256:<base64url>` of the serving certificate's SPKI.
  The client recomputes this from the TLS handshake peer certificate.
- `tls_spki_der` — the same SPKI as base64url DER, so a verifier can recompute
  `report_data`.
- `ehbp` — present when EHBP is on: `protocol` (`ehbp-rfc9180-v1`),
  `key_config` (RFC 9458 key configuration), `public_key` (raw X25519), and
  `public_key_sha256`. The public key is the one hashed into `report_data`.
- `attestation_state_digest` — the value per-request receipts cite as
  `attestation_binding.evidence_digest` (see *Per-request enclave receipts*).
- `receipt_pubkey_jwk` — public JWK of the receipt key; `kid` is its RFC 7638
  SHA-256 thumbprint.
- `workload` — policy ID, model ID, compose digest, model digest, and
  `proxy_version`. These are values the proxy was configured with (the model
  digest may come from the measurer's manifest). The quote and event log are
  what prove the workload; these fields only say what the proxy claims.
- `gpu_evidence` — the cached NVIDIA NRAS bundle (one signed EAT JWT per GPU),
  or `null` when the collector has not produced one.
- `gpu_evidence_ref` — `"nras-eat-bundle"` when GPU evidence is present.
- `gpu_evidence_fresh_at` — the bundle's `generated_at`; clients apply their
  freshness policy to it.
- `gpu_evidence_stale` — present and `true` when the bundle's `generated_at`
  is older than 30 minutes, missing, unparsable, or more than 60 seconds in
  the future. The proxy keeps serving attestation **and inference** with
  stale GPU evidence; it is the client verifier that must refuse.
- `dev` — present and `true` only in `DEV_MODE`. Production policy must
  reject any evidence carrying this flag.

### GPU evidence collection (collector container)

The proxy never talks to NVIDIA at request time. A separate container
(`collector/gpu_evidence_collector.py`, image built from
`Dockerfile.collector` with `nv-attestation-sdk==2.7.3`) runs a remote
attestation round against NVIDIA NRAS
(`get_evidence(options={"ppcie_mode": False})` → `attest()` →
`get_token()`), keeps the NVIDIA-signed tokens (ES384 with a `kid`), and
writes the bundle atomically (temp file, `fsync`, rename) to a volume the
proxy mounts read-only. It then sleeps `GPU_EVIDENCE_INTERVAL` seconds (300
in the reference deployment) and repeats. A round on eight GPUs takes
minutes, so bundles are further apart than the interval alone suggests.

```json
{"version":1,"generated_at":"<RFC3339>","nonce":"<hex or null>","nonce_source":"nras-sdk",
 "gpus_attested":8,"minimum_gpu_count":8,"verdict":"successful","eat_jwts":["…"],
 "source":"nv_attestation_sdk remote NRAS","nras_url":"https://nras.attestation.nvidia.com/v4/attest/gpu"}
```

A failed round leaves the previous bundle in place; the proxy marks it stale
once `generated_at` is more than 30 minutes old. The proxy re-stats the file
at most once per 30 s and re-reads it only when its mtime changes. The proxy
container has no GPU access and no NVIDIA credential. The proxy does not
verify the tokens' signatures; verifiers must.

### Verification receipt (compact ES256 JWS)

Header: `{"alg":"ES256","kid":"<jwk thumbprint>","typ":"JWT"}`. Signature is
the raw 64-byte R‖S per RFC 7518 §3.4 (not ASN.1). Claims:

| Claim | Value |
| --- | --- |
| `iss` | `RECEIPT_ISSUER` |
| `aud` | `RECEIPT_AUDIENCE` |
| `nonce` | the client nonce, echoed |
| `verdict` | `"verified"` |
| `iat` / `exp` | epoch seconds; `exp = iat + 300` |
| `evidence_sha256` | `sha256:<base64url>` over the **canonicalized** evidence |
| `model_id` | `MODEL_ID` |
| `endpoint` | `ENDPOINT` |
| `model_digest` | `MODEL_DIGEST` (omitted when unset) |
| `runtime_digest` | `RUNTIME_DIGEST` (omitted when unset) |

Canonicalization is byte-identical to the TypeScript client
(`src/lib/confidential/verification.ts` in adverserial-webui): object keys
sorted recursively, no whitespace, `JSON.stringify` string semantics (raw
non-ASCII, raw U+2028/U+2029, no `<`/`>`/`&` escaping). The Go implementation
is pinned against a TS-generated test vector in
`internal/canonjson/canonjson_test.go`.

### Route allowlist

The proxy answers these itself: `/attestation`,
`/.well-known/adverserial-attestation`,
`/.well-known/adverserial-key-attestation`,
`/.well-known/adverserial-meter-jwks.json`, `/.well-known/hpke-keys` (EHBP
key configuration, when EHBP is on), `/statusz`, and `/healthz`.

In `CONFIDENTIAL_MODE` exactly three requests are forwarded to `UPSTREAM`:

| Method | Path |
| --- | --- |
| `GET` | `/v1/models` |
| `POST` | `/v1/chat/completions` |
| `POST` | `/v1/responses` |

Any other method or path (a trailing slash included) is answered 404 before
the body is read. The model server's native and administrative endpoints
(`/generate`, `/invocations`, cache and configuration routes, and so on) are
therefore not reachable through the proxy. Outside confidential mode the
fence is the `/v1/` prefix.

Forwarded requests use a direct connection (proxy environment variables are
ignored) with a 100 ms flush interval, so SSE responses stream. The proxy
changes these things on the way through:

- `Authorization` is replaced by the VM-internal upstream credential, or
  removed when there is none, so a client entitlement never reaches the model
  server. `Connection`, `X-Forwarded-For`, `X-Forwarded-Host`, and
  `Forwarded` are removed.
- `Accept-Encoding` is removed on the two `POST` routes and on
  `GET /v1/models`, so the proxy can read usage counts and edit the model
  list.
- In confidential mode the upstream-bound body gets a proxy-derived
  `cache_salt` (see *Tenant cache isolation*), and streaming chat completions
  get `stream_options.include_usage=true`. The receipt still hashes the
  client's original bytes.
- The model server's `Access-Control-*` response headers are dropped (the
  proxy sets CORS itself), and the body of any non-200 model response is
  replaced by a short sanitized JSON error (status code kept), so tracebacks
  and file paths do not leak.
- A non-streaming model response larger than 8 MiB is answered 502.

### `GET /v1/models` augmentation (browser-direct chat)

The browser client (`adverserial-webui`) discovers how to verify an endpoint
from `info.meta.confidential_verification` on each model. The proxy injects
that block into the upstream `GET /v1/models` response — working on the
parsed JSON structure, never touching any other response, and restoring the
original body verbatim on any shape mismatch or error:

```json
"info": { "meta": { "confidential_verification": {
  "attestation_url":      "<PUBLIC_BASE_URL>/attestation",
  "verification_url":     "<VERIFICATION_URL>",
  "receipt_issuer":       "<RECEIPT_ISSUER>",
  "receipt_audience":     "<RECEIPT_AUDIENCE>",
  "trusted_receipt_keys": { "<receipt kid>": { "kty":"EC","crv":"P-256","x":"…","y":"…","kid":"…" } },
  "expected": { "model_id": "<model id from upstream>", "endpoint": "<PUBLIC_BASE_URL>",
                "model_digest": "…", "runtime_digest": "…" }
} } }
```

`model_digest` / `runtime_digest` are omitted when unset. When
`ATTESTED_MODELS` is set, only listed model IDs are augmented; when empty,
every entry is. The augmenter strips `Accept-Encoding` on this one route so
it always sees identity JSON; gzip for all other routes passes through
end-to-end untouched. Body content is never logged during augmentation (the
no-content-logging test covers this path too).

### TLS certificates: self-signed (default) or ACME DNS-01

When `ACME_DOMAINS` is empty, the proxy generates a self-signed P-256
certificate in process memory at every start — trust comes from the
quote-bound SPKI, not a CA. When `ACME_DOMAINS` is set (with `ACME_EMAIL`,
`CERT_DIR`, and the `DNS_PROVIDER` credentials —
`CLOUDFLARE_API_TOKEN`/`CLOUDFLARE_ZONE` for Cloudflare, which the reference
deployment uses, or `GANDI_PAT`/`GANDI_ZONE` for Gandi LiveDNS, the code
default), the proxy runs a minimal stdlib-only RFC 8555 client inside the VM.
Both private keys involved, the ACME account key and the certificate key, are
generated in the VM from `crypto/rand`; the DNS credential is the only
operator-supplied input and it never signs anything the client verifies:

1. Loads (or creates and persists) the P-256 ACME account key at
   `CERT_DIR/account.key`.
2. If `CERT_DIR/certificate.crt` exists, covers all configured domains, and
   has ≥30 days left, it is used as-is (no re-issuance on restart).
3. Otherwise: new order → for each domain, `_acme-challenge.<sub>` TXT record
   set via the selected provider (Gandi LiveDNS `PUT/DELETE
   /v5/livedns/domains/{zone}/records/{name}/TXT`, or Cloudflare
   `POST/PUT/DELETE /zones/{zoneID}/dns_records`) → challenge notify →
   authorization poll → finalize with a CSR for a freshly generated P-256
   certificate key → chain download → persist `certificate.crt` and
   `certificate.key` (mode `0600`) to `CERT_DIR`. Challenge records are
   always deleted afterwards.
4. A background ticker checks every 12 h and renews (hot-swapping the serving
   certificate via `tls.Config.GetCertificate`) when <30 days remain.

If first issuance fails the proxy stays up and retries after 1 minute, then
5 minutes, then every 15 minutes, which stays inside the CA's
failed-validation limit. It does not listen until it has a certificate.

The `tls_spki_sha256` published in attestation evidence — and bound into the
TDX quote `report_data` — always reflects the **active** serving certificate,
across renewals (covered by `TestSPKIFollowsActiveCert`).

### Legacy auth gate (`POST /v1/*`)

When `AUTH_REQUIRED` is on (the default), every `POST` under `/v1/`
(`chat/completions`, `completions`, `responses`, `embeddings`, …) requires an
`Authorization: Bearer <key>` header. The proxy buffers the request body,
extracts `"model"` (missing/invalid JSON → 400), and calls billing
`POST {BILLING_URL}/auth/check` with `{"api_key": key, "model": model}`.
Verdicts are cached per key+model for 60 s. **Fail closed:** billing
unreachable or non-200 → 503, no inference ever runs unauthenticated.
Unauthenticated → 401; authenticated but not allowed → 403 with the billing
reason. The full client key is never logged — denials log the 8-char prefix
only. `/attestation`, `/.well-known/*`, `/healthz`, and `GET /v1/models` stay
unauthenticated.

### Confidential entitlement gate and durable meter

With `CONFIDENTIAL_MODE=1`, `AUTH_REQUIRED` **must** be `0`. The proxy
rejects a normal `sk-` API key: the customer key is presented only to billing
by the local gateway or browser entitlement exchange. Billing reserves a
bounded request and returns a short-lived Ed25519 JWS with an opaque
reservation ID, canonical model ID, input/output limits, one-use count, and
the TLS SPKI fingerprint observed during client verification. Billing picks
the lifetime; the proxy refuses any entitlement valid for more than 24 hours.

A confidential `POST` passes these checks in order, and each refusal happens
before the next step does any work:

1. Route allowlist (404).
2. An EHBP encapsulated-key header must be present (426); plaintext bodies
   are never accepted.
3. Ingress guard, before decryption and before any authentication is
   possible: at most **48** requests may be in this stage at once (16 up to
   rc.30; 503 beyond that), the encrypted body may be at most 9 MiB (413),
   and it must arrive within 60 seconds.
4. EHBP decryption with the in-memory receiver key.
5. `CONFIDENTIAL_ACTIVATION` must be `active` and the model server's
   `/health` must have answered 200 at the last 2-second probe (503
   otherwise, so a booting model server does not burn an entitlement).
6. The decrypted body may be at most 8 MiB and must pass the request limits
   in `internal/gate/request_limits.go`: JSON nesting up to 32 levels, up to
   **16,384** messages or input items (the limit was 512 up to rc.29), up
   to 16 tool calls and 32 content parts per message, a positive
   output-token limit, no `n`/`best_of` fan-out, and no SGLang-native debug,
   routing, adapter, or token-ID fields.
7. Entitlement, cache-salt, replay, and start checks, described next.

The CVM verifies that JWS locally using `ENTITLEMENT_JWKS_JSON`. It checks the
issuer, audience, expiry, canonical model, exact active TLS SPKI, body-byte
upper bound, and requested `max_tokens`; it then atomically records the
opaque reservation ID in `ENTITLEMENT_REPLAY_DIR` before calling SGLang, so a
captured entitlement cannot be replayed. A crash after consumption is safe:
the client must obtain a fresh entitlement rather than risk a second
inference.

Before dispatch the proxy registers the reservation with billing: a signed
one-hour `adverserial-confidential-start/v1` JWS (reservation ID, request
ID, model, timestamps — zero counts) is posted synchronously as
`{"start":"<JWS>"}` to `POST {METER_URL}/cc/start` over the same meter
channel. Dispatch proceeds only on `stored:true, started:false`; an
already-started reservation is refused 409, a released or expired one 401
(closing the release-then-replay free-inference hole), and any transport or
non-2xx failure fails closed with 503 — no inference ever runs that billing
could not record. The start call is deliberately not routed through the
outbox: if it cannot reach billing, nothing is dispatched and no settlement
is ever owed.

Terminal settlement is exactly once on every path. The gate attaches a
per-request settlement handle, and whichever terminal event happens first —
response completion with a usage chunk, an upstream error status, a transport
failure, a client abort mid-stream, or a handler panic (recovered to a 500) —
enqueues one count-only meter event with the best-known counts (zeros when no
usage was observed), so reservations settle instead of leaking. Streaming
chat-completion requests carry `stream_options.include_usage=true` upstream
so completed streams always end in a usage chunk; the receipt still binds the
client's original request bytes. The proxy signs that one-hour
`adverserial-confidential-meter/v1` JWS with the enclave meter key and first
writes it to `METER_OUTBOX_DIR` with `O_EXCL`, `fsync`, and mode `0600`. It
posts `{"meter":"<JWS>"}` only to `POST {METER_URL}/cc/meter`. The file is
deleted only after a 2xx response; otherwise it survives process and CVM
restarts and is retried at boot and every 30 seconds. A record billing
rejects with 400, 404, 409, or 422 is moved to `dead/` so it cannot block the
queue. The record has only issuer, audience, type, reservation ID, request
ID, model, three token counts, and timestamps — never content, identity, raw
API key, or response hash (`meter.Claims` in `internal/meter/meter.go`).

There are two delivery modes (`METER_DELIVERY_MODE`):

- **`direct-signed`** (the reference deployment): TLS 1.3 straight to
  `https://billing.adverserial.ai`, verified against the public CA store, no
  client certificate, plus the operator-supplied
  `METER_INGRESS_SHARED_SECRET` header. The shared secret only says "this
  came from a deployment the operator configured"; what billing must rely on
  is the Ed25519 signature under the meter key it pinned from the key
  attestation.
- **`mtls-ingress`** (the code default): TLS 1.3 with a client certificate to
  the separately deployed
  [`confidential-meter-ingress`](https://github.com/AdverserialAI/confidential-meter-ingress),
  which validates that certificate and forwards the unchanged envelope to
  billing. The ingress must be outside the CVM and its TLS session must
  reach that process un-terminated. The client key for this mode is supplied
  by the operator; it authenticates the network origin and signs no meter
  record.

### Where each key comes from

In `CONFIDENTIAL_MODE` no private key crosses the VM boundary in either
direction: none is accepted from configuration and no route returns one.

| Key | Generated by | When | Stored |
| --- | --- | --- | --- |
| Receipt signing key (ECDSA P-256) | the proxy, `internal/enclavekeys`, from `crypto/rand` | first boot with an empty `ENCLAVE_KEY_DIR` | `ENCLAVE_KEY_DIR/receipt-p256.pem`, PKCS#8, mode `0600`, on the VM's encrypted state volume |
| Meter signing key (Ed25519) | the proxy, `internal/enclavekeys`, from `crypto/rand` | first boot with an empty `ENCLAVE_KEY_DIR` | `ENCLAVE_KEY_DIR/meter-ed25519.pem`, PKCS#8, mode `0600`, same volume |
| EHBP / HPKE receiver identity (X25519) | the proxy, through the EHBP library's `identity.NewIdentity()` | every process start | memory only |
| TLS certificate key (ECDSA P-256) | the in-enclave ACME client (`internal/acme`) | each certificate issuance or renewal | `CERT_DIR/certificate.key`, mode `0600`, same volume |
| ACME account key (ECDSA P-256) | the proxy (`internal/acme`) | first use | `CERT_DIR/account.key`, mode `0600`, same volume |
| Prefix-cache salt key (32 bytes) | the proxy (`internal/gate`) | every process start | memory only |
| Self-signed TLS key (only without `ACME_DOMAINS`) | the proxy | every process start | memory only |

Two further secrets are not created by this repository's code but by the
reference compose file, also inside the VM:

| Secret | Generated by | When | Stored |
| --- | --- | --- | --- |
| Proxy-to-model bearer token | the one-shot `inference-auth-init` container (`secrets.token_urlsafe(48)`), which has no network | every VM boot | a file on the `inference-handoff` volume, mode `0440`, read by the proxy (`UPSTREAM_BEARER_TOKEN_FILE`) and the model server |
| Model server admin key | the model server's launcher script (`secrets.token_urlsafe(48)`) | every launch on the launcher's first configuration | the model server's command line only |

What is **not** generated in the enclave: the four operator-supplied
variables of the reference deployment (`HF_TOKEN`, `CLOUDFLARE_API_TOKEN`,
`NV_ATTESTATION_SERVICE_KEY`, `METER_INGRESS_SHARED_SECRET`), and billing's
entitlement *public* key (`ENTITLEMENT_JWKS_JSON`). None of them signs
receipts or meter records, decrypts request bodies, or terminates TLS.

`ENCLAVE_KEY_DIR` is created with mode `0700`; each key file is written with
mode `0600` through a temporary file in the same directory, `fsync`, an
atomic no-replace link into place, and a directory `fsync`. On later boots
the files are loaded. The proxy **fails closed** and never regenerates over
an existing file when the directory or a file is group/world-accessible, is
not a regular file (symlinks are refused), or does not parse as a single
PKCS#8 block of the expected key type. Recovery from such a state is a
deliberate operator action: remove the file, restart, and re-pin the new
public key everywhere it is trusted. Mount the state volume at the parent
(e.g. `/state`, owned by uid 65532 in the image) and let the proxy create
the key directory; a volume mounted directly at `ENCLAVE_KEY_DIR` with mode
`0755` is refused.

The proxy refuses to start in `CONFIDENTIAL_MODE` when any of
`RECEIPT_SIGNING_SEED`, `METER_SIGNING_SEED`, `EHBP_IDENTITY_B64`, or
`UPSTREAM_BEARER_TOKEN` is set to a non-empty value
(`config.ExternalSecretEnv`). The error names the variable and never its
value. `METER_SIGNING_SEED` and `EHBP_IDENTITY_B64` are not read anywhere
else; the tool that used to generate an EHBP identity outside the VM
(`cmd/generate-ehbp-identity`) was removed in rc.31.

Outside confidential mode (development) the receipt key is an in-memory key,
or a deterministic key from `RECEIPT_SIGNING_SEED`; `keys_origin` then reads
`process-ephemeral` or `operator-seed`, and a verifier following the recipe
below rejects both.

Consequences for relying parties:

- The receipt and meter public keys change only if the key directory is
  lost. Verifiers and billing must pin them from quote-bound evidence
  (below), not from operator-supplied configuration.
- The EHBP public key changes on **every** proxy restart, and with it
  `attestation_state_digest`. Clients must fetch the EHBP key from fresh
  `/attestation` evidence after a restart; a cached key configuration fails
  decryption with a key-configuration error.

### What the operator can and cannot do

"Operator" means whoever deploys the compose file and holds the hosting
account. The statements below hold for the reference deployment, and they
rest on Intel TDX, the dstack guest image and its disk encryption, and on
the client actually verifying the quote and event log against a policy it
trusts. They are not guarantees this repository can make by itself.

The operator can:

- Choose what is deployed. A different compose file, image digest, or
  environment produces a different measurement in the event log, which a
  verifying client sees. The operator also publishes the policy that says
  which measurements are acceptable (see *Known limits*).
- Set the four operator-supplied variables and therefore knows them: the
  Hugging Face token, the Cloudflare DNS token, the NVIDIA attestation
  service key, and the meter ingress shared secret.
- Use the DNS token to change DNS for the zone and so obtain a CA-signed
  certificate for the API hostname on a machine outside the enclave. A
  client that only checks the WebPKI certificate would accept it; a client
  that checks the quote-bound TLS key would not.
- Stop, restart, or destroy the VM and its volumes. Destroying the state
  volume creates new receipt and meter keys, visible as new key IDs.
- See traffic metadata (addresses, timing, sizes) and the container logs,
  which carry no request or response content.
- Run billing: issue or withhold entitlements and see token counts.

The operator cannot:

- Supply, choose, or read the receipt, meter, EHBP, or TLS private keys.
  Supplying one is refused at startup; none is written anywhere but the VM's
  memory and encrypted volume; no route exports one.
- Read prompts or completions. TLS ends inside the VM, request and response
  bodies are additionally encrypted to the in-memory EHBP key, and neither
  the proxy nor the compose file logs content.
- Reach the model server from outside. It is on a Docker network marked
  `internal`, publishes no port, requires a bearer token created inside the
  VM at boot, and the proxy forwards only three routes to it.
- Forge a receipt or a meter record, or make billing accept counts the
  enclave did not sign.

### Known limits

- **GPU evidence is not bound to the TDX quote.** The NVIDIA tokens are
  collected by a separate container with its own nonce and embedded in the
  evidence next to the quote. Nothing cryptographically ties them to this
  VM's quote or to the client's nonce. The receipt signs a digest of the
  evidence that contains them, which shows the enclave served them, not that
  the GPUs they describe are the ones attached to it.
- **In the reference deployment the OS does not attest the GPUs at boot.**
  The guest OS there, dstack 0.6.5, can attest the GPUs itself and require
  each GPU's Confidential Computing mode to be on before it releases the VM's
  keys. The hosting provider switched that check off for this VM
  (`"requirements":{"gpu_policy":{"attest_gpu":false}}` in the measured
  app-compose): eight H200 GPUs run in NVIDIA's multi-GPU Protected PCIe
  mode, in which the per-GPU Confidential Computing status reads off, and the
  0.6.5 check does not recognise that mode and would refuse to boot. The
  provider says it will add support and tell us when the flag can be removed.
  The protection is the same as on dstack 0.5.x, which had no such check, but
  nothing in the measured boot chain currently verifies the GPUs' protected
  mode. The opt-out is visible in the evidence this proxy serves: the event
  log has the RTMR3 event `gpu-policy-hash` =
  SHA-256 of `{"attest_gpu":false}` =
  `930188e08f58d0c555acff500a40be79c1f7e1d9ae23d26d901486cc9cc1a77d` and no
  `gpu-attestation` event. The collector's NRAS rounds, which continue, show
  genuine GPUs, firmware measurements NVIDIA accepts, secure boot on and
  debug off; they do not by themselves prove Protected PCIe mode. The proxy
  neither reads nor enforces the GPU policy.
- **Stale GPU evidence does not stop inference.** After 30 minutes the proxy
  sets `gpu_evidence_stale` and keeps serving. Refusing is the client
  verifier's job. The proxy also does not verify the tokens' signatures.
- **The collector's minimum-count check counts tokens.** It requires at
  least `GPU_EVIDENCE_MIN_GPU_COUNT` distinct NVIDIA-signed tokens in the
  NRAS response. It does not parse them to confirm each one describes a
  different GPU. `gpus_attested` is the same token count.
- **Persisted keys are files, not sealed keys.** The receipt, meter, ACME
  account, and TLS keys are PEM files on the VM's encrypted disk. They are
  not sealed to the workload measurement through the dstack KMS. Whether
  different software deployed to the same VM could read them depends on
  dstack's disk-key policy, which this repository neither controls nor
  checks.
- **The policy is published unsigned over HTTPS.** Clients compare evidence
  against policy documents served by `verify.adverserial.ai`. The documents
  are not signed and the site is outside the enclave, so the policy is as
  trustworthy as that site and the operator who runs it.
- **The inference server image is pinned, not reproducible.** The compose
  file pins `lmsysorg/sglang` and `vllm/vllm-openai` by digest, so the
  measurement fixes exactly which images run. Nobody can rebuild those
  images from source and get the same digest. The proxy, collector, and
  measurer images are built by this repository's release workflow with
  provenance attestations; bit-for-bit reproducibility of those images has
  not been demonstrated either.
- **The model server's admin endpoints exist.** They cannot be reached from
  outside: the network is internal and the proxy forwards three routes. On
  the launcher's first configuration they are also locked with a random key
  created inside the VM and written nowhere. The launcher's fallback
  configurations (used only if the first one fails to become ready) do not
  set that key; `/statusz` shows which one is running under
  `inference.rung`.
- **The model download step installs a Python package at first boot.** The
  `model-download` container has network access and runs
  `pip install huggingface_hub[hf_transfer]` unpinned before downloading the
  pinned model revision. What it produces is then measured by a container
  with no network and compared file by file against the manifest embedded in
  the compose file; the proxy and the model server do not start unless that
  check passes.
- **Workload digests in the evidence are configuration.** `COMPOSE_DIGEST`
  and `RUNTIME_DIGEST` are strings the proxy is given and repeats. The proof
  of what runs is the quote plus the event log.
- **Attestation proves the software, not its absence of bugs.** A verified
  quote says which code runs, not that the code is correct.

### `GET /.well-known/adverserial-meter-jwks.json`

Unauthenticated. Returns the meter verification key as a JWK set:

```json
{"keys":[{"kty":"OKP","crv":"Ed25519","x":"<base64url>","kid":"<base64url SHA-256 of the raw public key>","use":"sig","alg":"EdDSA"}]}
```

`kid` is the `kid` header of every `/cc/start` and `/cc/meter` JWS. The set
is empty outside confidential mode. A JWKS fetched over TLS proves only that
the TLS endpoint served it; billing must check the key attestation before
pinning the key.

### `GET /.well-known/adverserial-key-attestation`

Unauthenticated. `GET /attestation` already binds the TLS, receipt, and EHBP
public keys into a nonce-fresh quote (its `report_data` format and evidence
fields are unchanged). This additive route binds **all** enclave keys,
including the meter key, and the claim that they were generated in the
enclave:

```json
{
  "statement": "{\"ehbp_public_key\":\"…\",…}",
  "quote": "<hex TDX quote>",
  "event_log": [ … ]
}
```

`statement` is a string holding canonical JSON (sorted keys, no whitespace,
the same encoding as the evidence digest):

| Field | Meaning |
| --- | --- |
| `type` | `adverserial-key-attestation/v1` |
| `issued_at` | RFC 3339 UTC time the statement was built |
| `proxy_version` | proxy build version |
| `keys_origin` | `enclave-generated` in confidential mode (`operator-seed` or `process-ephemeral` otherwise) |
| `receipt_pubkey_jwk` | receipt signing public JWK (P-256, `kid` = RFC 7638 thumbprint) |
| `meter_pubkey_jwk` | meter signing public JWK (Ed25519), or `null` |
| `ehbp_public_key` / `ehbp_public_key_sha256` | raw X25519 receiver key (base64url) and `sha256:<base64url>` of it, or `null` |
| `tls_spki_sha256` | `sha256:<base64url>` of the active serving certificate's SPKI |
| `dev` | present and `true` only for synthetic `DEV_MODE` evidence |

The quote's 64-byte `report_data` is

```
SHA-512("adverserial-key-attestation-v1\n" || statement_bytes)
```

The result is cached for 60 seconds per serving certificate, and generation
is single-flight, so the route cannot be used to exhaust quote generation.
The statement carries no caller nonce: freshness is `issued_at` plus the
60-second cache, which is what a pinning decision needs. Use
`/attestation?nonce=…` when per-request freshness is required.

**Verification recipe** (billing before pinning the meter key; any verifier
before trusting a receipt key):

1. Connect to the endpoint over TLS and record the SHA-256 of the peer
   certificate's SubjectPublicKeyInfo.
2. `GET /.well-known/adverserial-key-attestation`. Take `statement` exactly
   as the JSON string decodes — do not re-serialize it.
3. Verify the TDX quote signature and certificate chain against Intel's
   root with a DCAP verifier, and check TCB status against policy.
4. Replay `event_log` against the quote's RTMRs and check the measured
   compose hash and image digests against the published policy for this
   release. This is the step that proves the keys below belong to *this*
   software; without it the quote proves only that some TDX guest made it.
5. Compute `SHA-512("adverserial-key-attestation-v1\n" || statement)` over
   the UTF-8 bytes and require it to equal the quote's `report_data`
   (all 64 bytes).
6. Parse `statement` and require `type` =
   `adverserial-key-attestation/v1`, `keys_origin` = `enclave-generated`,
   no `dev` member, `issued_at` within your freshness window (a few
   minutes), and `tls_spki_sha256` equal to the value from step 1.
7. Only then pin `meter_pubkey_jwk` (billing) or `receipt_pubkey_jwk`
   (clients), and require `kid` to match the JWS headers you verify. Repeat
   the procedure when a JWS arrives under an unknown `kid`.

### `GET /statusz`

Unauthenticated operational status. It carries public key identifiers and
counters only — no secrets and nothing derived from a request:

```json
{
  "version": "v0.1.0-rc.33",
  "started_at": "2026-11-24T10:00:00Z",
  "keys_origin": "enclave-generated",
  "receipt_kid": "<RFC 7638 thumbprint of the receipt key>",
  "meter_kid": "<meter JWS kid>",
  "meter_jwk_thumbprint": "<RFC 7638 thumbprint of the meter key>",
  "ehbp_public_key_sha256": "sha256:<base64url>",
  "upstream_ready": true,
  "ingress": {"in_use": 0, "max": 48},
  "inference": {"ladder_id": "…", "rung": "…", "phase": "…", "attempt": "…",
                "started_at": "…", "updated_at": "…", "detail": "…"}
}
```

`meter_kid`, `meter_jwk_thumbprint`, `ehbp_public_key_sha256`, and
`upstream_ready` are `null` when not applicable (outside confidential mode).
`inference` appears only when `INFERENCE_STATUS_FILE` is set and holds a JSON
object of at most 8 KiB. Only the seven fields shown are copied; each present,
non-null value is rendered as a string of at most 200 characters with every
character outside `[A-Za-z0-9 _.:,=/+-]` replaced by `?`. `/statusz` values
are unauthenticated hints for operators; trust decisions use the quote-bound
routes.

### Tenant cache isolation

SGLang keys its radix prefix cache on the per-request `cache_salt` and
`extra_key` fields, and a cache hit is observable through latency and
`cached_tokens`. In confidential mode the proxy owns both fields on
`POST /v1/chat/completions` and `POST /v1/responses`:

- a client-supplied `extra_key` is rejected with 400;
- a client `cache_salt` is optional; when present it must be a string
  matching `^[A-Za-z0-9_-]{32,128}$`, otherwise 400;
- the forwarded `cache_salt` is **always** replaced by
  `base64url-nopad(HMAC-SHA256(k, tenant_id || 0x00 || client_salt))`, where
  `k` is 32 random bytes drawn at process start (memory only) and
  `client_salt` is empty when the client sent none.

`tenant_id` comes from the billing-signed entitlement, so a client cannot
choose it: `"sub:" + sub` when the entitlement carries the optional `sub`
claim, otherwise `"jti:" + jti`. `sub` must be an opaque, stable,
per-account identifier matching `^[A-Za-z0-9_.:-]{1,128}$` (never an email,
name, or API key); it is used only as HMAC input and is never logged,
metered, or forwarded. Because `jti` is single-use, an entitlement without
`sub` that sends no `cache_salt` is isolated from every other request and
never hits the prefix cache. An entitlement without `sub` that does send a
`cache_salt` is partitioned by that salt alone: requests carrying the same
32-to-128-character salt share cache entries, so the salt must be kept
secret by the client that chose it. Same `sub` and same client salt share
cache entries; different `sub` values never can, whatever salt they send. Validation happens before the entitlement is
consumed, and the rewrite touches only the upstream-bound body: the receipt
still hashes, and the entitlement input bound still measures, the client's
original bytes. The cache partition does not survive a proxy restart (new
`k`).

### Legacy counts-only usage tap

For `POST /v1/chat/completions` and `/v1/responses`, after a 200 response
completes the proxy posts one usage event to `POST {BILLING_URL}/usage`:

```json
{"source":"attest-proxy","model":"…","api_key_prefix":"<first 8 chars>",
 "input_tokens":0,"cached_tokens":0,"output_tokens":0,
 "request_id":"<uuid>","ts":"<RFC3339>"}
```

Non-streaming responses are parsed as JSON; streaming responses are tapped at
the SSE chunk level — every byte is forwarded to the client unmodified while
the final `data:` chunk carrying `"usage"` is parsed (both the
chat-completions and the responses usage shapes). No usage chunk → no write.
The write is fire-and-forget with a 5 s timeout and never affects the user's
request. This is the entire billing boundary: **billing receives
`api_key_prefix` + token counts + model + request_id + timestamp; never
content, never full keys.**

### Static virtual host for the chat UI

When `CHAT_HOST` and `CHAT_DOCROOT` are both set, requests whose Host matches
`CHAT_HOST` (case-insensitive, port stripped) are served the SPA from
`CHAT_DOCROOT`: existing files directly, unknown non-asset paths fall back to
`index.html`, `/_app/*` hash-named assets get
`Cache-Control: public, max-age=31536000, immutable`, `index.html` gets
`no-cache`, and missing asset paths 404 (no SPA fallback). Requests to
`CHAT_HOST` for `/attestation`, `/.well-known/*`, `/healthz`, and `/v1/*`
still route to the API handlers — the UI talks to the API through the same
public base URL. CORS behavior is unchanged.

### Per-request enclave receipts (WP-7)

Every `POST /v1/chat/completions` (and `/v1/responses`) with a 200 response
carries a receipt proving **this exact exchange** ran on the attested
workload under the current policy — hash-only, never content.

- **Request nonce**: `X-Adverserial-Nonce` (base64url 16–64 B, validated like
  the attestation nonce; 400 on malformed) or generated by the proxy and
  returned in the receipt.
- **`request_body_hash`**: `sha256:<base64url>` of the request body bytes
  exactly as the client sent them (after EHBP decryption), before the proxy
  rewrites `cache_salt` or `stream_options` for the model server.
- **`response_hash`**: non-streaming → SHA-256 of the raw response body.
  Streaming → SHA-256 over the concatenation of all upstream SSE data-chunk
  payloads in order. Payload rule (shared with the SDK): strip the trailing
  CR, drop `data:` and ONE leading space; `[DONE]` is included; the injected
  receipt chunk is not.
- **Delivery**: non-streaming → `X-Adverserial-Receipt` header. Streaming → a
  final `data: {"adverserial_receipt": "<jws>"}` chunk inserted after the
  last upstream content event and before the upstream `[DONE]`, which is
  passed through last, byte-identical. Upstream chunks are never dropped or
  reordered; without receipts configured the stream is untouched.
- **Claims** (compact ES256 JWS signed by the same key published in
  `/attestation` evidence):

| Claim | Value |
| --- | --- |
| `v` | `1` |
| `iss` / `aud` | `RECEIPT_ISSUER` / `RECEIPT_AUDIENCE` |
| `request_nonce` | client nonce or proxy-generated |
| `request_body_hash` / `response_hash` | `sha256:<base64url>` as above |
| `model_id` / `policy_id` | from the request model + `POLICY_ID` |
| `attestation_binding` | `{tls_spki_sha256, evidence_digest}` — SPKI of the active serving cert + the current attestation-state digest |
| `iat` / `exp` | epoch seconds, `exp = iat + 120` |
| `usage` | `{input_tokens, cached_tokens, output_tokens}` when the tap captured usage |

`attestation_binding.evidence_digest` is the canonical digest of the proxy's
current attestation **state** (workload digests, policy id, proxy version,
active TLS SPKI, receipt kid, GPU evidence presence/freshness) — it changes
on key/cert rotation, policy changes, and GPU freshness flips. It is not a
per-request quote: freshness comes from the client's own `/attestation` call,
exchange binding from the receipt hashes.

Client verification (the SDK does this automatically): signature against the
attested receipt key, nonce echo, both hashes against the bytes sent/received,
model/policy/issuer/audience match, `exp` unexpired, binding SPKI equals the
TLS pin. Cost: O(n) hashing, one signature per request, no blocking on
billing or NRAS.

Access logs look like:

```
time=… level=INFO msg=request method=POST path=/v1/chat/completions status=200 bytes=1629 duration_ms=812
```

Path segments that look like identifiers are reduced to `:id`
(`/v1/models/lordx64` → `/v1/models/:id`). Bodies, headers, cookies, and query
strings are never logged — the marker-string regression test in
`internal/proxy/proxy_test.go` (`TestNoContentLogging`) enforces this.
Token counts are **not** logged either: the proxy reads them from the
response to build receipts and meter records, and they go nowhere else.
Other log lines carry a request ID, a key ID, or an error reason. In
confidential mode an entitlement refusal logs only the reason. The legacy
(non-confidential) gate logs the first 8 characters of the API key and the
model name when it denies a request.

## Threat model (one-pager)

**What this proxy proves to a client that verifies the receipt:**

- A TDX quote was minted fresh for *their* nonce (replay of stale evidence
  fails the nonce binding and the 5-minute expiry).
- The quote's `report_data` is bound to the TLS key terminating *their*
  connection and to the key signing the receipt — so a TLS-terminating edge
  or a swapped certificate fails verification before any prompt is sent.
- The receipt binds the claimed model ID, model/runtime digests, endpoint,
  issuer, and audience.
- **WP-7 route proof**: the per-request receipt proves this exact exchange —
  the bytes sent and received, by hash — ran on the attested workload under
  the current policy, signed by the key the attestation evidence published.
  A swapped backend, substituted response, or replayed receipt fails client
  verification.
- The evidence publishes everything a policy verifier needs to check
  workload identity (policy ID, compose digest, model digest, proxy version).

**What it does not prove (see also *Known limits*):**

- That the workload measurement matches a published policy: clients must
  compare evidence against `verify.adverserial.ai` policy documents (WP-5);
  the proxy publishes digests but does not enforce them, and the policy
  documents are unsigned.
- GPU evidence is a **cached** bundle: `gpu_evidence_fresh_at` /
  `gpu_evidence_stale` expose its age, but the proxy does not re-verify EAT
  signatures — clients must validate the NVIDIA EAT chains against policy and
  reject stale bundles. A GPU/driver swap between collector rounds is visible
  only after the next refresh.
- Per-request receipts bind hashes, not content: a client that never checks
  them (or accepts `receipt_verified=False` silently) gets no route proof.
  Receipts cover the response body; they do not cover upstream HTTP headers.
- Key continuity across restarts: the ACME account key and certificates
  persist on the dstack volume via `CERT_DIR`, and in confidential mode the
  receipt and meter keys persist under `ENCLAVE_KEY_DIR`. Their
  confidentiality at rest is that of the CVM's encrypted state volume; they
  are not additionally sealed to an RTMR policy. The EHBP identity and the
  self-signed dev TLS key are ephemeral per process boot.
- Operator-supplied material that remains in the reference deployment: the
  meter ingress shared secret, the ACME DNS token, the NVIDIA attestation
  service key, and the Hugging Face token. (`mtls-ingress` delivery, which
  the reference deployment does not use, adds an operator-supplied mTLS
  client key.) None of them signs receipts or meter events or decrypts
  request bodies.

**Content boundary:** prompts, completions, attachments, and chat history
exist only inside the CVM (proxy memory + inference server). The proxy's logs
carry metadata only. Billing is metadata-only by construction. In
confidential mode no API key enters the VM and billing receives only signed
start and meter records (reservation ID, request ID, model, token counts,
timestamps). In legacy mode the auth gate sends the full key **to** billing
over TLS (billing is the credential store) and the usage tap sends
`api_key_prefix` + token counts + model + request_id + timestamp. Neither
mode ever sends prompt or completion content. DNS, static hosting, billing,
and the verification site are outside the TEE boundary by design. The gate
buffers request bodies in proxy memory to read the `model` field and limits
(≤8 MiB in confidential mode, ≤64 MiB in legacy mode) — buffered bytes are
never logged.

**`DEV_MODE` caveat:** synthetic evidence proves nothing about a TEE. It
exists for client-integration development and is always marked `"dev": true`.

## Not done yet

- **KMS sealing** of the enclave-generated receipt and meter keys to an RTMR
  policy via dstack `/GetKey` (WP-2/WP-4). The proxy does not call `/GetKey`
  today.
- **Binding GPU evidence to the TDX quote** and enforcing GPU freshness in
  the proxy rather than only in the client (WP-3).
- **Signed policy documents.**
- ACME: CAA/account binding hardening.

Earlier versions of this list also named rate limiting on the attestation
endpoint, digest-pinned base images, and ACME retry backoff. Those are done:
see *Protocol*, the three Dockerfiles, and *TLS certificates*.

## Reference deployment

[`deploy/reference/docker-compose.cyberseek-v5.yml`](./deploy/reference/docker-compose.cyberseek-v5.yml)
is the compose file of the `adverserial/cyberseek` deployment
(SHA-256 of the file:
`dd186c2ffd55de67be863314bfc6623ad81445da9e162beef12f6d4d2ad5436c`). It
contains no credential: the four secrets appear only as `${VAR}`
references, and the long base64 value is the expected model manifest (file
names, sizes, and SHA-256 hashes).

**Platform (as of 2026-11-24).** One Intel TDX VM on Phala Cloud with eight
NVIDIA H200 GPUs, guest OS image `dstack-0.6.5`
(`os_image_hash` `4771a29e03e93f0e2d5e37174cd8bb1112942c9689deb36b16c5df9e183d8623`,
NVIDIA driver 595.91.07). The hosting provider moved the VM to this image on
2026-11-24; a rollout on `dstack-nvidia-0.5.15` earlier that day never served
a request, because one GPU failed to initialise at every boot. dstack measures
the app-compose document that wraps this compose file, not the file itself;
its hash on this deployment is `compose_hash`
`9c78bf82dfad3a133838f2ac87406b3fe1c9d875d8a4d5fbe04e9f34d7d3b820`. The exact
measured bytes are published in
[cyberseek-transparency](https://github.com/AdverserialAI/cyberseek-transparency/tree/main/deployments/v0.1.0-rc.33-os-0.6.5)
and in
[confidential-infra](https://github.com/AdverserialAI/confidential-infra/tree/main/deployed).
That document sets `"attest_gpu": false`; see *Known limits*. The policy
clients verify against is updated only after a live attestation of this
configuration has been checked.

**Network.** Two Docker networks: `default`, and `inference`, which is
`internal: true` (no route out of the VM). The proxy is on both. The model
server is on `inference` only and listens on `sglang:30000`; the proxy
reaches it at `UPSTREAM=http://sglang:30000`. The only published port is
443, mapped to the proxy's 8443.

**Services.**

| Service | Image | Role | Network | Runs as |
| --- | --- | --- | --- | --- |
| `attest-proxy` | `ghcr.io/adverserialai/attest-proxy@sha256:5a41bcfb…` (the image the release workflow pushed for tag `v0.1.0-rc.33`) | this proxy | `default` + `inference` | uid 65532, read-only root, all capabilities dropped |
| `sglang` | `lmsysorg/sglang@sha256:b4f09a2c…` | model server, 8 GPUs | `inference` only | starts as root with a reduced capability set, then drops to uid 65532 for the server process on the launcher's first configuration |
| `inference-auth-init` | `vllm/vllm-openai@sha256:91ee972a…` | one-shot: writes a fresh random proxy-to-model token at every boot | none | root, three capabilities |
| `gpu-evidence-collector` | `ghcr.io/adverserialai/gpu-evidence-collector@sha256:88484069…` (the `v0.1.0-rc.29` build; the collector source has not changed since) | NVIDIA NRAS rounds, 8 GPUs, `GPU_EVIDENCE_INTERVAL=300`, `GPU_EVIDENCE_MIN_GPU_COUNT=8` | `default` | uid 65532, read-only root |
| `model-download` | `vllm/vllm-openai@sha256:91ee972a…` | one-shot: downloads the pinned model revision | `default` | root |
| `model-perms` | same | one-shot: makes the model files readable | none | root |
| `model-measurer` | `ghcr.io/adverserialai/model-measurer@sha256:5f5f0653…` (the `v0.1.0-rc.29` build; source unchanged since) | one-shot: hashes every model file into a manifest | none | uid 65532, read-only |
| `native-manifest-check` | `vllm/vllm-openai@sha256:91ee972a…` | one-shot: compares the measured manifest with the one embedded in the compose file (57 files) | none | uid 65532, read-only |
| `retire-old-proxy-state` | same | one-shot: empties the earlier `proxy-state` volume once the current one (`proxy-state-v2`) holds a certificate | none | root, two capabilities |

The proxy and the model server start only after `inference-auth-init` and
`native-manifest-check` have succeeded.

**Operator-supplied variables.** Four, delivered as dstack encrypted
environment variables. The operator sets them and therefore knows them:

| Variable | Used by | For |
| --- | --- | --- |
| `HF_TOKEN` | `model-download` | downloading the model |
| `CLOUDFLARE_API_TOKEN` | `attest-proxy` | ACME DNS-01 records for `api.adverserial.ai` |
| `NV_ATTESTATION_SERVICE_KEY` | `gpu-evidence-collector` | NVIDIA NRAS |
| `METER_INGRESS_SHARED_SECRET` | `attest-proxy` | `direct-signed` meter delivery header |

**Proxy settings that matter for trust.** `CONFIDENTIAL_MODE=1`,
`EHBP_REQUIRED=1`, `AUTH_REQUIRED=0`, `CONFIDENTIAL_ACTIVATION=active`,
`ENCLAVE_KEY_DIR=/state/keys`, `CERT_DIR=/state/certificates`,
`DNS_PROVIDER=cloudflare`, `UPSTREAM_BEARER_TOKEN_FILE=/run/handoff/upstream-token`,
`MODEL_MANIFEST_FILE=/model-evidence/native-manifest.json`,
`METER_DELIVERY_MODE=direct-signed` with
`METER_URL=https://billing.adverserial.ai`, and `RUNTIME_DIGEST` equal to
the model server image digest. None of the four variables the proxy refuses
is set. The proxy has no GPU, mounts the dstack socket read-only, and mounts
the evidence, manifest, token, and status volumes read-only; only `/state`
is writable.

**Limits in force.** 48 pre-authentication ingress slots in the proxy
(compiled in, shown at `/statusz` as `ingress.max`); the model server runs
with `--max-running-requests 32`.

The compose file also sets `GPU_EVIDENCE_EXPECTED_TYPE` on the collector. The
collector in this repository does not read that variable.

## Layout

```
cmd/attest-proxy/        main: config, keygen, ACME wiring, graceful shutdown
cmd/model-measurer/      one-shot model artifact measurer (sha256-tree-v1 manifest)
collector/               GPU evidence collector (nv_attestation_sdk → NRAS, atomic bundle)
deploy/reference/        compose file of the reference deployment
tests/                   collector tests (mocked SDK, offline)
scripts/                 local release helper (binary, SBOM, cosign)
internal/acme/           RFC 8555 dns-01 client, Gandi LiveDNS + Cloudflare providers, cert store
internal/attestation/    evidence building, report_data, GPU bundle cache, dstack QuoteSource
internal/billing/        billing service client (auth check, usage write, /cc/start, /cc/meter)
internal/canonjson/      TS-identical canonical JSON + digest
internal/config/         env configuration, refusal of outside keys
internal/enclavekeys/    enclave-generated receipt + meter keys (PKCS#8, fail-closed store)
internal/entitlement/    billing JWS verification + durable one-use replay store
internal/gate/           /v1/ auth gate, request limits, request attribution, tenant cache-salt binding
internal/meter/          signed count-only meter JWS + durable retry outbox
internal/proxy/          reverse proxy, /v1/models augmenter, usage tap, receipts, no-content logging
internal/receipt/        ES256 JWS minting, JWK, RFC 7638 thumbprints
internal/server/         TLS + hot-swap holder, route allowlist, ingress guard, chat vhost, attestation, key attestation, statusz
internal/upstreamtoken/  file-backed upstream credential with change detection
internal/buildinfo/      proxy version (ldflags-overridable)
```

## Security

Please report security vulnerabilities privately to [security@adverserial.ai](mailto:security@adverserial.ai). Do not open a public issue for a suspected vulnerability.

## Third-party protocol implementation

The encrypted-body boundary uses the maintained [Tinfoil Encrypted HTTP Body
Protocol reference implementation](https://github.com/tinfoilsh/encrypted-http-body-protocol)
(EHBP, MIT licensed). It implements RFC 9180 HPKE, RFC 9458 key
configuration, framed encrypted streaming responses, and response-key
derivation. Adverserial binds the receiver public key configuration into its
fresh attestation evidence before a client uses it; clients must not replace it
with an independently fetched key.

The receiver identity is generated inside the enclave on every boot and held
in memory only; there is no way to provision one. The proxy publishes only
its RFC 9458 public key configuration in fresh quote-bound evidence.

## License

This repository is source-available proprietary software owned by Adverserial
AI LLC. See [`LICENSE`](./LICENSE) and [`LICENSING.md`](./LICENSING.md).
Third-party components retain their own terms.
