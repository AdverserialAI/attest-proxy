# attest-proxy

`attest-proxy` is the single public process of an Adverserial confidential
inference deployment. It runs **inside** a Phala dstack confidential VM
(Intel TDX) in front of the SGLang inference server and:

1. terminates TLS in-enclave — either an ACME DNS-01 certificate via Gandi
   LiveDNS or Cloudflare (production) or an ECDSA P-256 self-signed key
   generated **in process** (dev default; never on disk),
2. serves nonce-bound TDX attestation evidence plus a signed ES256
   verification receipt (`GET /attestation`). In confidential mode the
   receipt key comes from a sealed, stable seed and its public JWK is pinned
   in the public runtime policy,
3. reverse-proxies everything else to the loopback inference server, and
4. never logs request or response content — method, path class, status,
   byte count, and duration only. There is no content-logging escape hatch.

Stdlib-first: the only third-party dependency is the MIT-licensed Tinfoil
EHBP reference implementation (see *Third-party protocol implementation*
below). Requires Go 1.26+.

## Build, test, run

```sh
go build ./...
go vet ./...
go test ./...

# Local development (synthetic attestation evidence, no dstack):
DEV_MODE=1 go run ./cmd/attest-proxy

# Production shape (inside the dstack CVM, socket mounted):
go run ./cmd/attest-proxy   # reads /var/run/dstack.sock
```

Docker:

```sh
docker build -t adverserial-attest-proxy .
docker run --rm -p 8443:8443 \
  -v /var/run/dstack.sock:/var/run/dstack.sock \
  adverserial-attest-proxy
```

## Configuration (environment)

| Variable | Default | Meaning |
| --- | --- | --- |
| `LISTEN_ADDR` | `:8443` | TLS listen address |
| `UPSTREAM` | `http://127.0.0.1:30000` | Inference server (loopback only) |
| `UPSTREAM_BEARER_TOKEN` | _(empty)_ | Sealed SGLang-only credential. Required in `CONFIDENTIAL_MODE`; replaces the client entitlement before the upstream request. |
| `MODEL_ID` | `lordx64/cyberglm` | Served model ID (receipt claim `model_id`) |
| `POLICY_ID` | `adverserial-policy/dev` | Policy identifier from the public policy registry |
| `ENDPOINT` | `https://api.adverserial.ai` | Public base URL (receipt claim `endpoint`) |
| `RECEIPT_ISSUER` | `https://verify.adverserial.ai` | Receipt claim `iss` |
| `RECEIPT_AUDIENCE` | `cc-chat.adverserial.ai` | Receipt claim `aud` |
| `RECEIPT_SIGNING_SEED` | _(empty)_ | Sealed 32-byte base64url seed for the stable P-256 receipt signer. Required in `CONFIDENTIAL_MODE`; publish only the derived public JWK in the active policy. |
| `COMPOSE_DIGEST` | _(empty)_ | `sha256:` digest of the dstack compose config |
| `MODEL_DIGEST` | _(empty)_ | `sha256:` digest of the model artifact |
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
| `DNS_PROVIDER` | `gandi` | ACME DNS-01 provider: `gandi` or `cloudflare` |
| `GANDI_PAT` | — | Gandi LiveDNS personal access token (required for ACME with `DNS_PROVIDER=gandi`) |
| `GANDI_ZONE` | — | Gandi DNS zone owning the domains, e.g. `adverserial.ai` |
| `CLOUDFLARE_API_TOKEN` | — | Cloudflare API token with Edit-zone-DNS on the zone (required for ACME with `DNS_PROVIDER=cloudflare`) |
| `CLOUDFLARE_ZONE` | — | Cloudflare DNS zone owning the domains, e.g. `adverserial.ai` |
| `CERT_DIR` | — | dstack-volume path persisting the ACME account key + certs |
| `AUTH_REQUIRED` | `1` (on) | Gate `POST /v1/*` behind billing `/auth/check` |
| `BILLING_URL` | — | Billing service base URL (required when `AUTH_REQUIRED` on) |
| `BILLING_WRITER_SECRET` | — | Bearer token for billing writes (required when `AUTH_REQUIRED` on) |
| `CONFIDENTIAL_MODE` | `0` | Enable local billing-entitlement verification. Requires `AUTH_REQUIRED=0`; raw customer API keys are rejected at this boundary. |
| `ENTITLEMENT_JWKS_JSON` | — | Billing's public Ed25519 JWK set; parsed at startup and never fetched on the prompt path. |
| `ENTITLEMENT_ISSUER` | `https://billing.adverserial.ai` | Required entitlement issuer. |
| `ENTITLEMENT_AUDIENCE` | `https://cc-api.adverserial.ai` | Required entitlement audience. |
| `ENTITLEMENT_REPLAY_DIR` | — | Persistent, private directory for atomically consuming one-use entitlement IDs. |
| `METER_SIGNING_SEED` | — | Sealed 32-byte base64url Ed25519 seed for count-only meter records. Never commit it. |
| `METER_ISSUER` | `https://cc-api.adverserial.ai` | Meter-event issuer. |
| `METER_AUDIENCE` | `https://billing.adverserial.ai` | Meter-event audience. |
| `METER_OUTBOX_DIR` | — | Persistent, private directory for signed meter retry records. |
| `METER_URL` | — | Fixed `https://meter-ingress…` origin. Required in confidential mode; it must not point to Heroku billing. |
| `METER_TLS_BUNDLE_B64` | — | Preferred production input: sealed base64url JSON containing `client_cert_pem`, `client_key_pem`, and `ingress_ca_pem`. The proxy validates and atomically materializes it into its private state volume before opening the mTLS client. |
| `METER_CLIENT_CERT_FILE` | — | File-mode alternative for a CVM-managed secret store; cannot be combined with `METER_TLS_BUNDLE_B64`. |
| `METER_CLIENT_KEY_FILE` | — | File-mode alternative for a CVM-managed secret store; cannot be combined with `METER_TLS_BUNDLE_B64`. |
| `METER_SERVER_CA_FILE` | — | File-mode alternative for a CVM-managed secret store; cannot be combined with `METER_TLS_BUNDLE_B64`. |
| `CHAT_HOST` | _(empty = disabled)_ | Static-chat virtual host, e.g. `cc-chat.adverserial.ai` |
| `CHAT_DOCROOT` | _(empty = disabled)_ | SPA docroot for `CHAT_HOST` (set both or neither) |
| `GPU_EVIDENCE_FILE` | `/data/gpu-evidence.json` | Cached NRAS EAT bundle from the collector sidecar (embedded as `gpu_evidence`) |
| `NV_ATTESTATION_SERVICE_KEY` | — | Sealed NVIDIA remote-attestation service key; required by the collector, never by the proxy |
| `GPU_EVIDENCE_MIN_GPU_COUNT` | `1` | Minimum number of independently attested GPU EATs; set to the deployment GPU count |

## Protocol

### `GET /attestation?nonce=<base64url>` (alias: `/.well-known/adverserial-attestation`)

The nonce must be base64url (padding optional) decoding to **16–64 bytes**.
Missing, malformed, duplicated, or out-of-range nonces are rejected with 400.
Every request fetches a **fresh** TDX quote; there is no quote cache.

The quote's 64-byte `report_data` is:

```
report_data[0:32]  = SHA-256(nonce_raw || tls_spki_der || receipt_spki_der)
report_data[32:64] = zero padding
```

`nonce_raw` is the decoded client nonce; `tls_spki_der` / `receipt_spki_der`
are the DER PKIX SubjectPublicKeyInfo of the serving TLS certificate key and
the receipt-signing key. This binds the hardware evidence to the exact TLS
key terminating the client's connection (WP-4 channel binding) and to the
receipt key.

### Response

```json
{
  "evidence": { ... },
  "verification_receipt": "<compact ES256 JWS>"
}
```

Evidence object (actual `DEV_MODE=1` output, keys as served):

```json
{
  "dev": true,
  "expires_at": "2026-10-04T14:08:22Z",
  "gpu_evidence_ref": null,
  "issued_at": "2026-10-04T14:03:22Z",
  "nonce": "cLX8hPUPTUxufQE8cxRNL1IvWpGF7Krn3SxpBjmcUNQ",
  "receipt_pubkey_jwk": {
    "crv": "P-256",
    "kid": "Ft_xbM9sJd-2OtTxhG1wg7qNk1xiSb_JzhcCsOv2MJY",
    "kty": "EC",
    "x": "ywO8Ki0SQfE7voSQGI-XmES2HhS0ci-0CMCB2nwk_eQ",
    "y": "M54SOaRg-3jxlGc1vh1yzvOJKOcncy3IHTMY9a-s4fE"
  },
  "tdx_quote": "4445565154453030ed0074b6…",
  "tls_spki_sha256": "sha256:ZvYv3BFGYhjUK9A2FGBApta76m_EdTHh7x-XpoQ7TR8",
  "version": 1,
  "workload": {
    "compose_digest": "sha256:…",
    "model_digest": "sha256:…",
    "model_id": "lordx64/cyberglm",
    "policy_id": "adverserial-policy/dev",
    "proxy_version": "0.1.0"
  }
}
```

- `version` — evidence schema version (1).
- `nonce` — the client nonce, echoed verbatim.
- `issued_at` / `expires_at` — RFC 3339; evidence is valid for 5 minutes.
- `tdx_quote` — hex TDX quote (in `DEV_MODE`, a synthetic `DEVQTE00…` blob).
- `tls_spki_sha256` — `sha256:<base64url>` of the serving certificate's SPKI.
  The client recomputes this from the TLS handshake peer certificate.
- `receipt_pubkey_jwk` — public JWK of the receipt key; `kid` is its RFC 7638
  SHA-256 thumbprint.
- `workload` — policy/model/compose/model digests plus `proxy_version`.
- `gpu_evidence` — the cached NVIDIA NRAS bundle (one signed EAT JWT per GPU),
  or `null` when the collector has not produced one.
- `gpu_evidence_ref` — `"nras-eat-bundle"` when GPU evidence is present.
- `gpu_evidence_fresh_at` — the bundle's `generated_at`; clients apply their
  freshness policy to it.
- `gpu_evidence_stale` — present and `true` when the bundle's `generated_at`
  is older than 10 minutes (or missing). Stale evidence is still served for
  availability; verifiers must fail freshness.
- `dev` — present and `true` only in `DEV_MODE`. Production policy must
  reject any evidence carrying this flag.

### GPU evidence collection (collector sidecar)

NRAS round-trips take seconds, so the proxy never attests at request time. A
Python sidecar (`collector/gpu_evidence_collector.py`, dependency:
`nv-attestation-sdk`) refreshes `GPU_EVIDENCE_FILE` every 5 minutes with a
fresh NRAS round (`get_evidence(options={"ppcie_mode": False})` → `attest()` →
one EAT JWT per GPU), writing atomically (tmp + fsync + rename):

```json
{"version":1,"generated_at":"<RFC3339>","nonce":"<hex>","gpus_attested":8,
 "verdict":"successful","eat_jwts":["…"],"source":"nv_attestation_sdk remote NRAS"}
```

On failure the previous bundle is kept (never truncated); the proxy marks it
stale once it ages past 10 minutes. The proxy re-stats the file at most once
per 30 s and re-reads only on mtime change. In the CVM compose the collector
runs `--once` before the proxy boots (best-effort, `|| true`) and then loops
in the background; the proxy container needs GPU visibility for it.

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

### Everything else → upstream

All other paths are reverse-proxied to `UPSTREAM` with a 100 ms flush
interval (SSE responses stream; nothing is buffered). `Authorization` and all
other headers pass through unchanged. One exception: `GET /v1/models` is
augmented, see below.

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

When `ACME_DOMAINS` is empty, the proxy keeps generating a self-signed P-256
certificate in process at boot — trust comes from the quote-bound SPKI, not a
CA. When `ACME_DOMAINS` is set (with `ACME_EMAIL`, `CERT_DIR`, and the
`DNS_PROVIDER` credentials — `GANDI_PAT`/`GANDI_ZONE` for Gandi LiveDNS, the
default, or `CLOUDFLARE_API_TOKEN`/`CLOUDFLARE_ZONE` for Cloudflare), the
proxy runs a minimal stdlib-only RFC 8555 client:

1. Loads (or creates and persists) the P-256 ACME account key at
   `CERT_DIR/account.key`.
2. If `CERT_DIR/certificate.crt` exists, covers all configured domains, and
   has ≥30 days left, it is used as-is (no re-issuance on restart).
3. Otherwise: new order → for each domain, `_acme-challenge.<sub>` TXT record
   set via the selected provider (Gandi LiveDNS `PUT/DELETE
   /v5/livedns/domains/{zone}/records/{name}/TXT`, or Cloudflare
   `POST/PUT/DELETE /zones/{zoneID}/dns_records`) → challenge notify →
   authorization poll → finalize with a fresh CSR → chain download → persist
   to `CERT_DIR`. Challenge records are always deleted afterwards.
4. A background ticker checks every 12 h and renews (hot-swapping the serving
   certificate via `tls.Config.GetCertificate`) when <30 days remain.

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
bounded request and returns a five-minute Ed25519 JWS with an opaque
reservation ID, canonical model ID, input/output limits, one-use count, and
the TLS SPKI fingerprint observed during client verification.

The CVM verifies that JWS locally using `ENTITLEMENT_JWKS_JSON`. It checks the
issuer, audience, expiry, canonical model, exact active TLS SPKI, body-byte
upper bound, and requested `max_tokens`; it then atomically records the
opaque reservation ID in `ENTITLEMENT_REPLAY_DIR` before calling SGLang.
Consequently billing is not contacted on the prompt path and a captured
entitlement cannot be replayed. A crash after consumption is safe: the client
must obtain a fresh entitlement rather than risk a second inference.

After the response, the proxy signs a count-only JWS and first writes it to
`METER_OUTBOX_DIR` with `O_EXCL`, `fsync`, and mode `0600`. It posts
`{"meter":"<JWS>"}` only to `POST {METER_URL}/cc/meter`, using TLS 1.3 and the
dedicated CVM client certificate. The separately deployed
[`confidential-meter-ingress`](https://github.com/AdverserialAI/confidential-meter-ingress)
validates that certificate and its optional SPKI pin, then forwards the
unchanged envelope to its fixed billing URL. Billing requires the ingress
header and verifies the proxy's pinned Ed25519 public key before idempotent
settlement. The file is deleted only after a 2xx response; otherwise it
survives process and CVM restarts and is retried at boot and every 30 seconds.
The event has only reservation ID, request ID, model, counts, timestamps, and
signature — never content, identity, raw API key, or response hash.

The ingress must be outside the CVM and its TLS session must reach that
process un-terminated; an L7 CDN, Heroku dyno, or TLS-terminating proxy cannot
authenticate the CVM client certificate. mTLS is network-origin defense in
depth and does not replace signed-event verification at billing.

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
- **`request_body_hash`**: `sha256:<base64url>` of the raw request body bytes
  exactly as forwarded upstream (post-gate restore).
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
Token counts are intentionally **not** logged: they live inside response
bodies (the final SSE `usage` chunk), which this proxy never inspects.

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

**What it does not prove (yet — see TODOs):**

- That the workload measurement matches a published policy: clients must
  compare evidence against `verify.adverserial.ai` policy documents (WP-5);
  the proxy publishes digests but does not enforce them.
- GPU evidence is a **cached** bundle: `gpu_evidence_fresh_at` /
  `gpu_evidence_stale` expose its age, but the proxy does not re-verify EAT
  signatures — clients must validate the NVIDIA EAT chains against policy and
  reject stale bundles. A GPU/driver swap between collector rounds is visible
  only after the next refresh.
- Per-request receipts bind hashes, not content: a client that never checks
  them (or accepts `receipt_verified=False` silently) gets no route proof.
  Receipts cover the response body; they do not cover upstream HTTP headers.
- Key continuity across restarts: the ACME account key and certificates
  persist on the dstack volume via `CERT_DIR`, but the **receipt** key and the
  self-signed dev TLS key are ephemeral per process boot until KMS sealing
  lands.

**Content boundary:** prompts, completions, attachments, and chat history
exist only inside the CVM (proxy memory + inference server). The proxy's logs
carry metadata only. Billing is metadata-only by construction: the auth gate
sends the full key **to** billing over TLS (billing is the credential store)
but the usage tap sends only `api_key_prefix` + token counts + model +
request_id + timestamp; neither path ever carries prompt or completion
content. DNS, static hosting, and the verification site are outside the TEE
boundary by design. The auth gate buffers request bodies in proxy memory to
read the `model` field (≤64 MiB) — buffered bytes are never logged and are
forwarded to the upstream verbatim.

**`DEV_MODE` caveat:** synthetic evidence proves nothing about a TEE. It
exists for client-integration development and is always marked `"dev": true`.

## TODOs (deliberately not in v0)

- **KMS sealing** of the receipt signing key (and self-signed dev TLS key)
  via dstack `/GetKey` (WP-2/WP-4).
- **GPU evidence freshness tightening**: the collector refreshes every 5 min
  and the proxy flags staleness past 10 min; policy-side min-freshness
  enforcement and per-request GPU binding remain WP-3 exit-criteria work.
- **Rate limiting** on the attestation endpoint.
- Pin base-image digests in the Dockerfile for reproducible releases (WP-1).
- ACME: retry backoff on issuance failure, and CAA/account binding hardening.

## Layout

```
cmd/attest-proxy/        main: config, keygen, ACME wiring, graceful shutdown
collector/               GPU evidence collector (nv_attestation_sdk → NRAS, atomic bundle)
tests/                   collector tests (mocked SDK, offline)
internal/acme/           RFC 8555 dns-01 client, Gandi LiveDNS + Cloudflare providers, cert store
internal/attestation/    evidence building, report_data, GPU bundle cache, dstack QuoteSource
internal/billing/        billing service client (auth check + usage write)
internal/canonjson/      TS-identical canonical JSON + digest
internal/config/         env configuration
internal/entitlement/    billing JWS verification + durable one-use replay store
internal/gate/           /v1/ auth gate + request attribution extraction
internal/meter/          signed count-only meter JWS + durable retry outbox
internal/proxy/          reverse proxy, /v1/models augmenter, usage tap, no-content logging
internal/receipt/        ES256 JWS minting, JWK, RFC 7638 thumbprints
internal/server/         TLS + hot-swap holder, routing, chat vhost, attestation handler
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

Generate the deployment-specific receiver identity only on an administrator
workstation, writing it directly into protected storage:

```sh
go run ./cmd/generate-ehbp-identity --out "$HOME/.config/adverserial/ehbp-identity"
chmod 600 "$HOME/.config/adverserial/ehbp-identity"
```

Copy the single file value into sealed `EHBP_IDENTITY_B64`; never commit or
print it. The proxy publishes only its RFC 9458 public key configuration in
fresh quote-bound evidence.
