# Confidential vLLM prefix-cache binding

Status: source implementation and local contract tests only. Not deployed,
not tested against the confidential H200 engine, and not a throughput claim.
Current CVM changes still require explicit owner approval.

With `CONFIDENTIAL_CACHE_ISOLATION=1`, confidential Chat Completions and
Responses requests get a server-controlled `cache_salt` after entitlement
signature, authority, model, time, channel and request-bound checks. The flag
defaults off for existing inference engines and requires confidential mode.

Billing can include the optional 43-character `cache_namespace` in a signed
v1 entitlement. Its value is an opaque HMAC scoped to the authenticated
immutable user ID, model, issuer and audience. The dedicated derivation key
stays at billing. The proxy never receives an email, raw user ID or derivation
key. This opt-in identifier intentionally links requests within one account;
it is not an anonymity guarantee against the inference service.

The proxy hashes that signed scope with its own purpose/model/authority domain
separation. Tokens without the field use a reservation-specific namespace,
preventing legacy callers from silently joining a shared global prefix cache.
Client `cache_salt`/`cache_namespace` fields, including case variants, are
rejected before replay consumption or billing dispatch. Original request
bytes remain the signed receipt input, and streaming usage injection and
terminal settlement behavior are preserved.

## Acceptance before activation

- Preserve EHBP, backend loopback authentication, replay protection, exact
  attested model/runtime/configuration pins and public-log privacy controls.
- Bind billing scopes to immutable identity from the same credential check;
  email lookup after authentication is insufficient if an address is reused.
- Keep multimodal preprocessing caching off until it has an independently
  reviewed tenant namespace. Do not accept caller-selected multimodal IDs.
- Test actual vLLM behavior on both API routes: same-account repeated prefix
  produces a real cache hit, a different account's first matching prefix is
  cold, and legacy entitlements cannot reuse another request's cached prefix.
  A fake backend or merely seeing an injected salt does not pass this gate.
- Test 64 concurrent, independently authorized sessions, unique response and
  recall markers, cancellation, key revocation, malformed/tampered scopes,
  signed receipts and actual cached-token settlement without credit changes.
- Inspect native logs with synthetic canaries: no prompts, completions,
  bearer tokens or namespace values may appear in public logs on success or
  error paths. Scope binding alone is not full VM/session isolation proof.

Local validation covers signed scopes, distinct accounts and authority/model
domains, legacy request isolation, caller spoof rejection before dispatch,
original receipt hash/content length, streaming usage, Responses and default
compatibility. Full proxy tests and the affected packages' race checks pass.
No signing key, customer record, inference request or production ledger is
needed for those tests.
