#!/usr/bin/env python3
"""GPU evidence collector for the Adverserial confidential deployment.

Collects NVIDIA GPU attestation evidence via nv_attestation_sdk against NRAS
(remote verifier) and writes the EAT bundle atomically to GPU_EVIDENCE_OUT
(default /data/gpu-evidence.json). attest-proxy embeds that file in its
/attestation evidence (gpu_evidence) and never talks to NRAS itself.

Failure policy: a failed collection keeps the previous bundle untouched — the
proxy marks it stale via gpu_evidence_fresh_at / gpu_evidence_stale, and
clients apply their freshness policy. This collector never truncates or
removes an existing bundle on failure.

Dependency (installed in the CVM image/compose): nv-attestation-sdk
    pip install nv-attestation-sdk

Modes:
    gpu_evidence_collector.py --once     single collection round, exit non-zero on failure
    gpu_evidence_collector.py            loop every GPU_EVIDENCE_INTERVAL seconds (default 300)
"""

import argparse
import base64
import json
import logging
import os
import secrets
import sys
import tempfile
import time
import warnings
from datetime import datetime, timezone

# nv_attestation_sdk (and some of its transitive deps) emit deprecation
# warnings on import; keep collector logs signal-only.
warnings.filterwarnings("ignore", category=DeprecationWarning)

log = logging.getLogger("gpu-evidence-collector")

NRAS_URL = os.environ.get("NRAS_URL", "https://nras.attestation.nvidia.com/v4/attest/gpu")
DEFAULT_OUT = "/data/gpu-evidence.json"
DEFAULT_INTERVAL = 300  # seconds; NRAS round-trips take seconds, so 5 min is the freshness/cost tradeoff


def _is_nvidia_eat(token):
    """Keep only NVIDIA-signed detached/overall EATs: ES384 header with a kid.
    The SDK token structure also carries an HS256 session JWT that is not an
    EAT and must not enter the bundle."""
    try:
        header = json.loads(base64.urlsafe_b64decode(token.split(".", 1)[0] + "=="))
    except (ValueError, IndexError, UnicodeDecodeError):
        return False
    return header.get("alg") == "ES384" and bool(header.get("kid"))


def extract_jwts(node, _depth=0):
    """Walk the get_token() structure and collect EAT JWT strings.

    nv_attestation_sdk returns a nested ["JWT", token(s)] + claims structure;
    with 8 GPUs there is one NVIDIA-signed EAT per GPU. We collect defensively
    by shape (three base64url segments, JWTs start with "eyJ") rather than by
    key path, so SDK layout changes don't break us. get_token() itself returns
    a JSON-encoded string, so string nodes that look like JSON are decoded and
    walked recursively.
    """
    found = []
    if _depth > 12:
        return found
    if isinstance(node, str):
        if node.startswith("eyJ") and node.count(".") == 2:
            found.append(node)
        elif node[:1] in "[{":
            try:
                decoded = json.loads(node)
            except ValueError:
                return found
            found.extend(extract_jwts(decoded, _depth + 1))
    elif isinstance(node, dict):
        for value in node.values():
            found.extend(extract_jwts(value, _depth + 1))
    elif isinstance(node, (list, tuple)):
        for value in node:
            found.extend(extract_jwts(value, _depth + 1))
    return found


def collect_bundle():
    """Run one collection + NRAS attestation round. Raises on failure."""
    from nv_attestation_sdk import attestation

    service_key = os.environ.get("NV_ATTESTATION_SERVICE_KEY", "").strip()
    if not service_key:
        raise RuntimeError("NV_ATTESTATION_SERVICE_KEY is required for remote NVIDIA attestation")
    try:
        minimum_gpus = int(os.environ.get("GPU_EVIDENCE_MIN_GPU_COUNT", "1"))
    except ValueError as exc:
        raise RuntimeError("GPU_EVIDENCE_MIN_GPU_COUNT must be an integer") from exc
    if minimum_gpus < 1:
        raise RuntimeError("GPU_EVIDENCE_MIN_GPU_COUNT must be positive")

    client = attestation.Attestation(name="attest-proxy-collector")
    client.set_service_key(service_key)
    client.add_verifier(
        attestation.Devices.GPU,
        attestation.Environment.REMOTE,
        NRAS_URL,
        "",
    )
    evidence = client.get_evidence(options={"ppcie_mode": False})
    ok = client.attest(evidence)
    if not ok:
        raise RuntimeError("NRAS attestation returned a negative verdict")
    token = client.get_token()
    eat_jwts = [jwt for jwt in extract_jwts(token) if _is_nvidia_eat(jwt)]
    if not eat_jwts:
        raise RuntimeError("NRAS attestation succeeded but yielded no EAT JWTs")
    if len(eat_jwts) < minimum_gpus:
        raise RuntimeError(f"NRAS attestation returned {len(eat_jwts)} GPU EATs; expected at least {minimum_gpus}")

    # The SDK generates the NRAS round nonce per Attestation instance; expose
    # it when available, otherwise record a locally generated round id.
    get_nonce = getattr(client, "get_nonce", None)
    if callable(get_nonce):
        nonce = get_nonce()
        nonce_hex = nonce.hex() if isinstance(nonce, (bytes, bytearray)) else str(nonce)
    else:
        nonce_hex = secrets.token_hex(32)

    return {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nonce": nonce_hex,
        "gpus_attested": len(eat_jwts),
        "verdict": "successful",
        "eat_jwts": eat_jwts,
        "source": "nv_attestation_sdk remote NRAS",
        "nras_url": NRAS_URL,
        "minimum_gpu_count": minimum_gpus,
    }


def write_atomic(path, payload):
    """Write payload as JSON to path atomically (tmp file + fsync + rename)."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".gpu-evidence.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def collect_and_write(out_path):
    bundle = collect_bundle()
    write_atomic(out_path, bundle)
    log.info(
        "GPU evidence refreshed: %d EATs, nonce=%s… -> %s",
        bundle["gpus_attested"],
        bundle["nonce"][:16],
        out_path,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description="NVIDIA NRAS GPU evidence collector")
    parser.add_argument("--once", action="store_true", help="single collection round, then exit")
    parser.add_argument(
        "--interval",
        type=int,
        default=int(os.environ.get("GPU_EVIDENCE_INTERVAL", str(DEFAULT_INTERVAL))),
        help="seconds between collection rounds in loop mode",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    out_path = os.environ.get("GPU_EVIDENCE_OUT", DEFAULT_OUT)

    if args.once:
        collect_and_write(out_path)
        return 0

    while True:
        try:
            collect_and_write(out_path)
        except Exception as exc:  # keep previous bundle; retry next cycle
            log.error("collection failed (previous bundle kept): %s", exc)
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
