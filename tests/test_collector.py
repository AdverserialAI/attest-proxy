"""Tests for the GPU evidence collector with a mocked nv_attestation_sdk.

The collector imports `from nv_attestation_sdk import attestation` lazily
inside collect_bundle(), so injecting fake modules into sys.modules before
calling it fully replaces the SDK (and any GPU/NRAS dependency).
"""

import importlib.util
import json
import os
import sys
import types

import pytest

COLLECTOR = os.path.join(
    os.path.dirname(__file__), "..", "collector", "gpu_evidence_collector.py"
)


def load_collector():
    spec = importlib.util.spec_from_file_location("gpu_evidence_collector", COLLECTOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def make_fake_sdk(fail_attest=False, gpu_count=8):
    """Build a fake nv_attestation_sdk (package + attestation submodule)."""
    pkg = types.ModuleType("nv_attestation_sdk")
    sub = types.ModuleType("nv_attestation_sdk.attestation")

    class Devices:
        GPU = "GPU"

    class Environment:
        REMOTE = "REMOTE"

    class Attestation:
        def __init__(self, name=None):
            self.name = name
            self.verifier = None

        def add_verifier(self, device, env, url, token):
            self.verifier = (device, env, url, token)

        def get_evidence(self, options=None):
            assert options == {"ppcie_mode": False}
            return [{"gpu_index": i} for i in range(gpu_count)]

        def attest(self, evidence):
            if fail_attest:
                raise RuntimeError("NRAS unreachable (mock)")
            assert len(evidence) == gpu_count
            return True

        def get_token(self):
            # Nested ["JWT", ...] + claims structure, one EAT per GPU.
            return {
                "GPU": {
                    "JWT": [f"eyJhbGciOiJIUzI1NiJ9.eyJncHUiOnt9fQ.c2ln{i}" for i in range(gpu_count)]
                },
                "Claims": {"x-nvidia-attestation": "ok"},
            }

        def get_nonce(self):
            return "ab" * 32

    sub.Devices = Devices
    sub.Environment = Environment
    sub.Attestation = Attestation
    pkg.attestation = sub
    return pkg, sub


@pytest.fixture
def collector(monkeypatch):
    pkg, sub = make_fake_sdk()
    monkeypatch.setitem(sys.modules, "nv_attestation_sdk", pkg)
    monkeypatch.setitem(sys.modules, "nv_attestation_sdk.attestation", sub)
    return load_collector()


def test_once_writes_bundle(collector, tmp_path, monkeypatch):
    out = tmp_path / "gpu-evidence.json"
    monkeypatch.setenv("GPU_EVIDENCE_OUT", str(out))

    rc = collector.main(["--once"])
    assert rc == 0

    bundle = json.loads(out.read_text())
    assert bundle["version"] == 1
    assert bundle["verdict"] == "successful"
    assert bundle["gpus_attested"] == 8
    assert len(bundle["eat_jwts"]) == 8
    assert all(j.startswith("eyJ") and j.count(".") == 2 for j in bundle["eat_jwts"])
    assert bundle["nonce"] == "ab" * 32
    assert bundle["source"] == "nv_attestation_sdk remote NRAS"
    # RFC3339 with Z suffix, parses back.
    from datetime import datetime

    datetime.strptime(bundle["generated_at"], "%Y-%m-%dT%H:%M:%SZ")


def test_atomic_write_leaves_no_tmp(collector, tmp_path, monkeypatch):
    out = tmp_path / "gpu-evidence.json"
    monkeypatch.setenv("GPU_EVIDENCE_OUT", str(out))
    collector.main(["--once"])
    leftovers = [p for p in os.listdir(tmp_path) if p.startswith(".gpu-evidence.")]
    assert leftovers == []


def test_failure_keeps_previous_bundle(collector, monkeypatch, tmp_path):
    out = tmp_path / "gpu-evidence.json"
    monkeypatch.setenv("GPU_EVIDENCE_OUT", str(out))

    # First round succeeds.
    assert collector.main(["--once"]) == 0
    before = out.read_bytes()

    # Second round: NRAS fails. --once must exit non-zero and the bundle on
    # disk must be byte-identical to before.
    pkg, sub = make_fake_sdk(fail_attest=True)
    monkeypatch.setitem(sys.modules, "nv_attestation_sdk", pkg)
    monkeypatch.setitem(sys.modules, "nv_attestation_sdk.attestation", sub)
    with pytest.raises(RuntimeError, match="NRAS unreachable"):
        collector.collect_bundle()
    assert out.read_bytes() == before


def test_attest_false_verdict_raises(collector, monkeypatch, tmp_path):
    pkg, sub = make_fake_sdk()
    monkeypatch.setitem(sys.modules, "nv_attestation_sdk", pkg)
    monkeypatch.setitem(sys.modules, "nv_attestation_sdk.attestation", sub)

    # attest() returning False (not raising) must also fail the round.
    sub.Attestation.attest = lambda self, evidence: False
    with pytest.raises(RuntimeError, match="negative verdict"):
        collector.collect_bundle()


def test_empty_jwts_raises(collector, monkeypatch):
    pkg, sub = make_fake_sdk()
    sub.Attestation.get_token = lambda self: {"GPU": {"JWT": []}}
    monkeypatch.setitem(sys.modules, "nv_attestation_sdk", pkg)
    monkeypatch.setitem(sys.modules, "nv_attestation_sdk.attestation", sub)
    with pytest.raises(RuntimeError, match="no EAT JWTs"):
        collector.collect_bundle()


def test_extract_jwts_shapes(collector):
    node = {"a": ["eyJ.x.y", "not-a-jwt", {"b": "eyJ.p.q"}], "c": 42, "d": None}
    assert collector.extract_jwts(node) == ["eyJ.x.y", "eyJ.p.q"]
