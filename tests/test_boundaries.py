"""Tests for resource-scoped authorization (destination / filesystem boundaries)."""
import asyncio

import pytest

from warden.boundaries import Boundaries
from warden.config import WardenConfig
from warden.interceptor import Blocked, Interceptor
from warden.policy import WardenPolicy
from warden.schemas import ToolCall


class _Audit:
    def append(self, rec): pass
    def verify(self): return True, "ok"


def _call(**args):
    return ToolCall("srv", "tool", dict(args))


# --- network domain allowlist --------------------------------------------------------------------

def test_network_allows_listed_domain():
    b = Boundaries.from_mapping({"network": {"domains": ["api.github.com", "*.company.internal"]}})
    assert b.check(_call(url="https://api.github.com/repos")) is None
    assert b.check(_call(url="https://svc.company.internal/x")) is None


def test_network_blocks_unlisted_domain():
    b = Boundaries.from_mapping({"network": {"domains": ["api.github.com"]}})
    v = b.check(_call(url="https://evil.example/steal"))
    assert v and "evil.example" in v


def test_network_blocks_ssrf_metadata():
    b = Boundaries.from_mapping({"network": {"domains": ["api.github.com"]}})
    assert b.check(_call(endpoint="http://169.254.169.254/latest/meta-data/")) is not None


# --- filesystem root allowlist -------------------------------------------------------------------

def test_filesystem_allows_under_root():
    b = Boundaries.from_mapping({"filesystem": {"roots": ["/workspace/project"]}})
    assert b.check(_call(path="/workspace/project/src/main.py")) is None


def test_filesystem_blocks_outside_root():
    b = Boundaries.from_mapping({"filesystem": {"roots": ["/workspace/project"]}})
    assert b.check(_call(path="/etc/passwd")) is not None


def test_filesystem_blocks_traversal_escape():
    b = Boundaries.from_mapping({"filesystem": {"roots": ["/workspace/project"]}})
    # normalizes to /workspace/secrets — outside the root
    assert b.check(_call(path="/workspace/project/../secrets")) is not None
    # relative traversal escaping the workspace
    assert b.check(_call(path="../../etc/passwd")) is not None


def test_no_constraints_is_noop():
    b = Boundaries.from_mapping(None)
    assert not b.active
    assert b.check(_call(url="http://anything", path="/etc/passwd")) is None


def test_nested_args_are_scanned():
    b = Boundaries.from_mapping({"network": {"domains": ["ok.com"]}})
    assert b.check(_call(payload={"targets": ["https://evil.example"]})) is not None


# --- interceptor enforcement ---------------------------------------------------------------------

def _run(boundaries, call, result="ok"):
    icept = Interceptor(WardenPolicy(WardenConfig(mode="allow")), _Audit(), boundaries=boundaries)
    return asyncio.run(icept.run(call, lambda c: result))


def test_interceptor_denies_boundary_violation():
    b = Boundaries.from_mapping({"network": {"domains": ["api.github.com"]}})
    with pytest.raises(Blocked) as e:
        _run(b, _call(url="https://evil.example"))
    assert "evil.example" in str(e.value)


def test_interceptor_allows_within_boundary():
    b = Boundaries.from_mapping({"network": {"domains": ["api.github.com"]}})
    out = _run(b, _call(url="https://api.github.com/x"), result="fetched")
    assert out == "fetched"
