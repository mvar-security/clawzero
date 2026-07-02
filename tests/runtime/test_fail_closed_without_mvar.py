"""Fail-closed behavior when the MVAR enforcement engine is unavailable.

ClawZero must refuse to run rather than silently degrade to the weaker embedded
policy engine (which does not enforce the full IFC taint invariant). These tests
simulate MVAR being absent and assert a hard stop by default, plus the explicit
opt-out paths.

Regression guard for Phase 2 finding CZ-2 (silent fail-open to embedded engine).
"""

import importlib

import pytest

from clawzero.exceptions import MVARUnavailableError
from clawzero.runtime import MVARRuntime


def _force_mvar_absent(monkeypatch):
    """Make the MVAR governor impossible to load, simulating mvar-security absent.

    Uses the runtime's own CLAWZERO_ENGINE_MODE=embedded escape hatch, which drives
    _try_load_mvar() to return False exactly as an import failure would — without
    having to uninstall the package from the test environment.
    """
    monkeypatch.setenv("CLAWZERO_ENGINE_MODE", "embedded")
    # Ensure the embedded escape hatch is NOT set, so require_mvar stays authoritative.
    monkeypatch.delenv("CLAWZERO_ALLOW_EMBEDDED", raising=False)


def test_runtime_hard_stops_when_mvar_absent_by_default(monkeypatch):
    """Default construction must raise MVARUnavailableError when MVAR can't load."""
    _force_mvar_absent(monkeypatch)
    with pytest.raises(MVARUnavailableError):
        MVARRuntime(profile="prod_locked")


def test_runtime_hard_stops_message_names_the_cause(monkeypatch):
    _force_mvar_absent(monkeypatch)
    with pytest.raises(MVARUnavailableError) as exc:
        MVARRuntime()
    msg = str(exc.value).lower()
    assert "mvar" in msg and ("fails closed" in msg or "fail" in msg)


def test_explicit_require_mvar_false_allows_embedded(monkeypatch):
    """Opt-out via require_mvar=False must be honored (embedded engine, reduced guarantees)."""
    _force_mvar_absent(monkeypatch)
    rt = MVARRuntime(profile="prod_locked", require_mvar=False)
    assert rt.engine == "embedded-policy-v0.1"
    assert rt.require_mvar is False


def test_env_escape_hatch_allows_embedded(monkeypatch):
    """CLAWZERO_ALLOW_EMBEDDED=1 must also permit the embedded engine explicitly."""
    monkeypatch.setenv("CLAWZERO_ENGINE_MODE", "embedded")
    monkeypatch.setenv("CLAWZERO_ALLOW_EMBEDDED", "1")
    rt = MVARRuntime()  # require_mvar defaults True, but env escape hatch overrides
    assert rt.engine == "embedded-policy-v0.1"
    assert rt.require_mvar is False


def test_default_is_require_mvar_true(monkeypatch):
    """The security-critical default: require_mvar is True unless overridden."""
    # Do not force absence here; just confirm the flag default is fail-closed.
    monkeypatch.delenv("CLAWZERO_ENGINE_MODE", raising=False)
    monkeypatch.delenv("CLAWZERO_ALLOW_EMBEDDED", raising=False)
    rt = MVARRuntime()  # MVAR present in this env → constructs fine
    assert rt.require_mvar is True
    assert rt.engine == "mvar-security"
