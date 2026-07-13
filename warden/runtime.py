"""Shared control assembly — the ONE place that wires a config's controls into an Interceptor.

Both the live proxy (`warden run`) and the effectiveness harness (`warden prove`) build their
interceptor here, so the attacks in the proof exercise the exact same construction that runs in
production — the harness can never test a differently-wired Warden than the one you deploy.
"""
from __future__ import annotations

from typing import Any

from .interceptor import Interceptor
from .policy import WardenPolicy
from .guard import WardenGuard


def build_controls(cfg: Any) -> dict:
    """Construct every deterministic control from a config. Returns a kwargs dict for Interceptor."""
    controls: dict[str, Any] = {"policy": WardenPolicy(cfg), "guard": WardenGuard()}

    if getattr(cfg, "flow", None):
        from .flow import FlowPolicy, FlowTracker
        fp = FlowPolicy.from_mapping(cfg.flow)
        if fp.enabled:
            controls["flow"] = FlowTracker(fp)

    if getattr(cfg, "constraints", None):
        from .boundaries import Boundaries
        b = Boundaries.from_mapping(cfg.constraints)
        if b.active:
            controls["boundaries"] = b

    from .argconstraints import ArgumentConstraints
    ac = ArgumentConstraints(getattr(cfg, "servers", None) or {})
    if ac.active:
        controls["arg_constraints"] = ac

    from .postconditions import Postconditions
    pc = Postconditions(getattr(cfg, "servers", None) or {})
    if pc.active:
        controls["postconditions"] = pc

    return controls


def build_interceptor(cfg: Any, audit: Any, approval: Any = None, approver: str = "operator") -> Interceptor:
    """Assemble a fully-wired Interceptor from a config (the production construction)."""
    controls = build_controls(cfg)
    policy = controls.pop("policy")
    guard = controls.pop("guard")
    return Interceptor(policy, audit, guard=guard, approval=approval, approver=approver, **controls)


__all__ = ["build_controls", "build_interceptor"]
