"""Warden — drop-in MCP security middleware."""
from .schemas import (
    Action,
    ApprovalOutcome,
    AuditRecord,
    Decision,
    Direction,
    GuardFinding,
    ToolCall,
)

try:
    from importlib.metadata import version as _v
    __version__ = _v("warden-mcp")          # single source of truth: the installed package metadata
except Exception:
    __version__ = "0.0.0+dev"
__all__ = [
    "Action",
    "ApprovalOutcome",
    "AuditRecord",
    "Decision",
    "Direction",
    "GuardFinding",
    "ToolCall",
]
