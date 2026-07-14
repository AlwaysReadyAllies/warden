"""Warden configuration loading and validation module.

This module handles parsing and validation of Warden policy files.
"""

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import yaml

# SECURITY: DECISION: We enforce strict validation on mode values and fallback to "strict" if invalid or missing.
# ALTERNATIVES: We could allow default "allow" mode, or pass-through arbitrary mode strings.
# WHY: A typo in the config (e.g., "stritc") could default to open/allow access. Defaulting to "strict" ensures we fail closed.
# THREAT: Misconfiguration leading to unauthorized execution of dangerous tools.

# SECURITY: DECISION: Use yaml.safe_load instead of yaml.load.
# ALTERNATIVES: yaml.load with Loader.
# WHY: yaml.load is vulnerable to arbitrary code execution (RCE) via constructor tags. safe_load prevents this.
# THREAT: Arbitrary code execution when parsing untrusted configuration files.

@dataclass
class WardenConfig:
    mode: str = "strict"
    servers: Dict[str, Any] = field(default_factory=dict)
    rules: List[Dict[str, Any]] = field(default_factory=list)
    sensitive_actions: List[str] = field(default_factory=list)
    # Optional OAuth 2.1 Resource-Server auth block (consumed by the HTTP transport). Raw mapping here;
    # warden.auth.AuthConfig.from_mapping validates it (and fails closed if enabled-but-incomplete).
    auth: Optional[Dict[str, Any]] = None
    # Optional cross-server dataflow block (lethal-trifecta defense): {sources, sinks, on_violation}.
    flow: Optional[Dict[str, Any]] = None
    # Optional approval channel: {channel: cli|telegram, ...}. Absent ⇒ CLI (/dev/tty).
    approval: Optional[Dict[str, Any]] = None
    # Optional resource-scoped authorization: {network: {domains: [...]}, filesystem: {roots: [...]}}.
    constraints: Optional[Dict[str, Any]] = None
    # When true, a capability-scoped DENY rule is AUTHORITATIVE — it overrides even an explicit per-tool
    # `action: allow`, so a coarse "no FINANCIAL/DELETE tools, ever" net can't be silently allow-listed
    # past. Default false preserves the documented precedence (an admin may allow one vetted tool by name).
    capability_deny_overrides: bool = False

    def __post_init__(self) -> None:
        # Validate mode
        if self.mode not in ("allow", "strict"):
            # SECURITY: DECISION: Override invalid mode with "strict" to fail closed.
            # ALTERNATIVES: Raise ValueError.
            # WHY: Raising ValueError might crash the system, but silently overriding to "strict" guarantees security enforcement remains intact.
            # THREAT: Bypass of security policy due to invalid mode configuration.
            self.mode = "strict"

        # Sanitize and validate servers mapping
        if not isinstance(self.servers, dict):
            self.servers = {}
        
        # Sanitize and validate rules list
        if not isinstance(self.rules, list):
            self.rules = []
            
        # Sanitize and validate sensitive_actions list
        if not isinstance(self.sensitive_actions, list):
            self.sensitive_actions = []


def load_config(path: str) -> WardenConfig:
    """Loads a Warden configuration from a YAML file.
    
    If the file does not exist, or contains invalid YAML, returns a default strict configuration.
    """
    # SECURITY: DECISION: If config file is missing, return a strict configuration rather than raising an error or returning allow.
    # ALTERNATIVES: Let the application crash, or return an empty allow configuration.
    # WHY: A missing configuration file is a system failure. The safest response is to run in strict mode (fail-closed).
    # THREAT: Unprotected environment due to missing configuration file.
    if not os.path.exists(path):
        return WardenConfig(mode="strict")

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if not isinstance(data, dict):
                return WardenConfig(mode="strict")
            
            return WardenConfig(
                mode=data.get("mode", "strict"),
                servers=data.get("servers", {}),
                rules=data.get("rules", []),
                sensitive_actions=data.get("sensitive_actions", []),
                auth=data.get("auth"),
                flow=data.get("flow"),
                approval=data.get("approval"),
                constraints=data.get("constraints"),
                capability_deny_overrides=bool(data.get("capability_deny_overrides", False)),
            )
    except Exception:
        # SECURITY: DECISION: Any parsing exception defaults to a strict config to fail closed.
        # ALTERNATIVES: Propagate the exception.
        # WHY: If policy loading crashes, the system could fail open or bypass the guard entirely. Failing closed guarantees safety.
        # THREAT: Policy bypass due to syntax errors or corrupt configuration files.
        return WardenConfig(mode="strict")
