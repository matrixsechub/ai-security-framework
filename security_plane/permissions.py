"""
security_plane/permissions.py
------------------------------
§03 — Agent Permissioning Model

Thin facade over the canonical MEMORY_NAMESPACE_MAP and CROSS_REPO_PERMISSIONS
defined in agent_config.py.  Provides higher-level validator helpers so other
modules import from one place rather than reaching into agent_config directly.

Cross-repo trust rules encoded here are bootstrap-only; enforcement at the
network/API boundary is deferred to the operator-surfaces and audit-hardening
branches.
"""

from __future__ import annotations

from typing import Any

from agent_config import (
    AGENT_REGISTRY,
    CROSS_REPO_PERMISSIONS,
    MEMORY_NAMESPACE_MAP,
    TrustLevel,
    ToolCategory,
    validate_agent_namespace_access,
    validate_cross_repo_tool_access,
)

__all__ = [
    "AgentPermissionValidator",
    "list_agent_namespaces",
    "list_repo_tools",
    "KNOWN_REPOS",
    # Aurelius — §04 reactivation surface
    "AURELIUS_GRANTED_NAMESPACES",
    "AURELIUS_CROSS_REPO_TOOLS",
]

KNOWN_REPOS: tuple[str, ...] = (
    "ai-security-framework",
    "intake-agent-v2",
    "ttx-operator-shell",
    "marketplace-tracking-backend",
    "gh0st-lay3r",
)

# ── Aurelius permission surface (human-readable reference) ────────────────────
# Derived from MEMORY_NAMESPACE_MAP and CROSS_REPO_PERMISSIONS in agent_config.py.
# Authoritative values are always in agent_config.py; these constants are read-only
# documentation for security-plane consumers that don't want to call the validator.
AURELIUS_GRANTED_NAMESPACES: dict[str, list[str]] = {
    "read":  ["session:analysis", "session:investigation", "kb:cve"],
    "write": ["session:analysis"],
}

# Tools Aurelius may invoke within the ai-security-framework repo context.
# "safe_telemetry_log" covers both safeTelemetryLog emission and
# validate_prompt_agent_linkage() governance health-checks (Task 3).
AURELIUS_CROSS_REPO_TOOLS: dict[str, str] = {
    "safe_telemetry_log": "write",   # ai-security-framework
    "siem_read":          "read",    # read:public telemetry
    "rag_retrieval":      "read",    # read:analysis knowledge base
    "cve_lookup":         "read",    # read:analysis vulnerability context
    "report_write":       "write",   # write:analysis findings
}


class AgentPermissionValidator:
    """
    Validates agent access to namespaces and cross-repo tool grants.

    Usage:
        validator = AgentPermissionValidator("ComplianceGovernanceAgent")
        validator.assert_namespace_read("audit:decisions")
        validator.assert_namespace_write("audit:decisions")
    """

    def __init__(self, agent_name: str) -> None:
        if agent_name not in {cfg.name for cfg in AGENT_REGISTRY.values()}:
            raise ValueError(
                f"Unknown agent '{agent_name}'. "
                f"Valid names: {[c.name for c in AGENT_REGISTRY.values()]}"
            )
        self.agent_name = agent_name
        self._config = next(c for c in AGENT_REGISTRY.values() if c.name == agent_name)

    # ── Namespace checks ──────────────────────────────────────────────────

    def can_read_namespace(self, namespace: str) -> bool:
        return validate_agent_namespace_access(self.agent_name, namespace, "read")

    def can_write_namespace(self, namespace: str) -> bool:
        return validate_agent_namespace_access(self.agent_name, namespace, "write")

    def assert_namespace_read(self, namespace: str) -> None:
        """Raise PermissionError if agent cannot read namespace."""
        if not self.can_read_namespace(namespace):
            raise PermissionError(
                f"{self.agent_name} is not permitted to READ namespace '{namespace}'. "
                f"Permitted readers: {MEMORY_NAMESPACE_MAP.get(namespace, {}).get('read_agents', [])}"
            )

    def assert_namespace_write(self, namespace: str) -> None:
        """Raise PermissionError if agent cannot write namespace."""
        if not self.can_write_namespace(namespace):
            raise PermissionError(
                f"{self.agent_name} is not permitted to WRITE namespace '{namespace}'. "
                f"Permitted writers: {MEMORY_NAMESPACE_MAP.get(namespace, {}).get('write_agents', [])}"
            )

    # ── Scope audit ───────────────────────────────────────────────────────

    def readable_namespaces(self) -> list[str]:
        """Return all namespaces this agent may read."""
        return [ns for ns in MEMORY_NAMESPACE_MAP if self.can_read_namespace(ns)]

    def writable_namespaces(self) -> list[str]:
        """Return all namespaces this agent may write."""
        return [ns for ns in MEMORY_NAMESPACE_MAP if self.can_write_namespace(ns)]

    def permitted_tools(self) -> list[ToolCategory]:
        """Return the agent's allowed tool categories (from AgentConfig)."""
        return list(self._config.allowed_tools)

    def trust_level(self) -> TrustLevel:
        return self._config.trust_level

    def summary(self) -> dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "trust_level": self._config.trust_level.name,
            "readable_namespaces": self.readable_namespaces(),
            "writable_namespaces": self.writable_namespaces(),
            "permitted_tools": [t.value for t in self.permitted_tools()],
        }


# ── Module-level helpers ──────────────────────────────────────────────────────

def list_agent_namespaces(agent_name: str) -> dict[str, list[str]]:
    """
    Return {'read': [...], 'write': [...]} namespace lists for agent_name.
    Convenience wrapper for quick inspection without instantiating the validator.
    """
    validator = AgentPermissionValidator(agent_name)
    return {
        "read": validator.readable_namespaces(),
        "write": validator.writable_namespaces(),
    }


def list_repo_tools(repo: str) -> dict[str, str]:
    """
    Return {tool_category_value: access_level} for the given repo.
    access_level is one of: 'none' | 'read' | 'write' | 'source'.
    """
    if repo not in KNOWN_REPOS:
        raise ValueError(f"Unknown repo '{repo}'. Known repos: {KNOWN_REPOS}")
    return {
        tool_value: access_level
        for tool_value, repo_map in CROSS_REPO_PERMISSIONS.items()
        if (access_level := repo_map.get(repo, "none")) != "none"
    }
