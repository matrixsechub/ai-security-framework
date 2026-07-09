
"""
agent_config.py
---------------
MatrixSecHub AI-Cybersecurity Suite
Multi-agent configuration for CrewAI and AutoGen orchestration.

This module defines agent identities, role constraints, tool permissions,
memory boundaries, and safety guardrails for the four core security agents.

Design principles:
  - Least-privilege tool access per agent role
  - Explicit trust levels enforced at orchestration layer
  - Memory isolation prevents cross-agent context bleed
  - Safety guardrails block policy-violating outputs before propagation
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

# ---------------------------------------------------------------------------
# Enumerations: Trust Levels and Tool Categories
# ---------------------------------------------------------------------------

class TrustLevel(Enum):
    """
    Defines the trust tier assigned to each agent.
    Higher trust = broader autonomy + veto/approval rights.
    """
    LOW = auto()       # Sandboxed; outputs reviewed before release
    MEDIUM = auto()    # Standard operational access; no destructive tools
    HIGH = auto()      # Policy authority; can block downstream agents


class ToolCategory(Enum):
    """
    Categories of tools available within the pipeline.
    Agents are granted a subset based on their role.
    """
    SIEM_READ        = "siem_read"           # Read-only SIEM/log queries
    CVE_LOOKUP       = "cve_lookup"          # NVD / CVE database queries
    MITRE_ATT_CK     = "mitre_attck"         # MITRE ATT&CK TTP retrieval
    THREAT_INTEL     = "threat_intel"        # External TI feeds (read)
    COMPLIANCE_DB    = "compliance_db"       # NIST / SOC 2 control lookup
    RAG_RETRIEVAL    = "rag_retrieval"       # Internal vector store queries
    REPORT_WRITE     = "report_write"        # Write structured report artifacts
    POLICY_GATE      = "policy_gate"         # Approve / block pipeline messages
    SIMULATION_EXEC  = "simulation_exec"     # Adversarial simulation (sandboxed)
    ALERT_DISPATCH   = "alert_dispatch"      # Dispatch alerts to ticketing/SIEM
    SAFE_TELEMETRY_LOG = "safe_telemetry_log"  # Aurelius: write audit-safe telemetry events


# ---------------------------------------------------------------------------
# Agent Configuration Dataclass
# ---------------------------------------------------------------------------

@dataclass
class AgentConfig:
    """
    Canonical configuration for a single security agent.

    Attributes:
        name:               Human-readable agent identifier.
        role:               Short role descriptor (used in prompt injection).
        trust_level:        Trust tier governing autonomy and veto rights.
        allowed_tools:      Explicit whitelist of permitted tool categories.
        memory_scope:       Keys defining accessible memory namespaces.
        max_iterations:     Hard cap on reasoning loops per invocation.
        output_schema:      Expected structured output format identifier.
        safety_guardrails:  List of active safety rule identifiers.
        requires_review:    Whether outputs require human or Compliance Agent review.
        temperature:        LLM sampling temperature for this agent.
        model:              LLM backend assignment.
    """
    name: str
    role: str
    trust_level: TrustLevel
    allowed_tools: list[ToolCategory]
    memory_scope: list[str]
    max_iterations: int
    output_schema: str
    safety_guardrails: list[str]
    requires_review: bool
    temperature: float = 0.2
    model: str = "gpt-4o"


# ---------------------------------------------------------------------------
# Safety Guardrail Definitions
# ---------------------------------------------------------------------------

GUARDRAIL_REGISTRY: dict[str, dict[str, Any]] = {
    "no_pii_in_output": {
        "description": "Strip or flag PII patterns (email, IP attribution, usernames) in agent output.",
        "action": "redact_and_flag",
    },
    "no_destructive_commands": {
        "description": "Block outputs containing shell commands with destructive potential (rm, DROP, format).",
        "action": "reject_and_log",
    },
    "structured_output_only": {
        "description": "Enforce JSON/YAML schema compliance; reject free-text outputs.",
        "action": "reject_and_retry",
    },
    "citation_required": {
        "description": "Every factual claim must include a RAG source reference or be flagged as ungrounded.",
        "action": "flag_for_review",
    },
    "no_external_url_generation": {
        "description": "Block generation of external URLs or hyperlinks not in the approved domain list.",
        "action": "reject_and_log",
    },
    "sandbox_boundary_enforcement": {
        "description": "Adversary agent outputs must not reference real production hostnames, credentials, or internal IPs.",
        "action": "sanitize_and_flag",
    },
    "compliance_gate_required": {
        "description": "Output cannot propagate downstream without Compliance Agent approval token.",
        "action": "hold_for_approval",
    },
    "max_token_budget": {
        "description": "Enforce per-turn token budget to prevent resource exhaustion attacks.",
        "action": "truncate_and_warn",
        "params": {"max_output_tokens": 4096},
    },
}


# ---------------------------------------------------------------------------
# Agent Definitions
# ---------------------------------------------------------------------------

SECURITY_ANALYST_AGENT = AgentConfig(
    name="SecurityAnalystAgent",
    role="Senior Security Analyst",
    trust_level=TrustLevel.MEDIUM,
    allowed_tools=[
        ToolCategory.SIEM_READ,
        ToolCategory.CVE_LOOKUP,
        ToolCategory.RAG_RETRIEVAL,
        ToolCategory.THREAT_INTEL,
        ToolCategory.REPORT_WRITE,
    ],
    # Memory scoped to current investigation session only.
    # No access to cross-session history or red-team outputs.
    memory_scope=["session:investigation", "kb:cve", "kb:mitre"],
    max_iterations=6,
    output_schema="security_finding_v1",
    safety_guardrails=[
        "no_pii_in_output",
        "structured_output_only",
        "citation_required",
        "no_external_url_generation",
        "max_token_budget",
    ],
    requires_review=False,  # Analyst outputs flow automatically to Compliance Agent
    temperature=0.1,        # Low temperature for deterministic analysis
    model=os.getenv("ANALYST_MODEL", "gpt-4o"),
)


THREAT_MODELING_AGENT = AgentConfig(
    name="ThreatModelingAgent",
    role="Threat Modeling Specialist",
    trust_level=TrustLevel.MEDIUM,
    allowed_tools=[
        ToolCategory.MITRE_ATT_CK,
        ToolCategory.CVE_LOOKUP,
        ToolCategory.RAG_RETRIEVAL,
        ToolCategory.REPORT_WRITE,
    ],
    # Read access to asset inventory and architecture docs; no SIEM access.
    memory_scope=["session:threat_model", "kb:mitre", "kb:nist_controls", "kb:asset_inventory"],
    max_iterations=8,
    output_schema="stride_threat_model_v2",
    safety_guardrails=[
        "structured_output_only",
        "citation_required",
        "no_external_url_generation",
        "compliance_gate_required",
        "max_token_budget",
    ],
    requires_review=False,
    temperature=0.2,
    model=os.getenv("THREAT_MODEL_MODEL", "gpt-4o"),
)


RED_TEAM_ADVERSARY_AGENT = AgentConfig(
    name="RedTeamAdversaryAgent",
    role="Adversarial Red Team Operator",
    trust_level=TrustLevel.LOW,   # Lowest trust; all outputs reviewed
    allowed_tools=[
        ToolCategory.MITRE_ATT_CK,
        ToolCategory.SIMULATION_EXEC,  # Sandboxed simulation only
        ToolCategory.RAG_RETRIEVAL,
    ],
    # Isolated memory namespace; cannot read analyst or compliance outputs.
    # Prevents the adversary agent from tailoring attacks to known defenses.
    memory_scope=["session:redteam_sandbox", "kb:mitre"],
    max_iterations=5,             # Tighter loop cap for adversarial agent
    output_schema="red_team_finding_v1",
    safety_guardrails=[
        "structured_output_only",
        "sandbox_boundary_enforcement",
        "no_destructive_commands",
        "no_pii_in_output",
        "no_external_url_generation",
        "compliance_gate_required",
        "max_token_budget",
    ],
    requires_review=True,         # ALL red-team outputs require Compliance Agent review
    temperature=0.4,              # Slightly higher temperature for creative adversarial thinking
    model=os.getenv("REDTEAM_MODEL", "gpt-4o"),
)


COMPLIANCE_GOVERNANCE_AGENT = AgentConfig(
    name="ComplianceGovernanceAgent",
    role="AI Governance and Compliance Officer",
    trust_level=TrustLevel.HIGH,  # Veto authority over all pipeline outputs
    allowed_tools=[
        ToolCategory.COMPLIANCE_DB,
        ToolCategory.RAG_RETRIEVAL,
        ToolCategory.POLICY_GATE,
        ToolCategory.ALERT_DISPATCH,
        ToolCategory.REPORT_WRITE,
    ],
    # Broadest read scope; can inspect all session memory for audit purposes.
    # Write access only to compliance reports and policy gate decisions.
    memory_scope=[
        "session:investigation",
        "session:threat_model",
        "session:redteam_sandbox",
        "kb:nist_controls",
        "kb:soc2_criteria",
        "kb:nist_ai_rmf",
        "audit:decisions",
    ],
    max_iterations=4,             # Compliance decisions should be fast and deterministic
    output_schema="compliance_decision_v1",
    safety_guardrails=[
        "structured_output_only",
        "citation_required",
        "no_pii_in_output",
        "max_token_budget",
    ],
    requires_review=False,        # Compliance Agent IS the review authority
    temperature=0.0,              # Zero temperature for maximum determinism in policy decisions
    model=os.getenv("COMPLIANCE_MODEL", "gpt-4o"),
)


# ---------------------------------------------------------------------------
# Aurelius Agent — Security Analysis Orchestrator (reactivated under §§01–04)
# ---------------------------------------------------------------------------
#
# Trust level : MEDIUM  — standard operational access, no veto or delegation rights
# Permissions : read:public (SIEM), read:analysis (RAG, CVE), write:analysis (reports)
# Namespace   : session:analysis (rw), session:investigation (r), kb:cve (r)
# TM escalation: disabled — Aurelius inputs are single-stage alerts; the classifier
#                will not trigger unless force_threat_modeling is set externally.
# Lifecycle   : SecurityLifecycleStage.ANALYSIS_READY (03:ANALYSIS_READY)

AURELIUS_AGENT = AgentConfig(
    name="AureliusAgent",
    role="Security Analysis Orchestrator",
    trust_level=TrustLevel.MEDIUM,
    allowed_tools=[
        ToolCategory.SIEM_READ,           # read:public — live telemetry ingestion
        ToolCategory.RAG_RETRIEVAL,       # read:analysis — knowledge base queries
        ToolCategory.CVE_LOOKUP,          # read:analysis — vulnerability context
        ToolCategory.REPORT_WRITE,        # write:analysis — structured findings
        ToolCategory.SAFE_TELEMETRY_LOG,  # cross-repo: safeTelemetryLog + linkage
    ],
    memory_scope=["session:analysis", "session:investigation", "kb:cve"],
    max_iterations=6,
    output_schema="aurelius_analysis_v1",
    safety_guardrails=[
        "no_pii_in_output",
        "structured_output_only",
        "citation_required",
        "no_external_url_generation",
        "max_token_budget",
    ],
    requires_review=False,
    temperature=0.15,
    model=os.getenv("AURELIUS_MODEL", "gpt-4o"),
)


# ---------------------------------------------------------------------------
# Agent Registry
# ---------------------------------------------------------------------------

AGENT_REGISTRY: dict[str, AgentConfig] = {
    "security_analyst":     SECURITY_ANALYST_AGENT,
    "threat_modeling":      THREAT_MODELING_AGENT,
    "red_team_adversary":   RED_TEAM_ADVERSARY_AGENT,
    "compliance_governance": COMPLIANCE_GOVERNANCE_AGENT,
    "aurelius":             AURELIUS_AGENT,
}


# ---------------------------------------------------------------------------
# CrewAI Agent Factory
# ---------------------------------------------------------------------------

def build_crewai_agent(config: AgentConfig, llm_client: Any) -> Any:
    """
    Instantiate a CrewAI Agent from an AgentConfig.

    Args:
        config:     The AgentConfig defining role, tools, and constraints.
        llm_client: A configured LLM client (OpenAI, Azure, Anthropic).

    Returns:
        A CrewAI Agent instance ready for crew assembly.
    """
    try:
        from crewai import Agent
    except ImportError as exc:
        raise ImportError("crewai is required: pip install crewai") from exc

    return Agent(
        name=config.name,
        role=config.role,
        goal=_derive_goal(config),
        backstory=_derive_backstory(config),
        tools=[],                       # Tool instances injected by tool_registry at runtime
        llm=llm_client,
        max_iter=config.max_iterations,
        memory=True,
        verbose=True,
        allow_delegation=(config.trust_level == TrustLevel.HIGH),
    )


def build_autogen_agent(config: AgentConfig, llm_config: dict[str, Any]) -> Any:
    """
    Instantiate a Microsoft AutoGen AssistantAgent from an AgentConfig.

    Args:
        config:     The AgentConfig defining role, tools, and constraints.
        llm_config: AutoGen-format LLM configuration dictionary.

    Returns:
        An AutoGen AssistantAgent instance.
    """
    try:
        from autogen import AssistantAgent
    except ImportError as exc:
        raise ImportError("pyautogen is required: pip install pyautogen") from exc

    return AssistantAgent(
        name=config.name,
        system_message=_derive_system_message(config),
        llm_config={
            **llm_config,
            "temperature": config.temperature,
        },
        max_consecutive_auto_reply=config.max_iterations,
        human_input_mode="NEVER" if not config.requires_review else "TERMINATE",
    )


# ---------------------------------------------------------------------------
# Internal Helpers
# ---------------------------------------------------------------------------

def _derive_goal(config: AgentConfig) -> str:
    """Derive a CrewAI goal string from agent config metadata."""
    tool_names = ", ".join(t.value for t in config.allowed_tools)
    return (
        f"As a {config.role}, analyze security inputs using available tools "
        f"({tool_names}) and produce structured outputs conforming to "
        f"schema '{config.output_schema}'. Adhere strictly to assigned guardrails."
    )


def _derive_backstory(config: AgentConfig) -> str:
    """Derive a CrewAI backstory from agent trust level and role."""
    trust_map = {
        TrustLevel.LOW:    "operating in a sandboxed simulation environment",
        TrustLevel.MEDIUM: "embedded in an enterprise security operations team",
        TrustLevel.HIGH:   "serving as the final policy authority in the pipeline",
    }
    return (
        f"You are a {config.role} {trust_map[config.trust_level]}. "
        f"Your outputs are governed by {len(config.safety_guardrails)} active safety guardrails. "
        f"All factual claims must be grounded in retrieved knowledge sources."
    )


def _derive_system_message(config: AgentConfig) -> str:
    """Derive an AutoGen system message incorporating guardrail identifiers."""
    guardrail_list = "\n".join(f"  - {g}" for g in config.safety_guardrails)
    return (
        f"You are {config.name}, a {config.role} operating within the MatrixSecHub "
        f"AI-Cybersecurity Suite.\n\n"
        f"Active safety guardrails:\n{guardrail_list}\n\n"
        f"Produce all outputs in '{config.output_schema}' format. "
        f"Do not exceed {config.max_iterations} reasoning steps per task."
    )


# ---------------------------------------------------------------------------
# Security Plane Bootstrap — §03: Agent Permissioning Model
# Integration Plan ref: memory namespace isolation + cross-repo tool permissions
# ---------------------------------------------------------------------------

# Maps every memory namespace to its owning repo, permitted readers/writers,
# and any special constraints (append_only, isolated).
MEMORY_NAMESPACE_MAP: dict[str, dict[str, Any]] = {
    # session:analysis — owned by ai-security-framework; Aurelius writes enriched
    # findings here; intake-agent-v2 sends pre-classified alerts as the source agent.
    # append_only: analysis findings accumulate within a run and are never overwritten.
    "session:analysis": {
        "owner_repo": "ai-security-framework",
        "read_agents": ["AureliusAgent", "intake_agent_v2", "ComplianceGovernanceAgent"],
        "write_agents": ["AureliusAgent"],
        "append_only": True,
    },
    "session:investigation": {
        "owner_repo": "intake-agent-v2",
        "read_agents": ["SecurityAnalystAgent", "AureliusAgent", "ComplianceGovernanceAgent"],
        "write_agents": ["SecurityAnalystAgent"],
    },
    "session:threat_model": {
        "owner_repo": "ai-security-framework",
        "read_agents": ["ThreatModelingAgent", "ComplianceGovernanceAgent"],
        "write_agents": ["ThreatModelingAgent"],
    },
    "session:redteam_sandbox": {
        "owner_repo": "ai-security-framework",
        # RedTeamAdversaryAgent is isolated: it cannot read investigation or
        # compliance outputs, preventing it from tailoring attacks to known defenses.
        "read_agents": ["RedTeamAdversaryAgent", "ComplianceGovernanceAgent"],
        "write_agents": ["RedTeamAdversaryAgent"],
        "isolated": True,
    },
    "kb:cve": {
        "owner_repo": "shared",
        "read_agents": ["SecurityAnalystAgent", "ThreatModelingAgent", "ComplianceGovernanceAgent"],
        "write_agents": [],
    },
    "kb:mitre": {
        "owner_repo": "shared",
        "read_agents": [
            "SecurityAnalystAgent",
            "ThreatModelingAgent",
            "RedTeamAdversaryAgent",
            "ComplianceGovernanceAgent",
        ],
        "write_agents": [],
    },
    "kb:nist_controls": {
        "owner_repo": "shared",
        "read_agents": ["ThreatModelingAgent", "ComplianceGovernanceAgent"],
        "write_agents": [],
    },
    "kb:nist_ai_rmf": {
        "owner_repo": "shared",
        "read_agents": ["ComplianceGovernanceAgent"],
        "write_agents": [],
    },
    "kb:soc2_criteria": {
        "owner_repo": "shared",
        "read_agents": ["ComplianceGovernanceAgent"],
        "write_agents": [],
    },
    # kb:asset_inventory is owned by marketplace-tracking-backend; this repo
    # treats it as a read-only external knowledge base for the TM agent.
    "kb:asset_inventory": {
        "owner_repo": "marketplace-tracking-backend",
        "read_agents": ["ThreatModelingAgent"],
        "write_agents": [],
    },
    "kb:threat_intel": {
        "owner_repo": "shared",
        "read_agents": ["SecurityAnalystAgent"],
        "write_agents": [],
    },
    # audit:decisions is owned by gh0st-lay3r; ComplianceGovernanceAgent may
    # append entries but can never modify or delete prior records.
    "audit:decisions": {
        "owner_repo": "gh0st-lay3r",
        "read_agents": ["ComplianceGovernanceAgent"],
        "write_agents": ["ComplianceGovernanceAgent"],
        "append_only": True,
    },
}

# Maps each ToolCategory to the access level each downstream repo may exercise.
# Access levels: "none" | "read" | "write" | "source"
CROSS_REPO_PERMISSIONS: dict[str, dict[str, str]] = {
    ToolCategory.SIEM_READ.value: {
        "intake-agent-v2":              "source",
        "ai-security-framework":        "read",
        "ttx-operator-shell":           "none",
        "marketplace-tracking-backend": "read",
        "gh0st-lay3r":                  "none",
    },
    ToolCategory.CVE_LOOKUP.value: {
        "intake-agent-v2":              "none",
        "ai-security-framework":        "read",
        "ttx-operator-shell":           "none",
        "marketplace-tracking-backend": "read",
        "gh0st-lay3r":                  "none",
    },
    ToolCategory.MITRE_ATT_CK.value: {
        "intake-agent-v2":              "none",
        "ai-security-framework":        "read",
        "ttx-operator-shell":           "read",
        "marketplace-tracking-backend": "none",
        "gh0st-lay3r":                  "none",
    },
    ToolCategory.THREAT_INTEL.value: {
        "intake-agent-v2":              "none",
        "ai-security-framework":        "read",
        "ttx-operator-shell":           "none",
        "marketplace-tracking-backend": "read",
        "gh0st-lay3r":                  "none",
    },
    ToolCategory.COMPLIANCE_DB.value: {
        "intake-agent-v2":              "none",
        "ai-security-framework":        "read",
        "ttx-operator-shell":           "read",
        "marketplace-tracking-backend": "none",
        "gh0st-lay3r":                  "read",
    },
    ToolCategory.RAG_RETRIEVAL.value: {
        "intake-agent-v2":              "none",
        "ai-security-framework":        "read",
        "ttx-operator-shell":           "none",
        "marketplace-tracking-backend": "none",
        "gh0st-lay3r":                  "none",
    },
    ToolCategory.REPORT_WRITE.value: {
        "intake-agent-v2":              "none",
        "ai-security-framework":        "write",
        "ttx-operator-shell":           "none",
        "marketplace-tracking-backend": "read",
        "gh0st-lay3r":                  "none",
    },
    ToolCategory.POLICY_GATE.value: {
        "intake-agent-v2":              "none",
        "ai-security-framework":        "write",  # ComplianceGovernanceAgent only
        "ttx-operator-shell":           "read",
        "marketplace-tracking-backend": "none",
        "gh0st-lay3r":                  "none",
    },
    ToolCategory.SIMULATION_EXEC.value: {
        "intake-agent-v2":              "none",
        "ai-security-framework":        "write",  # RedTeamAdversaryAgent, sandboxed
        "ttx-operator-shell":           "read",
        "marketplace-tracking-backend": "none",
        "gh0st-lay3r":                  "none",
    },
    ToolCategory.ALERT_DISPATCH.value: {
        "intake-agent-v2":              "none",
        "ai-security-framework":        "write",  # ComplianceGovernanceAgent only
        "ttx-operator-shell":           "write",  # human-approved dispatch
        "marketplace-tracking-backend": "none",
        "gh0st-lay3r":                  "none",
    },
    # safe_telemetry_log — Aurelius writes audit-safe telemetry events and invokes
    # validate_prompt_agent_linkage() as a governance health-check tool.
    # marketplace-tracking-backend reads for telemetry aggregation only.
    ToolCategory.SAFE_TELEMETRY_LOG.value: {
        "intake-agent-v2":              "none",
        "ai-security-framework":        "write",  # AureliusAgent: safeTelemetryLog + linkage check
        "ttx-operator-shell":           "none",
        "marketplace-tracking-backend": "read",
        "gh0st-lay3r":                  "none",
    },
}


def validate_agent_namespace_access(
    agent_name: str,
    namespace: str,
    access_type: str = "read",
) -> bool:
    """
    Return True if agent_name is permitted to access namespace at access_type level.

    Unknown namespaces are denied by default (fail-closed).
    """
    ns = MEMORY_NAMESPACE_MAP.get(namespace)
    if ns is None:
        return False
    if access_type == "write":
        return agent_name in ns.get("write_agents", [])
    return agent_name in ns.get("read_agents", [])


def validate_cross_repo_tool_access(tool: ToolCategory, repo: str) -> str:
    """Return the access level repo has for tool. Defaults to 'none'."""
    return CROSS_REPO_PERMISSIONS.get(tool.value, {}).get(repo, "none")


@dataclass
class SecurityRunContext:
    """
    Cross-repo correlation carrier for a single pipeline run.
    Serialised as the X-Security-Run-ID HTTP header between services.
    Not used for audit hardening (HMAC/sealing) — that belongs to a later branch.
    """
    pipeline_run_id: str
    trust_floor: TrustLevel = TrustLevel.LOW
    initiated_by_repo: str = "ai-security-framework"

    def as_header_value(self) -> str:
        """Encode as a URL-safe base64 token for the X-Security-Run-ID header."""
        import base64
        import json
        payload = {
            "run_id": self.pipeline_run_id,
            "trust_floor": self.trust_floor.name,
            "repo": self.initiated_by_repo,
        }
        return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()

    @classmethod
    def from_header_value(cls, header: str) -> "SecurityRunContext":
        """Decode an X-Security-Run-ID header value back into a context object."""
        import base64
        import json
        payload = json.loads(base64.urlsafe_b64decode(header.encode()))
        return cls(
            pipeline_run_id=payload["run_id"],
            trust_floor=TrustLevel[payload["trust_floor"]],
            initiated_by_repo=payload["repo"],
        )