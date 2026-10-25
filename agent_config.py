
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
# Agent Registry
# ---------------------------------------------------------------------------

AGENT_REGISTRY: dict[str, AgentConfig] = {
    "security_analyst":     SECURITY_ANALYST_AGENT,
    "threat_modeling":      THREAT_MODELING_AGENT,
    "red_team_adversary":   RED_TEAM_ADVERSARY_AGENT,
    "compliance_governance": COMPLIANCE_GOVERNANCE_AGENT,
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
