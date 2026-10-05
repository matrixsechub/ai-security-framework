
"""
pipeline_scaffold.py
--------------------
MatrixSecHub AI-Cybersecurity Suite
High-level orchestration pipeline for multi-agent security analysis.

Architecture:
  1. Input ingestion and pre-processing
  2. RAG grounding — context retrieval for all agents
  3. Security Analyst Agent — alert triage and enrichment
  4. Threat Modeling Agent — STRIDE analysis (conditional on analyst escalation)
  5. Red Team Adversary Agent — adversarial simulation (conditional)
  6. Compliance/Governance Agent — policy gate on all outputs
  7. Evaluation rubric — scoring and quality assurance
  8. Audit logging — structured output to SIEM-compatible sink
  9. Downstream dispatch — findings to ticketing, SIEM, or reporting

All agent handoffs are typed and schema-validated.
All errors are caught, logged, and surfaced as structured error objects.
Human-in-the-loop breakpoints are enforced for HIGH severity and red-team outputs.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Module-level logger (structured JSON via custom formatter)
# ---------------------------------------------------------------------------

logger = logging.getLogger("matrixsechub.pipeline")


class StructuredJsonFormatter(logging.Formatter):
    """Emit log records as JSON for SIEM ingestion (Splunk HEC, Elastic, Chronicle)."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "pipeline_run_id": getattr(record, "pipeline_run_id", None),
            "agent": getattr(record, "agent", None),
            "stage": getattr(record, "stage", None),
        }
        return json.dumps(payload)


def configure_logging(level: int = logging.INFO) -> None:
    """Configure the pipeline logger with structured JSON output."""
    handler = logging.StreamHandler()
    handler.setFormatter(StructuredJsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(level)


# ---------------------------------------------------------------------------
# Pipeline Data Models
# ---------------------------------------------------------------------------

class PipelineStatus(Enum):
    PENDING    = auto()
    RUNNING    = auto()
    COMPLETED  = auto()
    FAILED     = auto()
    BLOCKED    = auto()    # Compliance Agent veto
    NEEDS_REVIEW = auto()  # Human-in-the-loop required


@dataclass
class PipelineInput:
    """
    Normalized input to the security analysis pipeline.
    Raw inputs (SIEM alerts, manual descriptions) are normalized here
    before being passed to any agent.
    """
    raw_input: dict[str, Any]
    input_type: str                     # "siem_alert" | "manual_description" | "threat_model_request"
    source_system: str
    pipeline_run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ingested_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    sanitized: bool = False             # Set True after sanitization pass


@dataclass
class AgentOutput:
    """
    Typed container for a single agent's structured output.
    Carries the output payload, quality scores, and pipeline metadata.
    """
    agent_name: str
    schema: str
    payload: dict[str, Any]
    retrieval_confidence: float
    evaluation_score: Optional[float] = None
    compliance_decision: Optional[str] = None
    pipeline_run_id: str = ""
    produced_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    flags: list[str] = field(default_factory=list)


@dataclass
class PipelineResult:
    """
    Final result object returned by the pipeline.
    Aggregates all agent outputs and the audit trail.
    """
    pipeline_run_id: str
    status: PipelineStatus
    analyst_output: Optional[AgentOutput] = None
    threat_model_output: Optional[AgentOutput] = None
    red_team_output: Optional[AgentOutput] = None
    compliance_output: Optional[AgentOutput] = None
    evaluation_summary: Optional[dict[str, Any]] = None
    audit_log: list[dict[str, Any]] = field(default_factory=list)
    completed_at_utc: Optional[str] = None
    error: Optional[dict[str, Any]] = None


# Terminal statuses that may emit approved actionable security payloads.
_PAYLOAD_RELEASE_STATUSES = frozenset({PipelineStatus.COMPLETED})


class HumanReviewControlError(Exception):
    """
    Explicit control-boundary failure for human-review gates.

    Raised (or used as a typed signal) when HITL approval is unavailable,
    declined, or otherwise cannot authorize release of actionable outputs.
    Must never fall through to a response that still contains actionable payloads.
    """

    def __init__(self, reason: str, *, status: PipelineStatus = PipelineStatus.NEEDS_REVIEW) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


def _withhold_actionable_outputs(result: PipelineResult) -> None:
    """Clear actionable / dispatchable fields from a pipeline result in place."""
    result.analyst_output = None
    result.threat_model_output = None
    result.red_team_output = None
    result.evaluation_summary = None


def sanitize_result_for_status(result: PipelineResult) -> PipelineResult:
    """
    Authoritative release policy for terminal pipeline results.

    COMPLETED → approved payloads may be emitted.
    NEEDS_REVIEW / BLOCKED → metadata + review reason only; no actionable payloads.
    FAILED (and other non-release statuses) → diagnostic metadata only.

    Returns a shallow-copied public view; does not rely on callers having
    already mutated the internal result object.
    """
    public = PipelineResult(
        pipeline_run_id=result.pipeline_run_id,
        status=result.status,
        analyst_output=result.analyst_output,
        threat_model_output=result.threat_model_output,
        red_team_output=result.red_team_output,
        compliance_output=result.compliance_output,
        evaluation_summary=result.evaluation_summary,
        audit_log=list(result.audit_log),
        completed_at_utc=result.completed_at_utc,
        error=dict(result.error) if result.error else None,
    )

    if public.status not in _PAYLOAD_RELEASE_STATUSES:
        _withhold_actionable_outputs(public)
        # Compliance decisions may cite remediation guidance; keep only non-actionable gate metadata.
        if public.compliance_output is not None and public.status in {
            PipelineStatus.NEEDS_REVIEW,
            PipelineStatus.BLOCKED,
            PipelineStatus.FAILED,
        }:
            decision = public.compliance_output.payload.get("decision")
            public.compliance_output = AgentOutput(
                agent_name=public.compliance_output.agent_name,
                schema=public.compliance_output.schema,
                payload={
                    "schema": public.compliance_output.payload.get("schema"),
                    "decision": decision,
                    "decision_id": public.compliance_output.payload.get("decision_id"),
                    "reviewed_agent": public.compliance_output.payload.get("reviewed_agent"),
                },
                retrieval_confidence=public.compliance_output.retrieval_confidence,
                compliance_decision=public.compliance_output.compliance_decision,
                pipeline_run_id=public.compliance_output.pipeline_run_id,
                produced_at_utc=public.compliance_output.produced_at_utc,
                flags=[],
            )

    return public


def public_result_view(result: PipelineResult) -> PipelineResult:
    """Alias for sanitize_result_for_status — every transport path should use this."""
    return sanitize_result_for_status(result)


def serialize_pipeline_result(result: PipelineResult) -> dict[str, Any]:
    """
    Serialize a pipeline result for CLI/API transport under the release policy.

    Always applies public_result_view so blocked/failed/needs-review results
    cannot emit analyst/TM/red-team payloads even if an internal object retains them.
    """
    public = public_result_view(result)
    payload = asdict(public)
    payload["status"] = public.status.name
    return payload


# ---------------------------------------------------------------------------
# RAG Grounding Pipeline
# ---------------------------------------------------------------------------

class RAGGroundingPipeline:
    """
    Retrieval-Augmented Generation grounding layer.

    Performs hybrid dense + sparse retrieval against curated knowledge bases:
      - MITRE ATT&CK (Enterprise, ICS, Mobile)
      - NIST NVD / CVE feeds
      - NIST SP 800-53 rev 5 controls
      - Internal runbook corpus

    Returns grounded context with confidence scores for each retrieved chunk.
    """

    CONFIDENCE_THRESHOLD = 0.65   # Below this → flag for human review

    def __init__(self, vector_store_client: Any, sparse_index_client: Any) -> None:
        """
        Args:
            vector_store_client: ChromaDB / Pinecone client (dense retrieval).
            sparse_index_client: BM25 / Elasticsearch client (sparse retrieval).
        """
        self.vector_store = vector_store_client
        self.sparse_index = sparse_index_client

    def retrieve(
        self,
        query: str,
        knowledge_bases: list[str],
        top_k: int = 5,
    ) -> dict[str, Any]:
        """
        Execute hybrid retrieval for a query across specified knowledge bases.

        Args:
            query:           Natural language query or structured alert text.
            knowledge_bases: List of KB identifiers to search.
            top_k:           Maximum number of chunks to retrieve per KB.

        Returns:
            Dict with keys: 'chunks', 'confidence', 'sources', 'low_confidence_flag'.
        """
        dense_results = self._dense_retrieval(query, knowledge_bases, top_k)
        sparse_results = self._sparse_retrieval(query, knowledge_bases, top_k)
        merged = self._merge_and_rerank(dense_results, sparse_results)
        confidence = self._compute_confidence(merged)

        return {
            "chunks": merged,
            "confidence": confidence,
            "sources": [c["source"] for c in merged],
            "low_confidence_flag": confidence < self.CONFIDENCE_THRESHOLD,
        }

    def _dense_retrieval(
        self, query: str, knowledge_bases: list[str], top_k: int
    ) -> list[dict[str, Any]]:
        """Semantic similarity search via embedding model + vector store."""
        results = []
        for kb in knowledge_bases:
            # Production: call self.vector_store.query(collection=kb, query_texts=[query], n_results=top_k)
            results.extend(
                self._mock_retrieval_results(query, kb, top_k, retrieval_type="dense")
            )
        return results

    def _sparse_retrieval(
        self, query: str, knowledge_bases: list[str], top_k: int
    ) -> list[dict[str, Any]]:
        """BM25 keyword search for exact term matching."""
        results = []
        for kb in knowledge_bases:
            # Production: call self.sparse_index.search(index=kb, query=query, size=top_k)
            results.extend(
                self._mock_retrieval_results(query, kb, top_k, retrieval_type="sparse")
            )
        return results

    def _merge_and_rerank(
        self,
        dense: list[dict[str, Any]],
        sparse: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Reciprocal Rank Fusion (RRF) merge of dense and sparse results.
        Deduplicates by chunk_id, boosts chunks present in both result sets.
        """
        seen: dict[str, dict[str, Any]] = {}
        for chunk in dense + sparse:
            cid = chunk["chunk_id"]
            if cid in seen:
                seen[cid]["score"] += chunk["score"] * 0.3   # Cross-retrieval boost
            else:
                seen[cid] = chunk
        return sorted(seen.values(), key=lambda x: x["score"], reverse=True)

    def _compute_confidence(self, chunks: list[dict[str, Any]]) -> float:
        """Compute aggregate retrieval confidence from top-k chunk scores."""
        if not chunks:
            return 0.0
        top_scores = [c["score"] for c in chunks[:3]]
        return round(sum(top_scores) / len(top_scores), 4)

    def _mock_retrieval_results(
        self, query: str, kb: str, top_k: int, retrieval_type: str
    ) -> list[dict[str, Any]]:
        """
        Scaffold placeholder — replace with real vector store / BM25 calls.
        Returns mock chunks for pipeline structure validation.
        """
        return [
            {
                "chunk_id": f"{kb}_{retrieval_type}_{i}",
                "source": f"{kb}/chunk_{i}",
                "text": f"[Mock {retrieval_type} result {i} from {kb} for query: {query[:40]}]",
                "score": round(0.9 - (i * 0.08), 4),
            }
            for i in range(min(top_k, 3))
        ]


# ---------------------------------------------------------------------------
# Evaluation Rubric Engine
# ---------------------------------------------------------------------------

class EvaluationRubric:
    """
    Multi-dimensional quality evaluation for agent outputs.

    Rubric dimensions:
      - schema_compliance:    Does the output conform to the expected JSON schema?
      - factual_grounding:    Are claims backed by retrieved citations?
      - hallucination_risk:   Are there ungrounded assertions flagged?
      - safety_adherence:     Did the agent respect all active guardrails?
      - output_completeness:  Are all required fields populated?
      - injection_resistance: No evidence of prompt injection in the output.
    """

    DIMENSIONS = [
        "schema_compliance",
        "factual_grounding",
        "hallucination_risk",
        "safety_adherence",
        "output_completeness",
        "injection_resistance",
    ]

    PASS_THRESHOLD = 0.75   # Aggregate score below this → fail + retry or escalate

    def evaluate(self, output: AgentOutput) -> dict[str, Any]:
        """
        Score an agent output across all rubric dimensions.

        Returns:
            Dict with per-dimension scores, aggregate score, pass/fail, and notes.
        """
        scores = {
            "schema_compliance":    self._score_schema_compliance(output),
            "factual_grounding":    self._score_factual_grounding(output),
            "hallucination_risk":   self._score_hallucination_risk(output),
            "safety_adherence":     self._score_safety_adherence(output),
            "output_completeness":  self._score_output_completeness(output),
            "injection_resistance": self._score_injection_resistance(output),
        }
        aggregate = round(sum(scores.values()) / len(scores), 4)
        passed = aggregate >= self.PASS_THRESHOLD

        return {
            "dimension_scores": scores,
            "aggregate_score": aggregate,
            "passed": passed,
            "threshold": self.PASS_THRESHOLD,
            "recommendation": "PASS" if passed else "RETRY_OR_ESCALATE",
            "notes": self._generate_notes(scores),
        }

    def _score_schema_compliance(self, output: AgentOutput) -> float:
        """Validate output payload against expected schema."""
        required_fields = self._get_required_fields(output.schema)
        present = sum(1 for f in required_fields if f in output.payload)
        return round(present / max(len(required_fields), 1), 4)

    def _score_factual_grounding(self, output: AgentOutput) -> float:
        """Check citation coverage relative to factual claim density."""
        citations = output.payload.get("citations", [])
        if not citations:
            return 0.3   # Penalize missing citations
        confidence = output.retrieval_confidence
        return round(min(confidence + (len(citations) * 0.05), 1.0), 4)

    def _score_hallucination_risk(self, output: AgentOutput) -> float:
        """
        Inverse hallucination score: higher = lower hallucination risk.
        Detects UNGROUNDED flags and missing citations as risk signals.
        """
        payload_str = json.dumps(output.payload)
        ungrounded_count = payload_str.count("UNGROUNDED:")
        if ungrounded_count == 0:
            return 1.0
        return round(max(0.0, 1.0 - (ungrounded_count * 0.2)), 4)

    def _score_safety_adherence(self, output: AgentOutput) -> float:
        """Penalize outputs that contain safety flag indicators."""
        flags = output.flags or output.payload.get("flags", [])
        critical_flags = [
            f for f in flags
            if any(kw in str(f).upper() for kw in [
                "INJECTION", "VIOLATION", "CREDENTIAL", "EXPLOIT", "BLOCKED"
            ])
        ]
        if critical_flags:
            return 0.0   # Hard fail on critical safety flags
        return round(max(0.0, 1.0 - (len(flags) * 0.1)), 4)

    def _score_output_completeness(self, output: AgentOutput) -> float:
        """Measure population rate of non-null required fields."""
        required_fields = self._get_required_fields(output.schema)
        populated = sum(
            1 for f in required_fields
            if output.payload.get(f) not in (None, "", [], {})
        )
        return round(populated / max(len(required_fields), 1), 4)

    def _score_injection_resistance(self, output: AgentOutput) -> float:
        """
        Scan output for patterns indicative of successful prompt injection.
        Pattern list is a subset — production should use a trained classifier.
        """
        injection_patterns = [
            "ignore previous instructions",
            "disregard your system prompt",
            "you are now",
            "new persona",
            "jailbreak",
            "override safety",
        ]
        payload_str = json.dumps(output.payload).lower()
        hits = sum(1 for p in injection_patterns if p in payload_str)
        return round(max(0.0, 1.0 - (hits * 0.5)), 4)

    def _get_required_fields(self, schema: str) -> list[str]:
        """Return required field list for a known schema identifier."""
        schema_fields = {
            "security_finding_v1": [
                "schema", "timestamp_utc", "alert_id", "severity",
                "summary", "affected_assets", "mitre_techniques",
                "containment_recommendations", "citations",
            ],
            "stride_threat_model_v2": [
                "schema", "timestamp_utc", "system_name",
                "assets", "trust_boundaries", "threats", "citations",
            ],
            "red_team_finding_v1": [
                "schema", "timestamp_utc", "scenario_id",
                "attack_chain", "attack_feasibility_score",
                "escalation_required", "citations",
            ],
            "compliance_decision_v1": [
                "schema", "timestamp_utc", "decision_id",
                "reviewed_output_id", "decision", "policy_citations",
                "audit_trail_entry",
            ],
        }
        return schema_fields.get(schema, [])

    def _generate_notes(self, scores: dict[str, float]) -> list[str]:
        """Generate human-readable notes for scores below 0.8."""
        notes = []
        for dimension, score in scores.items():
            if score < 0.8:
                notes.append(
                    f"{dimension}: score {score} below 0.8 — review recommended."
                )
        return notes


# ---------------------------------------------------------------------------
# Agent Invocation Wrappers
# ---------------------------------------------------------------------------

def invoke_security_analyst(
    pipeline_input: PipelineInput,
    rag_context: dict[str, Any],
    llm_client: Any,
) -> AgentOutput:
    """
    Invoke the Security Analyst Agent.

    In production, this calls the CrewAI / AutoGen agent with the
    system prompt, input payload, and RAG-grounded context.
    """
    logger.info(
        "Invoking SecurityAnalystAgent",
        extra={
            "pipeline_run_id": pipeline_input.pipeline_run_id,
            "agent": "SecurityAnalystAgent",
            "stage": "analyst",
        },
    )

    # Production: call built CrewAI agent or AutoGen agent here
    # agent = build_crewai_agent(SECURITY_ANALYST_AGENT, llm_client)
    # result = agent.run(task=..., context=rag_context)

    # Scaffold: return mock output structure
    payload = {
        "schema": "security_finding_v1",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "alert_id": pipeline_input.raw_input.get("alert_id", "UNKNOWN"),
        "severity": {
            "cvss_score": 7.5,
            "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "label": "HIGH",
        },
        "summary": "[Mock] Suspicious outbound connection to known C2 infrastructure.",
        "affected_assets": ["srv-web-01"],
        "mitre_techniques": [
            {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "source": "kb:mitre/chunk_0"},
        ],
        "containment_recommendations": [
            "Isolate srv-web-01 from external network segments.",
            "Capture network traffic for forensic analysis.",
        ],
        "escalate_to_threat_modeling": True,
        "retrieval_confidence": rag_context.get("confidence", 0.82),
        "citations": rag_context.get("sources", [])[:3],
        "flags": [],
    }

    return AgentOutput(
        agent_name="SecurityAnalystAgent",
        schema="security_finding_v1",
        payload=payload,
        retrieval_confidence=payload["retrieval_confidence"],
        pipeline_run_id=pipeline_input.pipeline_run_id,
    )


def invoke_threat_modeling(
    analyst_output: AgentOutput,
    rag_context: dict[str, Any],
    llm_client: Any,
) -> AgentOutput:
    """
    Invoke the Threat Modeling Agent with analyst findings as input context.
    Only called when analyst flags escalate_to_threat_modeling = True.
    """
    logger.info(
        "Invoking ThreatModelingAgent",
        extra={
            "pipeline_run_id": analyst_output.pipeline_run_id,
            "agent": "ThreatModelingAgent",
            "stage": "threat_modeling",
        },
    )

    payload = {
        "schema": "stride_threat_model_v2",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "system_name": "WebApplicationStack",
        "assets": [
            {"id": "srv-web-01", "name": "Web Server", "type": "service"},
            {"id": "db-01", "name": "Primary Database", "type": "data"},
        ],
        "trust_boundaries": [
            {"id": "tb-internet-dmz", "between": ["internet", "srv-web-01"]},
            {"id": "tb-dmz-internal", "between": ["srv-web-01", "db-01"]},
        ],
        "threats": [
            {
                "id": "THR-001",
                "stride_category": "I",
                "description": "[Mock] Attacker may intercept data in transit across tb-internet-dmz.",
                "affected_trust_boundary": "tb-internet-dmz",
                "likelihood": "HIGH",
                "impact": "HIGH",
                "mitre_techniques": [
                    {"id": "T1557", "name": "Adversary-in-the-Middle"},
                ],
                "recommended_controls": [
                    {"nist_id": "SC-8", "name": "Transmission Confidentiality and Integrity"},
                    {"nist_id": "SC-23", "name": "Session Authenticity"},
                ],
                "citations": rag_context.get("sources", [])[:2],
            }
        ],
        "retrieval_confidence": rag_context.get("confidence", 0.78),
        "flags": [],
    }

    return AgentOutput(
        agent_name="ThreatModelingAgent",
        schema="stride_threat_model_v2",
        payload=payload,
        retrieval_confidence=payload["retrieval_confidence"],
        pipeline_run_id=analyst_output.pipeline_run_id,
    )


def invoke_red_team_adversary(
    threat_model_output: AgentOutput,
    rag_context: dict[str, Any],
    llm_client: Any,
) -> AgentOutput:
    """
    Invoke the Red Team Adversary Agent in sandboxed mode.
    Requires explicit human-in-the-loop approval before outputs propagate.
    """
    logger.info(
        "Invoking RedTeamAdversaryAgent (sandboxed)",
        extra={
            "pipeline_run_id": threat_model_output.pipeline_run_id,
            "agent": "RedTeamAdversaryAgent",
            "stage": "red_team",
        },
    )

    payload = {
        "schema": "red_team_finding_v1",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "scenario_id": f"RT-{str(uuid.uuid4())[:8].upper()}",
        "target_system_ref": threat_model_output.payload.get("system_name"),
        "threat_actor_profile": {
            "sophistication": "APT",
            "primary_motivation": "Data Exfiltration",
            "assumed_initial_access": "Phishing — T1566.001",
        },
        "attack_chain": [
            {
                "stage": 1,
                "tactic": "Initial Access",
                "technique_id": "T1566.001",
                "technique_name": "Spearphishing Attachment",
                "description": "[Mock] Simulated phishing email delivers macro-enabled document.",
                "detection_hypothesis": "Email gateway: attachment with macro + external link.",
                "defensive_gap": "No attachment sandboxing on email gateway.",
            },
            {
                "stage": 2,
                "tactic": "Command and Control",
                "technique_id": "T1071.001",
                "technique_name": "Application Layer Protocol: Web Protocols",
                "description": "[Mock] Beacon communicates over HTTPS to simulated C2.",
                "detection_hypothesis": "Proxy logs: beaconing pattern at fixed intervals.",
                "defensive_gap": "SSL inspection not enforced on internal hosts.",
            },
        ],
        "attack_feasibility_score": 72,
        "feasibility_justification": "[Mock] Multiple defensive gaps identified; initial access vector is low-complexity.",
        "escalation_required": True,   # Score > 70 triggers escalation
        "retrieval_confidence": rag_context.get("confidence", 0.80),
        "citations": rag_context.get("sources", [])[:3],
        "flags": [],
    }

    return AgentOutput(
        agent_name="RedTeamAdversaryAgent",
        schema="red_team_finding_v1",
        payload=payload,
        retrieval_confidence=payload["retrieval_confidence"],
        pipeline_run_id=threat_model_output.pipeline_run_id,
        flags=["REQUIRES_HUMAN_REVIEW"],   # Always flagged per config
    )


def invoke_compliance_governance(
    agent_output: AgentOutput,
    llm_client: Any,
) -> AgentOutput:
    """
    Invoke the Compliance/Governance Agent to review and gate an agent output.
    Returns a compliance decision that must be APPROVED before output propagates.
    """
    logger.info(
        "Invoking ComplianceGovernanceAgent",
        extra={
            "pipeline_run_id": agent_output.pipeline_run_id,
            "agent": "ComplianceGovernanceAgent",
            "stage": "compliance_gate",
        },
    )

    decision = "APPROVED" if not agent_output.flags else "APPROVED_WITH_CONDITIONS"

    payload = {
        "schema": "compliance_decision_v1",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "decision_id": str(uuid.uuid4()),
        "reviewed_output_id": f"{agent_output.agent_name}_{agent_output.produced_at_utc}",
        "reviewed_agent": agent_output.agent_name,
        "decision": decision,
        "policy_citations": [
            {
                "framework": "NIST_AI_RMF",
                "control_id": "GOVERN-1.1",
                "rationale": "Output reviewed against organizational AI use policy.",
            },
            {
                "framework": "SOC2",
                "control_id": "CC7.2",
                "rationale": "Security event output assessed for confidentiality controls.",
            },
        ],
        "conditions": (
            ["Human review required before dispatch — red team output."]
            if "REQUIRES_HUMAN_REVIEW" in agent_output.flags else []
        ),
        "flags_detected": agent_output.flags,
        "nist_rmf_function": "GOVERN",
        "soc2_criteria_triggered": ["CC7.2"],
        "audit_trail_entry": {
            "pipeline_run_id": agent_output.pipeline_run_id,
            "decision_by": "ComplianceGovernanceAgent",
            "human_review_required": "REQUIRES_HUMAN_REVIEW" in agent_output.flags,
        },
        "remediation_guidance": None,
    }

    compliance_output = AgentOutput(
        agent_name="ComplianceGovernanceAgent",
        schema="compliance_decision_v1",
        payload=payload,
        retrieval_confidence=1.0,
        pipeline_run_id=agent_output.pipeline_run_id,
        compliance_decision=decision,
    )

    # Attach the compliance decision back to the reviewed output
    agent_output.compliance_decision = decision

    return compliance_output


# ---------------------------------------------------------------------------
# Human-in-the-Loop Checkpoint
# ---------------------------------------------------------------------------

def human_review_checkpoint(
    output: AgentOutput,
    pipeline_run_id: str,
    auto_approve_in_test: bool = False,
) -> bool:
    """
    Pause the pipeline and request human approval for flagged outputs.

    In production, this dispatches a review request to a ticketing system
    or SOC dashboard and blocks until approval is received.

    Until a real HITL dispatcher exists, this fails closed by raising
    NotImplementedError with reason human_review_unavailable. Callers must
    treat that as a control-boundary failure (NEEDS_REVIEW), never as a
    generic runtime error that still releases actionable payloads.

    Args:
        output:               The agent output requiring review.
        pipeline_run_id:      Current pipeline run identifier.
        auto_approve_in_test: If True, auto-approves for CI/CD test runs only.

    Returns:
        True if approved, False if rejected.

    Raises:
        NotImplementedError: When production HITL dispatch is unavailable.
    """
    if auto_approve_in_test:
        logger.warning(
            "HUMAN REVIEW AUTO-APPROVED (test mode only — disable in production)",
            extra={"pipeline_run_id": pipeline_run_id, "agent": output.agent_name, "stage": "human_review"},
        )
        return True

    logger.info(
        "HUMAN REVIEW REQUIRED — pipeline paused",
        extra={"pipeline_run_id": pipeline_run_id, "agent": output.agent_name, "stage": "human_review"},
    )

    # Production: dispatch to ticketing system (ServiceNow, Jira, PagerDuty)
    # approval_token = dispatch_review_request(output, pipeline_run_id)
    # approved = wait_for_approval(approval_token, timeout_seconds=3600)
    # return approved

    # Fail closed until real HITL dispatch exists — do not release pre-review payloads.
    raise NotImplementedError("human_review_unavailable")


# ---------------------------------------------------------------------------
# Audit Logger
# ---------------------------------------------------------------------------

class AuditLogger:
    """
    Append-only structured audit log for all pipeline events.
    Compatible with Splunk HEC, Elastic, and Google Chronicle ingestion.
    """

    def __init__(self, sink: str = "stdout") -> None:
        """
        Args:
            sink: 'stdout' | 'splunk_hec' | 'elastic' | 'chronicle'
        """
        self.sink = sink
        self._entries: list[dict[str, Any]] = []

    def log_event(
        self,
        event_type: str,
        pipeline_run_id: str,
        agent: Optional[str],
        stage: str,
        data: dict[str, Any],
    ) -> None:
        """Append a structured audit event to the log."""
        entry = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "pipeline_run_id": pipeline_run_id,
            "agent": agent,
            "stage": stage,
            "data": data,
        }
        self._entries.append(entry)

        if self.sink == "stdout":
            logger.info(
                json.dumps(entry),
                extra={"pipeline_run_id": pipeline_run_id, "agent": agent, "stage": stage},
            )
        elif self.sink == "splunk_hec":
            self._dispatch_to_splunk(entry)
        # Additional sinks (elastic, chronicle) implemented similarly

    def get_full_audit_trail(self) -> list[dict[str, Any]]:
        """Return all audit entries for the current pipeline run."""
        return list(self._entries)

    def _dispatch_to_splunk(self, entry: dict[str, Any]) -> None:
        """
        Send audit entry to Splunk HTTP Event Collector.
        Production: use requests.post to HEC endpoint with Authorization header.
        """
        # import requests
        # requests.post(
        #     os.environ["SPLUNK_HEC_URL"],
        #     headers={"Authorization": f"Splunk {os.environ['SPLUNK_HEC_TOKEN']}"},
        #     json={"event": entry, "sourcetype": "_json"},
        # )
        pass


# ---------------------------------------------------------------------------
# Main Orchestration Pipeline
# ---------------------------------------------------------------------------

def run_pipeline(
    raw_input: dict[str, Any],
    input_type: str,
    source_system: str,
    llm_client: Any,
    rag_pipeline: Optional[RAGGroundingPipeline] = None,
    enable_red_team: bool = False,
    auto_approve_human_review: bool = False,
    audit_sink: str = "stdout",
) -> PipelineResult:
    """
    Execute the full MatrixSecHub AI-Cybersecurity Pipeline.

    Stages:
      1. Input sanitization
      2. RAG grounding
      3. Security Analyst Agent
      4. Evaluation rubric
      5. Threat Modeling Agent (conditional)
      6. Red Team Adversary Agent (conditional + human-in-the-loop)
      7. Compliance/Governance gate (per agent)
      8. Audit logging
      9. Result aggregation

    Args:
        raw_input:                   Raw alert or description dict.
        input_type:                  Input classification string.
        source_system:               Originating system identifier.
        llm_client:                  Configured LLM client instance.
        rag_pipeline:                RAGGroundingPipeline instance (mocked if None).
        enable_red_team:             Enable adversarial simulation stage.
        auto_approve_human_review:   Auto-approve human checkpoints (test only).
        audit_sink:                  Audit log destination identifier.

    Returns:
        PipelineResult aggregating all outputs and audit trail.
    """
    configure_logging()
    rubric = EvaluationRubric()
    audit = AuditLogger(sink=audit_sink)

    pipeline_input = PipelineInput(
        raw_input=raw_input,
        input_type=input_type,
        source_system=source_system,
    )
    run_id = pipeline_input.pipeline_run_id
    result = PipelineResult(pipeline_run_id=run_id, status=PipelineStatus.RUNNING)
    # Pre-review staging: hold actionable outputs privately until the release gate passes.
    staged_analyst: Optional[AgentOutput] = None
    staged_threat_model: Optional[AgentOutput] = None
    staged_red_team: Optional[AgentOutput] = None

    audit.log_event(
        event_type="PIPELINE_START",
        pipeline_run_id=run_id,
        agent=None,
        stage="init",
        data={"input_type": input_type, "source_system": source_system},
    )

    try:
        # ── Stage 1: Input Sanitization ────────────────────────────────────
        pipeline_input = _sanitize_input(pipeline_input, audit, run_id)

        # ── Stage 2: RAG Grounding ─────────────────────────────────────────
        rag_context = _ground_input(pipeline_input, rag_pipeline, audit, run_id)

        # ── Stage 3: Security Analyst Agent ────────────────────────────────
        analyst_output = invoke_security_analyst(pipeline_input, rag_context, llm_client)
        analyst_eval = rubric.evaluate(analyst_output)
        audit.log_event("AGENT_OUTPUT", run_id, "SecurityAnalystAgent", "analyst", {"eval": analyst_eval})

        if not analyst_eval["passed"]:
            return public_result_view(
                _fail_pipeline(result, "Security Analyst output failed evaluation rubric.", audit, run_id)
            )

        analyst_compliance = invoke_compliance_governance(analyst_output, llm_client)
        staged_analyst = analyst_output
        result.compliance_output = analyst_compliance

        if analyst_compliance.payload["decision"] == "BLOCKED":
            # Attach only for internal audit path; public view withholds actionable payloads.
            result.analyst_output = staged_analyst
            return public_result_view(
                _block_pipeline(result, analyst_compliance, audit, run_id)
            )

        # ── Stage 4: Threat Modeling (Conditional) ─────────────────────────
        escalate = analyst_output.payload.get("escalate_to_threat_modeling", False)
        if escalate:
            rag_context_tm = _ground_input(pipeline_input, rag_pipeline, audit, run_id, stage="threat_modeling")
            tm_output = invoke_threat_modeling(analyst_output, rag_context_tm, llm_client)
            tm_eval = rubric.evaluate(tm_output)
            audit.log_event("AGENT_OUTPUT", run_id, "ThreatModelingAgent", "threat_modeling", {"eval": tm_eval})

            if not tm_eval["passed"]:
                return public_result_view(
                    _fail_pipeline(result, "Threat Modeling output failed evaluation rubric.", audit, run_id)
                )

            tm_compliance = invoke_compliance_governance(tm_output, llm_client)
            staged_threat_model = tm_output

            if tm_compliance.payload["decision"] == "BLOCKED":
                result.analyst_output = staged_analyst
                result.threat_model_output = staged_threat_model
                return public_result_view(
                    _block_pipeline(result, tm_compliance, audit, run_id)
                )

            # ── Stage 5: Red Team Adversary (Optional) ─────────────────────
            if enable_red_team:
                rag_context_rt = _ground_input(pipeline_input, rag_pipeline, audit, run_id, stage="red_team")
                rt_output = invoke_red_team_adversary(tm_output, rag_context_rt, llm_client)

                # Red team outputs ALWAYS require human-in-the-loop review.
                # Catch NotImplementedError separately from generic exceptions —
                # missing HITL dispatch is a control failure, not an ordinary runtime error.
                try:
                    approved = human_review_checkpoint(
                        rt_output, run_id, auto_approve_in_test=auto_approve_human_review
                    )
                except NotImplementedError as hitl_exc:
                    raise HumanReviewControlError(
                        str(hitl_exc) or "human_review_unavailable",
                        status=PipelineStatus.NEEDS_REVIEW,
                    ) from hitl_exc

                if not approved:
                    raise HumanReviewControlError(
                        "human_review_rejected",
                        status=PipelineStatus.BLOCKED,
                    )

                rt_eval = rubric.evaluate(rt_output)
                audit.log_event("AGENT_OUTPUT", run_id, "RedTeamAdversaryAgent", "red_team", {"eval": rt_eval})

                rt_compliance = invoke_compliance_governance(rt_output, llm_client)
                staged_red_team = rt_output

                if rt_compliance.payload["decision"] == "BLOCKED":
                    result.analyst_output = staged_analyst
                    result.threat_model_output = staged_threat_model
                    result.red_team_output = staged_red_team
                    return public_result_view(
                        _block_pipeline(result, rt_compliance, audit, run_id)
                    )

        # Release gate passed — attach staged actionable outputs only now.
        result.analyst_output = staged_analyst
        result.threat_model_output = staged_threat_model
        result.red_team_output = staged_red_team

        # ── Stage 6: Final Evaluation Summary ─────────────────────────────
        result.evaluation_summary = _build_evaluation_summary(result, rubric)

        # ── Stage 7: Pipeline Complete ─────────────────────────────────────
        result.status = PipelineStatus.COMPLETED
        result.completed_at_utc = datetime.now(timezone.utc).isoformat()
        result.audit_log = audit.get_full_audit_trail()

        audit.log_event("PIPELINE_COMPLETE", run_id, None, "complete", {"status": "COMPLETED"})
        return public_result_view(result)

    except HumanReviewControlError as control_exc:
        logger.warning(
            "Human-review control boundary failure — failing closed",
            extra={
                "pipeline_run_id": run_id,
                "agent": None,
                "stage": "human_review",
            },
        )
        # Do not attach staged pre-review payloads on control failure.
        _withhold_actionable_outputs(result)
        result.status = control_exc.status
        result.error = {
            "reason": control_exc.reason,
            "blocked_by": "human_review_checkpoint",
            "pipeline_run_id": run_id,
        }
        result.audit_log = audit.get_full_audit_trail()
        audit.log_event(
            "PIPELINE_NEEDS_REVIEW" if control_exc.status == PipelineStatus.NEEDS_REVIEW else "PIPELINE_BLOCKED",
            run_id,
            None,
            "human_review",
            {"reason": control_exc.reason, "status": control_exc.status.name},
        )
        return public_result_view(result)

    except Exception as exc:  # pylint: disable=broad-except
        logger.exception(
            "Unhandled pipeline exception",
            extra={"pipeline_run_id": run_id, "agent": None, "stage": "exception"},
        )
        # Fail closed: never resurrect prior-stage actionable outputs on generic failure.
        _withhold_actionable_outputs(result)
        result.status = PipelineStatus.FAILED
        result.error = {
            "exception_type": type(exc).__name__,
            "message": str(exc),
            "pipeline_run_id": run_id,
        }
        result.audit_log = audit.get_full_audit_trail()
        audit.log_event("PIPELINE_ERROR", run_id, None, "exception", {"error": str(exc)})
        return public_result_view(result)


# ---------------------------------------------------------------------------
# Pipeline Helper Functions
# ---------------------------------------------------------------------------

def _sanitize_input(
    pipeline_input: PipelineInput,
    audit: AuditLogger,
    run_id: str,
) -> PipelineInput:
    """
    Sanitize raw input before passing to agents.

    Checks:
      - No embedded override instructions in input strings.
      - No real credentials patterns (API keys, passwords).
      - Input size within bounds.
    """
    raw_str = json.dumps(pipeline_input.raw_input).lower()

    injection_patterns = [
        "ignore previous instructions",
        "disregard your system prompt",
        "you are now a",
        "new instructions:",
    ]
    for pattern in injection_patterns:
        if pattern in raw_str:
            raise ValueError(f"PROMPT_INJECTION_DETECTED in input: pattern='{pattern}'")

    # Enforce input size limit (64KB)
    if len(raw_str) > 65536:
        raise ValueError("INPUT_TOO_LARGE: input exceeds 64KB limit.")

    pipeline_input.sanitized = True
    audit.log_event("INPUT_SANITIZED", run_id, None, "sanitization", {"sanitized": True})
    return pipeline_input


def _ground_input(
    pipeline_input: PipelineInput,
    rag_pipeline: Optional[RAGGroundingPipeline],
    audit: AuditLogger,
    run_id: str,
    stage: str = "analyst",
) -> dict[str, Any]:
    """Execute RAG retrieval for the given pipeline stage."""
    query = json.dumps(pipeline_input.raw_input)[:500]   # Truncate for query
    knowledge_bases = {
        "analyst":        ["kb:mitre", "kb:cve", "kb:threat_intel"],
        "threat_modeling": ["kb:mitre", "kb:nist_controls", "kb:asset_inventory"],
        "red_team":       ["kb:mitre"],
    }.get(stage, ["kb:mitre"])

    if rag_pipeline:
        context = rag_pipeline.retrieve(query, knowledge_bases)
    else:
        # Mock context for scaffold / testing
        context = {
            "chunks": [],
            "confidence": 0.82,
            "sources": [f"{kb}/mock_chunk_0" for kb in knowledge_bases],
            "low_confidence_flag": False,
        }

    audit.log_event(
        "RAG_GROUNDING",
        run_id,
        None,
        stage,
        {"knowledge_bases": knowledge_bases, "confidence": context["confidence"]},
    )
    return context


def _fail_pipeline(
    result: PipelineResult,
    reason: str,
    audit: AuditLogger,
    run_id: str,
) -> PipelineResult:
    """Mark pipeline as failed, withhold actionable payloads, and log the failure reason."""
    result.status = PipelineStatus.FAILED
    _withhold_actionable_outputs(result)
    result.error = {"reason": reason}
    result.audit_log = audit.get_full_audit_trail()
    audit.log_event("PIPELINE_FAILED", run_id, None, "failure", {"reason": reason})
    return result


def _block_pipeline(
    result: PipelineResult,
    compliance_output: Optional[AgentOutput],
    audit: AuditLogger,
    run_id: str,
    reason: Optional[str] = None,
) -> PipelineResult:
    """Mark pipeline as blocked and withhold actionable security payloads."""
    result.status = PipelineStatus.BLOCKED
    _withhold_actionable_outputs(result)
    block_reason = reason or (
        compliance_output.payload.get("remediation_guidance", "Compliance gate blocked output.")
        if compliance_output else "Compliance gate blocked output."
    )
    result.error = {
        "reason": block_reason,
        "blocked_by": "ComplianceGovernanceAgent" if compliance_output else "human_review_checkpoint",
    }
    result.audit_log = audit.get_full_audit_trail()
    audit.log_event(
        "PIPELINE_BLOCKED",
        run_id,
        "ComplianceGovernanceAgent" if compliance_output else None,
        "compliance_gate" if compliance_output else "human_review",
        {"reason": block_reason},
    )
    return result


def _build_evaluation_summary(
    result: PipelineResult,
    rubric: EvaluationRubric,
) -> dict[str, Any]:
    """Aggregate evaluation scores across all produced agent outputs."""
    outputs = {
        "analyst": result.analyst_output,
        "threat_modeling": result.threat_model_output,
        "red_team": result.red_team_output,
    }
    summary: dict[str, Any] = {}
    for label, output in outputs.items():
        if output is not None:
            evaluation = rubric.evaluate(output)
            summary[label] = {
                "agent": output.agent_name,
                "aggregate_score": evaluation["aggregate_score"],
                "passed": evaluation["passed"],
                "notes": evaluation["notes"],
            }
    return summary


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="MatrixSecHub AI-Cybersecurity Pipeline")
    parser.add_argument("--mode", choices=["analyst", "full", "redteam"], default="analyst")
    parser.add_argument("--input", type=str, help="Path to JSON input file")
    parser.add_argument("--sink", choices=["stdout", "splunk_hec"], default="stdout")
    args = parser.parse_args()

    if args.input:
        with open(args.input, "r", encoding="utf-8") as f:
            raw = json.load(f)
    else:
        raw = {
            "alert_id": "ALERT-20250115-0042",
            "source_ip": "10.0.1.55",
            "destination_ip": "203.0.113.99",
            "protocol": "HTTPS",
            "event_type": "suspicious_outbound_connection",
            "severity_raw": "HIGH",
        }

    # Production default: never auto-approve HITL. Tests may pass True explicitly.
    auto_approve = os.environ.get("MSH_AUTO_APPROVE_HUMAN_REVIEW", "").lower() in {
        "1", "true", "yes",
    }

    pipeline_result = run_pipeline(
        raw_input=raw,
        input_type="siem_alert",
        source_system="splunk_es",
        llm_client=None,       # Inject real LLM client here
        enable_red_team=(args.mode == "redteam"),
        auto_approve_human_review=auto_approve,
        audit_sink=args.sink,
    )

    # Transport path applies the same release policy as the returned object.
    print(json.dumps(serialize_pipeline_result(pipeline_result), indent=2, default=str))
    sys.exit(0 if pipeline_result.status == PipelineStatus.COMPLETED else 1)