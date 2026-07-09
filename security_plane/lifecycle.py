"""
security_plane/lifecycle.py
----------------------------
§02 — Security Lifecycle Model (Stages 1–3 implemented; 4–9 defined)

Re-exports SecurityLifecycleStage and LIFECYCLE_STAGE_OWNERS from
pipeline_scaffold.py as the single authoritative source, and adds the
Stage 1–3 runner used when this repo acts as the orchestration entry point
rather than intake-agent-v2.

Stage ownership:
  01 INTAKE        intake-agent-v2              (external; contract defined here)
  02 GROUNDING     ai-security-framework
  03 ANALYSIS      ai-security-framework
  04 EVALUATION    ai-security-framework
  05 THREAT_MODEL  ai-security-framework        (conditional)
  06 RED_TEAM      ai-security-framework + ttx-operator-shell
  07 COMPLIANCE    ai-security-framework → gh0st-lay3r
  08 AUDIT         marketplace-tracking-backend  (later branch)
  09 HQ_PROPAGATE  gh0st-lay3r                  (later branch)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from pipeline_scaffold import (
    LIFECYCLE_STAGE_OWNERS,
    AuditLogger,
    PipelineInput,
    PipelineResult,
    PipelineStatus,
    RAGGroundingPipeline,
    SecurityLifecycleStage,
    _ground_input,
    _sanitize_input,
    invoke_security_analyst,
    EvaluationRubric,
    configure_logging,
)

__all__ = [
    "SecurityLifecycleStage",
    "LIFECYCLE_STAGE_OWNERS",
    "StageResult",
    "run_stages_1_to_3",
    "stage_owner",
    # Aurelius — §04 reactivation
    "AURELIUS_LIFECYCLE_STAGE",
    "AURELIUS_LIFECYCLE_OWNER",
]

# ── Aurelius lifecycle binding ────────────────────────────────────────────────
# AureliusAgent is cleared at ANALYSIS_READY (03:ANALYSIS_READY) and transitions
# to ANALYSIS (03:ANALYSIS) when run_stages_1_to_3() is invoked with its input.
# TM escalation is disabled for standard Aurelius inputs; force_threat_modeling
# must be set explicitly by the caller or the intake TM classifier.
AURELIUS_LIFECYCLE_STAGE: SecurityLifecycleStage = SecurityLifecycleStage.ANALYSIS_READY
AURELIUS_LIFECYCLE_OWNER: str = LIFECYCLE_STAGE_OWNERS[SecurityLifecycleStage.ANALYSIS_READY]


@dataclass
class StageResult:
    """
    Typed result from a partial lifecycle run (stages 1–3).
    Used when the caller wants stage-level control rather than the full pipeline.
    """
    stage_reached: SecurityLifecycleStage
    pipeline_input: PipelineInput          # Sanitized + classified input (Stage 1 out)
    rag_context: dict[str, Any]            # RAG grounding context (Stage 2 out)
    analyst_output: Any                    # AgentOutput from Stage 3
    analyst_eval: dict[str, Any]           # EvaluationRubric scores for analyst output
    audit_entries: list[dict[str, Any]]
    status: PipelineStatus
    error: Optional[dict[str, Any]] = None


def stage_owner(stage: SecurityLifecycleStage) -> str:
    """Return the repo responsible for executing the given lifecycle stage."""
    return LIFECYCLE_STAGE_OWNERS[stage]


def run_stages_1_to_3(
    raw_input: dict[str, Any],
    input_type: str,
    source_system: str,
    llm_client: Any,
    rag_pipeline: Optional[RAGGroundingPipeline] = None,
    intake_tm_classifier_fn: Optional[Callable[[dict[str, Any], str], bool]] = None,
    audit_sink: str = "stdout",
) -> StageResult:
    """
    Execute the first three lifecycle stages in isolation.

    Stage 1: Input Sanitization   [INTAKE]
    Stage 2: RAG Grounding        [GROUNDING]
    Stage 3: Security Analyst     [ANALYSIS]

    Returns a StageResult so the caller can inspect stage outputs before
    deciding whether to continue to Stage 4 (Threat Modeling) or 6 (Red Team).

    This entry point is used when intake-agent-v2 delegates orchestration back
    to this repo, or for unit-testing stages in isolation.
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

    audit.log_event(
        "STAGE_RUN_START",
        run_id,
        None,
        "lifecycle",
        {"stages": "1-3", "source_system": source_system},
    )

    try:
        # ── Stage 1: INTAKE ───────────────────────────────────────────────
        pipeline_input = _sanitize_input(pipeline_input, audit, run_id)

        if intake_tm_classifier_fn is not None:
            pipeline_input.force_threat_modeling = intake_tm_classifier_fn(
                pipeline_input.raw_input,
                pipeline_input.input_type,
            )
            if pipeline_input.force_threat_modeling:
                audit.log_event(
                    "TM_HOOK_ACTIVATED",
                    run_id,
                    None,
                    "intake",
                    {"classifier": intake_tm_classifier_fn.__name__},
                )

        # ── Stage 2: GROUNDING ────────────────────────────────────────────
        rag_context = _ground_input(pipeline_input, rag_pipeline, audit, run_id)

        # ── Stage 3: ANALYSIS ─────────────────────────────────────────────
        analyst_output = invoke_security_analyst(pipeline_input, rag_context, llm_client)
        analyst_eval = rubric.evaluate(analyst_output)
        audit.log_event(
            "AGENT_OUTPUT",
            run_id,
            "SecurityAnalystAgent",
            "analyst",
            {"eval": analyst_eval},
        )

        status = (
            PipelineStatus.RUNNING
            if analyst_eval["passed"]
            else PipelineStatus.FAILED
        )

        return StageResult(
            stage_reached=SecurityLifecycleStage.ANALYSIS,
            pipeline_input=pipeline_input,
            rag_context=rag_context,
            analyst_output=analyst_output,
            analyst_eval=analyst_eval,
            audit_entries=audit.get_full_audit_trail(),
            status=status,
            error=None if analyst_eval["passed"] else {
                "reason": "Security Analyst output failed evaluation rubric.",
                "scores": analyst_eval,
            },
        )

    except Exception as exc:
        return StageResult(
            stage_reached=SecurityLifecycleStage.INTAKE,
            pipeline_input=pipeline_input,
            rag_context={},
            analyst_output=None,
            analyst_eval={},
            audit_entries=audit.get_full_audit_trail(),
            status=PipelineStatus.FAILED,
            error={"exception_type": type(exc).__name__, "message": str(exc)},
        )
