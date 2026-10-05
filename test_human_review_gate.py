"""
Regression tests: human-review control boundary must fail closed.

A blocked / unavailable / declined HITL gate must not release analyst,
threat-model, or red-team actionable payloads (e.g. Isolate srv-web-01)
through the returned object or CLI/API serialization.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import pytest

from pipeline_scaffold import (
    AgentOutput,
    PipelineResult,
    PipelineStatus,
    human_review_checkpoint,
    public_result_view,
    run_pipeline,
    sanitize_result_for_status,
    serialize_pipeline_result,
)


SAMPLE_INPUT = {
    "alert_id": "ALERT-20250115-0042",
    "source_ip": "10.0.1.55",
    "destination_ip": "203.0.113.99",
    "protocol": "HTTPS",
    "event_type": "suspicious_outbound_connection",
    "severity_raw": "HIGH",
}


def _run_red_team(**kwargs: Any) -> PipelineResult:
    defaults = {
        "raw_input": SAMPLE_INPUT,
        "input_type": "siem_alert",
        "source_system": "splunk_es",
        "llm_client": None,
        "enable_red_team": True,
        "auto_approve_human_review": False,
        "audit_sink": "stdout",
    }
    defaults.update(kwargs)
    return run_pipeline(**defaults)


def _serialized_text(result: PipelineResult) -> str:
    return json.dumps(serialize_pipeline_result(result), default=str)


def _assert_no_actionable_payloads(result: PipelineResult) -> None:
    assert result.analyst_output is None
    assert result.threat_model_output is None
    assert result.red_team_output is None
    assert result.evaluation_summary is None


def _assert_no_dispatchable_leak(serialized: str) -> None:
    lowered = serialized.lower()
    assert "isolate srv-web-01" not in lowered
    assert "containment_recommendations" not in lowered
    assert "attack_chain" not in lowered
    assert "trust_boundaries" not in lowered
    assert "remediation_guidance" not in lowered
    # Topology / asset dispatch signals from threat model
    assert '"assets"' not in lowered
    assert "red_team_finding" not in lowered


class TestHumanReviewUnavailable:
    def test_stub_review_needs_review_and_clears_outputs(self) -> None:
        result = _run_red_team(auto_approve_human_review=False)

        assert result.status == PipelineStatus.NEEDS_REVIEW
        assert result.error is not None
        assert result.error.get("reason") == "human_review_unavailable"
        _assert_no_actionable_payloads(result)

    def test_cli_json_withholds_containment_and_red_team(self) -> None:
        result = _run_red_team(auto_approve_human_review=False)
        serialized = _serialized_text(result)

        assert result.status == PipelineStatus.NEEDS_REVIEW
        _assert_no_dispatchable_leak(serialized)
        assert "Isolate srv-web-01" not in serialized
        assert '"analyst_output": null' in serialized or '"analyst_output":null' in serialized.replace(" ", "")

    def test_status_ignoring_consumer_cannot_dispatch(self) -> None:
        """Downstream that ignores status still gets no dispatchable action fields."""
        result = _run_red_team(auto_approve_human_review=False)
        public = public_result_view(result)
        payload = serialize_pipeline_result(public)

        for key in ("analyst_output", "threat_model_output", "red_team_output"):
            assert payload.get(key) is None

        # No nested containment even if consumer walks the whole dict
        blob = json.dumps(payload, default=str)
        assert "Isolate srv-web-01" not in blob
        assert "containment_recommendations" not in blob


class TestNegativeHumanDecision:
    def test_rejected_review_blocks_and_clears_outputs(self) -> None:
        with patch(
            "pipeline_scaffold.human_review_checkpoint",
            return_value=False,
        ):
            result = _run_red_team(auto_approve_human_review=False)

        assert result.status == PipelineStatus.BLOCKED
        assert result.error is not None
        assert result.error.get("reason") == "human_review_rejected"
        _assert_no_actionable_payloads(result)
        _assert_no_dispatchable_leak(_serialized_text(result))


class TestGenericPostGateException:
    def test_post_gate_exception_fails_closed(self) -> None:
        import pipeline_scaffold as scaffold

        call_count = {"n": 0}
        real_compliance = scaffold.invoke_compliance_governance

        def compliance_after_hitl(agent_output: AgentOutput, llm_client: Any) -> AgentOutput:
            call_count["n"] += 1
            # analyst + threat model first; third call is post-HITL red-team gate
            if call_count["n"] >= 3:
                raise RuntimeError("post-gate boom")
            return real_compliance(agent_output, llm_client)

        with patch(
            "pipeline_scaffold.human_review_checkpoint",
            return_value=True,
        ), patch(
            "pipeline_scaffold.invoke_compliance_governance",
            side_effect=compliance_after_hitl,
        ):
            result = _run_red_team(auto_approve_human_review=False)

        assert result.status == PipelineStatus.FAILED
        _assert_no_actionable_payloads(result)
        assert "Isolate srv-web-01" not in _serialized_text(result)


class TestApprovedReviewPath:
    def test_approved_review_returns_expected_outputs(self) -> None:
        result = _run_red_team(auto_approve_human_review=True)

        assert result.status == PipelineStatus.COMPLETED
        assert result.analyst_output is not None
        assert result.threat_model_output is not None
        assert result.red_team_output is not None
        assert "Isolate srv-web-01" in json.dumps(result.analyst_output.payload)


class TestSerializationPolicyIndependent:
    def test_sanitize_strips_even_if_internal_object_retains_payloads(self) -> None:
        tainted = PipelineResult(
            pipeline_run_id="test-run",
            status=PipelineStatus.NEEDS_REVIEW,
            analyst_output=AgentOutput(
                agent_name="SecurityAnalystAgent",
                schema="security_finding_v1",
                payload={
                    "containment_recommendations": ["Isolate srv-web-01 from external network segments."],
                    "affected_assets": ["srv-web-01"],
                },
                retrieval_confidence=0.9,
            ),
            threat_model_output=AgentOutput(
                agent_name="ThreatModelingAgent",
                schema="stride_threat_model_v2",
                payload={
                    "assets": [{"id": "srv-web-01"}],
                    "trust_boundaries": [{"id": "tb-1"}],
                },
                retrieval_confidence=0.8,
            ),
            red_team_output=AgentOutput(
                agent_name="RedTeamAdversaryAgent",
                schema="red_team_finding_v1",
                payload={"attack_chain": [{"stage": 1}], "scenario_id": "RT-LEAK"},
                retrieval_confidence=0.8,
            ),
            evaluation_summary={"analyst": {"passed": True}},
            error={"reason": "human_review_unavailable"},
        )

        public = sanitize_result_for_status(tainted)
        assert public.status == PipelineStatus.NEEDS_REVIEW
        _assert_no_actionable_payloads(public)

        # Original internal object may still hold data — policy is on the public view.
        assert tainted.analyst_output is not None
        serialized = _serialized_text(tainted)
        assert "Isolate srv-web-01" not in serialized
        assert "attack_chain" not in serialized
        assert "trust_boundaries" not in serialized

    def test_failed_status_also_withholds_actionable_payloads(self) -> None:
        tainted = PipelineResult(
            pipeline_run_id="fail-run",
            status=PipelineStatus.FAILED,
            analyst_output=AgentOutput(
                agent_name="SecurityAnalystAgent",
                schema="security_finding_v1",
                payload={"containment_recommendations": ["Isolate srv-web-01"]},
                retrieval_confidence=0.9,
            ),
            error={"reason": "boom"},
        )
        public = sanitize_result_for_status(tainted)
        _assert_no_actionable_payloads(public)
        assert "Isolate srv-web-01" not in _serialized_text(tainted)

    def test_completed_status_may_emit_approved_payloads(self) -> None:
        ok = PipelineResult(
            pipeline_run_id="ok-run",
            status=PipelineStatus.COMPLETED,
            analyst_output=AgentOutput(
                agent_name="SecurityAnalystAgent",
                schema="security_finding_v1",
                payload={"containment_recommendations": ["Isolate srv-web-01"]},
                retrieval_confidence=0.9,
            ),
        )
        public = sanitize_result_for_status(ok)
        assert public.analyst_output is not None
        assert "Isolate srv-web-01" in json.dumps(public.analyst_output.payload)


class TestNotImplementedErrorSplit:
    def test_human_review_checkpoint_raises_not_implemented(self) -> None:
        output = AgentOutput(
            agent_name="RedTeamAdversaryAgent",
            schema="red_team_finding_v1",
            payload={},
            retrieval_confidence=0.5,
            flags=["REQUIRES_HUMAN_REVIEW"],
        )
        with pytest.raises(NotImplementedError, match="human_review_unavailable"):
            human_review_checkpoint(output, "run-1", auto_approve_in_test=False)
