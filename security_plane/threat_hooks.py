"""
security_plane/threat_hooks.py
--------------------------------
§04 — Threat Modeling Hooks (repo-local activation points)

Provides the `IntakeTMClassifier` callable contract and a default implementation
that classifies incoming requests as threat model targets based on input_type and
raw_input heuristics.

The classifier is injected into run_pipeline() via intake_tm_classifier_fn.
When it returns True, PipelineInput.force_threat_modeling is set, causing the
Threat Modeling stage (Stage 5) to activate regardless of the Security Analyst's
escalate_to_threat_modeling flag.

Hook registry allows additional classifiers to be registered by name; the
pipeline resolves the active classifier from the registry at startup.
"""

from __future__ import annotations

import re
from typing import Any, Callable

__all__ = [
    "IntakeTMClassifier",
    "classify_threat_model_request",
    "ThreatHookRegistry",
    "DEFAULT_REGISTRY",
]

# Callable type alias: (raw_input, input_type) → bool
IntakeTMClassifier = Callable[[dict[str, Any], str], bool]


# ── Default classifier ────────────────────────────────────────────────────────

# Input types that unconditionally trigger threat modeling, regardless of content.
_TM_INPUT_TYPES: frozenset[str] = frozenset({
    "threat_model_request",
    "architecture_review",
    "dfd_submission",
})

# Keywords in raw_input values that indicate a multi-component system description
# suitable for STRIDE analysis (checked on str-serialised input).
_TM_KEYWORDS: tuple[str, ...] = (
    "data flow",
    "trust boundary",
    "attack surface",
    "threat model",
    "dfd",
    "stride",
    "pasta",
    "asset inventory",
    "system description",
    "architecture diagram",
)

_TM_KEYWORD_RE = re.compile(
    "|".join(re.escape(kw) for kw in _TM_KEYWORDS),
    re.IGNORECASE,
)

# Minimum number of distinct top-level fields in raw_input to suggest a
# multi-component system description rather than a single-event alert.
_MIN_FIELDS_FOR_SYSTEM_DESCRIPTION = 5


def classify_threat_model_request(
    raw_input: dict[str, Any],
    input_type: str,
) -> bool:
    """
    Default intake TM classifier.

    Returns True (force_threat_modeling) when any of the following hold:
      1. input_type is in _TM_INPUT_TYPES.
      2. A TM keyword is found anywhere in the serialised raw_input values.
      3. raw_input has >= _MIN_FIELDS_FOR_SYSTEM_DESCRIPTION fields,
         suggesting a system description rather than a point alert.
    """
    if input_type in _TM_INPUT_TYPES:
        return True

    serialised = " ".join(str(v) for v in raw_input.values())
    if _TM_KEYWORD_RE.search(serialised):
        return True

    if len(raw_input) >= _MIN_FIELDS_FOR_SYSTEM_DESCRIPTION:
        # Heuristic: rich structured input that isn't a simple SIEM alert
        # likely describes a system and warrants STRIDE analysis.
        return True

    return False


# ── Hook registry ─────────────────────────────────────────────────────────────

class ThreatHookRegistry:
    """
    Named registry for intake TM classifier functions.

    Downstream repos (e.g. intake-agent-v2) can register custom classifiers
    by name; the pipeline resolves the active classifier from this registry.

    Usage:
        registry = ThreatHookRegistry()
        registry.register("my_classifier", my_classifier_fn)
        classifier = registry.resolve("my_classifier")
        pipeline_result = run_pipeline(..., intake_tm_classifier_fn=classifier)
    """

    def __init__(self) -> None:
        self._hooks: dict[str, IntakeTMClassifier] = {}

    def register(self, name: str, fn: IntakeTMClassifier) -> None:
        """Register a named classifier. Overwrites existing registration."""
        if not callable(fn):
            raise TypeError(f"Classifier '{name}' must be callable.")
        self._hooks[name] = fn

    def resolve(self, name: str) -> IntakeTMClassifier:
        """Return classifier by name. Raises KeyError if not registered."""
        if name not in self._hooks:
            raise KeyError(
                f"No TM classifier named '{name}'. Registered: {list(self._hooks)}"
            )
        return self._hooks[name]

    def list_registered(self) -> list[str]:
        return list(self._hooks)

    def __contains__(self, name: str) -> bool:
        return name in self._hooks


# Module-level default registry pre-loaded with the built-in classifier.
DEFAULT_REGISTRY = ThreatHookRegistry()
DEFAULT_REGISTRY.register("default", classify_threat_model_request)
