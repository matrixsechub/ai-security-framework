"""
security_plane
--------------
Bootstrap package for the MatrixSecHub AI-Security Framework Security Plane.

Implements §§00–04 of the Security Plane Integration Plan (v1):
  §00 — agent roster + guardrail roster  (agent_config.py)
  §01 — architecture map                 (plan reference only)
  §02 — security lifecycle model         (lifecycle.py, pipeline_scaffold.py)
  §03 — agent permissioning model        (permissions.py, agent_config.py)
  §04 — threat modeling hooks            (threat_hooks.py)

Out of scope for this branch (belong to later branches):
  §05 — audit hardening (HMAC, run-ID correlation)
  §06 — anomaly detection pipeline
  §07 — operator security surfaces
  §08 — HQ schema extensions
  §09 — telemetry → HQ propagation

Integration Plan revision: v1
Security Plane version: 1.0.0-bootstrap
"""

SECURITY_PLANE_VERSION = "1.0.0-bootstrap"
INTEGRATION_PLAN_REVISION = "v1"

__all__ = [
    "permissions",
    "lifecycle",
    "threat_hooks",
    "SECURITY_PLANE_VERSION",
    "INTEGRATION_PLAN_REVISION",
]
