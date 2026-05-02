# MatrixSecHub AI‑Cybersecurity Suite

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Framework: CrewAI / AutoGen](https://img.shields.io/badge/framework-CrewAI%20%7C%20AutoGen-green.svg)]()
[![Compliance: NIST AI RMF / SOC 2](https://img.shields.io/badge/compliance-NIST%20AI%20RMF%20%7C%20SOC%202-red.svg)]()

---

## Overview

**MatrixSecHub AI‑Cybersecurity Suite** is a production‑grade, multi‑agent AI security framework designed for enterprise threat detection, adversarial red‑teaming, compliance governance, and autonomous security operations. Built on **CrewAI** and **Microsoft AutoGen**, it demonstrates how large language model (LLM) agents can be safely orchestrated in high‑stakes security environments with strict role constraints, retrieval‑augmented grounding, and continuous evaluation pipelines.

This repository serves as the reference architecture for the **MatrixSecHub** AI security platform — a system designed by and for AI Security Architects who treat model behavior, prompt injection surface area, and agent trust boundaries as first‑class engineering concerns.

---

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                    Orchestration Layer (CrewAI)                   │
│   ┌─────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│   │  Security   │  │   Threat     │  │   Red‑Team           │   │
│   │  Analyst    │◄─┤   Modeling   │◄─┤   Adversary          │   │
│   │  Agent      │  │   Agent      │  │   Agent              │   │
│   └──────┬──────┘  └──────┬───────┘  └──────────────────────┘   │
│          │                │                                        │
│   ┌──────▼────────────────▼──────────────────────────────────┐   │
│   │              Compliance / Governance Agent                │   │
│   └──────────────────────────┬───────────────────────────────┘   │
└──────────────────────────────┼───────────────────────────────────┘
                               │
         ┌─────────────────────▼──────────────────────┐
         │           RAG Grounding Pipeline             │
         │  ┌──────────────┐   ┌─────────────────────┐ │
         │  │  Vector Store│   │  NIST / MITRE / CVE  │ │
         │  │  (Chroma /   │   │  Knowledge Bases     │ │
         │  │   Pinecone)  │   │                      │ │
         │  └──────────────┘   └─────────────────────┘ │
         └────────────────────────────────────────────┘
                               │
         ┌─────────────────────▼──────────────────────┐
         │         Evaluation & Audit Pipeline          │
         │  Rubric Scoring │ Hallucination Guards │ Logs│
         └────────────────────────────────────────────┘
```

---

## Core Components

### 1. Multi‑Agent Orchestration

The suite deploys four specialized agents operating under strict role isolation:

| Agent | Primary Function | Trust Level |
|---|---|---|
| **Security Analyst** | Triage, enrichment, SIEM correlation | Medium — read‑only tool access |
| **Threat Modeling** | STRIDE/PASTA analysis, attack surface mapping | Medium — structured output only |
| **Red‑Team Adversary** | Adversarial simulation, TTPs generation | Low — sandboxed, output reviewed |
| **Compliance/Governance** | NIST AI RMF, SOC 2, policy enforcement | High — veto authority |

Agents communicate via a typed message bus. No agent directly invokes external APIs without passing through the Compliance Agent's policy gate.

---

### 2. Role‑Constrained Prompts (NIST / SOC 2 Aligned)

Every system prompt enforces:

- **Least‑privilege reasoning**: agents are scoped to their domain; cross‑domain inferences are flagged.
- **Output schema constraints**: structured JSON/YAML outputs prevent prompt injection exfiltration.
- **Denial‑of‑service guardrails**: agents refuse requests that would trigger unbounded tool loops.
- **NIST AI RMF alignment**: Govern, Map, Measure, Manage functions are embedded in agent objectives.
- **SOC 2 Trust Service Criteria**: Security, Availability, and Confidentiality principles govern data handling instructions.

Prompt templates are versioned and auditable. See [`prompt_templates.py`](prompt_templates.py).

---

### 3. RAG Grounding Pipeline

Agents are grounded against curated, versioned knowledge bases to prevent hallucination in security‑critical outputs:

- **MITRE ATT&CK** (Enterprise, ICS, Mobile) — TTP retrieval for threat modeling
- **NIST NVD / CVE feeds** — real‑time vulnerability context
- **NIST SP 800‑53 / CSF 2.0** — control mapping for compliance outputs
- **Internal runbook corpus** — organization‑specific IR procedures

Retrieval uses a hybrid dense+sparse search strategy (embedding similarity + BM25 keyword match) with a confidence threshold gate. Responses citing retrieval sources below threshold are flagged for human review.

---

### 4. Evaluation Workflows

Every agent output passes through a multi‑stage evaluation rubric before propagating downstream:

```
Agent Output
    │
    ▼
[Schema Validation]  ──FAIL──► Rejection + Retry (max 3)
    │ PASS
    ▼
[Factual Grounding Check]  ──LOW CONFIDENCE──► Human Review Queue
    │ PASS
    ▼
[Policy Gate (Compliance Agent)]  ──BLOCKED──► Audit Log + Alert
    │ APPROVED
    ▼
[Downstream Consumer / SIEM / Ticketing]
```

Evaluation scores are logged to a structured audit trail compatible with SIEM ingestion (Splunk, Elastic, Chronicle).

---

### 5. Threat Modeling Integration

The Threat Modeling Agent produces structured STRIDE analysis artifacts:

- **Asset inventory** ingested from CMDB or manual input
- **Data flow diagram** (DFD) traversal for trust boundary identification
- **STRIDE categorization** with CVSS‑aligned severity scoring
- **MITRE ATT&CK mapping** for each identified threat
- **Recommended controls** cross‑referenced against NIST SP 800‑53

Output is a machine‑readable JSON threat model suitable for import into tools such as IriusRisk, ThreatDragon, or custom ASPM platforms.

---

## Why This Repository Demonstrates AI Security Engineering

This codebase reflects the intersection of **security engineering discipline** and **AI systems architecture**:

1. **Agent trust boundaries are treated as a security primitive** — not an afterthought. Each agent has an explicit trust level, tool permission set, and memory scope.

2. **Prompt injection is a first‑class threat** — system prompts are designed with injection resistance in mind; user‑controlled inputs are never concatenated directly into privileged prompt contexts.

3. **RAG grounding reduces hallucination risk** — in security tooling, a hallucinated CVE or misattributed TTP can trigger a false incident response. Grounding pipelines enforce citation requirements.

4. **Evaluation is continuous, not terminal** — rubric hooks run at every agent handoff, not just at pipeline exit, enabling early detection of model drift or adversarial prompt manipulation.

5. **Compliance is architectural** — NIST AI RMF and SOC 2 controls are embedded in agent design, not bolted on post‑hoc.

6. **Adversarial agents are sandboxed by design** — the Red‑Team agent operates in an isolated context with output reviewed by the Compliance Agent before any artifact leaves the pipeline.

---

## Technology Stack

| Layer | Technology |
|---|---|
| Agent Orchestration | CrewAI 0.28+, Microsoft AutoGen 0.2+ |
| LLM Backend | OpenAI GPT‑4o, Azure OpenAI, Anthropic Claude |
| Vector Store | ChromaDB (local), Pinecone (production) |
| Embedding Model | OpenAI `text-embedding-3-large` |
| Evaluation | DeepEval, custom rubric engine |
| Observability | LangSmith, OpenTelemetry, Splunk HEC |
| Infrastructure | Docker, Kubernetes, Azure AKS |
| Secrets Management | HashiCorp Vault, Azure Key Vault |

---

## Getting Started

```bash
git clone https://github.com/matrixsechub/ai-security-framework.git
cd ai-security-framework
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # populate API keys via Vault or env injection
python pipeline_scaffold.py --mode analyst --input examples/sample_alert.json
```

---

## Security Considerations

- All API keys must be injected via environment variables or a secrets manager. No credentials in source.
- The Red‑Team Adversary Agent must never be run against production infrastructure without explicit human‑in‑the‑loop approval.
- RAG knowledge bases must be access‑controlled; embedding stores may contain sensitive organizational data.
- LLM outputs are **advisory only** — all high‑severity findings require human analyst review before action.

---

## License

MIT License. See [LICENSE](LICENSE).

---

*MatrixSecHub AI‑Cybersecurity Suite — Architected for the security engineer who understands that AI is both the tool and the threat surface.*
