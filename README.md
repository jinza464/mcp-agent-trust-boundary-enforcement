
# MCP Agent Trust Boundary Enforcement

> Client-side trust boundary enforcement prototype for **MCP-enabled LLM agents**.

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](#quick-start)
[![FastAPI](https://img.shields.io/badge/FastAPI-runtime-009688)](#architecture)
[![Status](https://img.shields.io/badge/status-research%20prototype-orange)](#project-scope)
[![Default Branch](https://img.shields.io/badge/branch-v1.1--artifact--consistency-purple)](#versions)
[![GitHub Repo](https://img.shields.io/badge/GitHub-jinza464%2Fmcp--agent--trust--boundary--enforcement-black)](https://github.com/jinza464/mcp-agent-trust-boundary-enforcement)

A research prototype for securing **tool-using LLM agents** on the **MCP client side**.  
This project focuses on **execution-time safety**, not just text safety: protocol context, metadata drift, trust propagation, decision evidence, and sink-side control.

---

## Overview

As LLM applications evolve into agents, the security problem changes from:

- “Is the output safe?”

to:

- “Is the **behavior** safe?”

In MCP-enabled agent systems, risks can propagate through:

- prompt injection / indirect prompt injection
- tool poisoning
- tool shadowing
- rug-pull / metadata drift
- source-to-sink data exfiltration
- excessive agency / authorization bypass

This repository explores how to enforce trust boundaries **before actions happen**.

---

## Highlights

- **MCP protocol object modeling**
- **Request lineage / provenance tracking**
- **Trust tagging**
- **Metadata validation**
- **Capability classification**
- **Decision evidence tree**
- **Sink guard for external effects**
- **Unified runtime/eval semantics**
- **Failure analysis + ablation reporting**

---

## Architecture

```text
User Query / MCP Request
        ↓
FastAPI Platform / RuntimeService
        ↓
MCPAgentClient
        ↓
Protocol Context & RequestLineage
        ↓
Trust Tagger → Metadata Validator → Capability Policy
        ↓
Decision Engine / Evidence Tree
        ↓
Sink Guard
        ↓
Mock Runtime / Execution Outcome
        ↓
Runtime Semantics / Metrics / Failure Report
````

---

## Repository Structure

```text
app/        # runtime, policy, sink guard, evaluation, services
docs/       # thesis chapter drafts, experiment analysis, runbook
scripts/    # experiment runner and summarizer
```

Repository URL:
`https://github.com/jinza464/mcp-agent-trust-boundary-enforcement`

---

## Quick Start

### 1. Create environment

```bash
python -m venv .venv
```

Windows:

```bash
.venv\Scripts\activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run tests

```bash
python -m pytest
```

### 4. Start the API

```bash
uvicorn main:app --reload
```

Typical endpoints:

* `/health`
* `/api/v1/tools`
* `/api/v1/runtime/execute`
* `/api/v1/evaluation/run`

---

## Reproduce Experiments

```bash
python scripts/run_thesis_experiments.py --output-root results/thesis_experiment_v1_final
python scripts/summarize_thesis_results.py --output-root results/thesis_experiment_v1_final
```

Typical outputs include:

* `experiment_manifest.json`
* `eval_summary.json`
* `eval_case_results.json`
* `failure_analysis_report.md`
* `thesis_metrics_table.md`
* `ablation_comparison.md`

---

## Versions

* **`research-prototype-v1.0`** — thesis baseline
* **`research-prototype-v1.1-rc1` / `research-prototype-v1.1-rc2`** — enhanced research branch
* **default showcase branch:** `v1.1-artifact-consistency`

---

## Project Scope

### In the main runtime path

* tools feature execution
* trust tagging
* metadata validation
* capability policy
* decision evidence tree
* lineage-aware sink context
* runtime/eval unified semantics
* failure analysis
* ablation reporting

### Recognized but not fully executed

* sampling
* roots
* elicitation

This is a **research prototype**, not a production security gateway.

---

## Key Findings

From the current thesis benchmark:

* the baseline keeps **attack success rate** relatively low
* **metadata validation** is the strongest defense component
* **sink guard** is critical for execution-time control
* **trust tagging** contributes contextual evidence
* the system is intentionally **security-conservative**
* remaining successful cases cluster around **adaptive synonym / paraphrase-style** attacks

For more details, see:

* `docs/thesis_experiment_analysis.md`

---

## Thesis Materials

This repository also includes thesis-related draft materials:

* `docs/thesis_chapter_2_related_work.md`
* `docs/thesis_chapter_3_system_design.md`
* `docs/thesis_experiment_analysis.md`
* `docs/thesis_experiment_runbook.md`

---

## Limitations

This repository does **not** claim:

* full real MCP transport integration
* complete defense against adaptive attackers
* production-grade concurrency/governance
* PatternMemory as part of the main decision path

---

## Roadmap

* semantic capability matching
* embedding-backed PatternMemory
* schema compatibility analysis
* authorization-chain modeling
* scoped sink policies
* real MCP server/client integration
* larger adaptive benchmarks

---

## Citation

If you use this project in academic work, please cite it as a research prototype and clearly indicate the version/tag used.

Suggested citation entry placeholder:

```bibtex
@misc{jinza464_mcp_agent_trust_boundary_enforcement,
  author       = {Jin Za},
  title        = {MCP Agent Trust Boundary Enforcement},
  year         = {2026},
  howpublished = {\url{https://github.com/jinza464/mcp-agent-trust-boundary-enforcement}},
  note         = {Research prototype for MCP-enabled LLM agent trust boundary enforcement}
}
```

---

## License

Recommended: **MIT**

---

## Contact

GitHub: [https://github.com/jinza464](https://github.com/jinza464)
Repository: [https://github.com/jinza464/mcp-agent-trust-boundary-enforcement](https://github.com/jinza464/mcp-agent-trust-boundary-enforcement)

```
```
