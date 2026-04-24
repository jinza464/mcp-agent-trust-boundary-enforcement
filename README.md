# MCP-enabled LLM Agents: Client-side Trust Boundary Enforcement (Prototype)

This repository contains a minimal runnable Python + FastAPI prototype scaffold for PhD research on **client-side trust boundary enforcement** for **MCP-enabled LLM agents**.

## Project Structure

- `app/main.py`: FastAPI entrypoint
- `app/api`: API layer placeholders
- `app/core`: core utilities/placeholders
- `app/registry`: tool/model registry placeholders
- `app/tagging`: data sensitivity tagging placeholders
- `app/policy`: policy definition placeholders
- `app/validation`: validation pipeline placeholders
- `app/decision`: decision engine placeholders
- `app/sink`: output sink placeholders
- `app/mcp`: MCP integration placeholders
- `app/eval`: evaluation placeholders
- `tests`: test placeholders
- `docs`: documentation
- `data`: local data assets

## Quick Start

1. Create and activate a virtual environment.
2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Run server:

   ```bash
   uvicorn app.main:app --reload
   ```

4. Verify endpoints:
- Health check: `http://127.0.0.1:8000/health`
- Swagger UI: `http://127.0.0.1:8000/docs`

## Research Prototype Status

This repository is currently sealed as a thesis experiment baseline for an MCP-enabled LLM agent client-side trust boundary enforcement research prototype. The current baseline includes tightened data boundaries, MCP protocol objects, evidence-tree policy decisions, unified runtime/eval semantics, service-layer consolidation, and final prototype capability completion.

Experiment scope and capability boundaries are documented in `docs/experiment_scope.md`. The thesis experiment readiness checklist is documented in `docs/thesis_experiment_ready_checklist.md`.
