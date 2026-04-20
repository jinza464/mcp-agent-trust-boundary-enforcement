from fastapi import FastAPI

app = FastAPI(
    title="Client-side Trust Boundary Enforcement Prototype",
    description="Minimal FastAPI prototype for MCP-enabled LLM agents research.",
    version="0.1.0",
)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}
