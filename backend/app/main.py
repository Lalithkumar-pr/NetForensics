"""
FastAPI Main Application Server for NetForensics (Final Phase).
Serves forensic investigation API endpoints and hosts the single-page dashboard.
"""

from pathlib import Path
from typing import Any, Dict, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.app.api.router import get_available_scenarios, run_investigation

app = FastAPI(
    title="NetForensics API",
    description="Deterministic Network Failure Forensics & Root-Cause Reconstruction Engine",
    version="1.0.0",
)

# Enable CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class InvestigateRequest(BaseModel):
    scenario_id: str


@app.get("/api/scenarios")
def api_get_scenarios() -> Dict[str, Any]:
    """
    Returns list of available scenario datasets from data/scenarios/.
    """
    scenarios = get_available_scenarios()
    return {
        "status": "success",
        "scenarios": scenarios,
    }


@app.post("/api/investigate")
def api_post_investigate(req: InvestigateRequest) -> Dict[str, Any]:
    """
    Runs end-to-end deterministic forensic pipeline for given scenario ID.
    """
    if not req.scenario_id:
        raise HTTPException(status_code=400, detail="scenario_id is required.")

    result = run_investigation(req.scenario_id)
    if result.get("status") == "error":
        raise HTTPException(status_code=404, detail=result.get("error", "Investigation failed."))

    return result


# Static UI mounting
frontend_dir = Path("frontend")
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory="frontend"), name="static")

    @app.get("/", response_class=HTMLResponse)
    def read_root():
        index_file = frontend_dir / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
        return HTMLResponse("<h1>NetForensics Dashboard</h1><p>index.html missing in frontend/</p>")
