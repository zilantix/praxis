import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, "/opt/praxis/app/lib")

from fastapi import FastAPI, Query
from fastapi.responses import PlainTextResponse, JSONResponse
import praxis_core as core

app = FastAPI(
    title="PRAXIS Adaptive Camouflage Controller API",
    version="0.1.0",
    description="Research service for PRAXIS configuration scoring, evidence browsing, and claim-boundary reporting.",
)


@app.get("/")
def root():
    return core.summary()


@app.get("/health")
def health():
    return {"status": "ok", "service": "praxis-controller-api"}


@app.get("/summary")
def summary():
    return core.summary()


@app.get("/files")
def files():
    return core.file_status()


@app.get("/rq-status")
def rq_status():
    return core.rq_status()


@app.get("/claim-boundary")
def claim_boundary():
    return core.claim_boundary()


@app.get("/score")
def score(
    detector_weight: float = Query(45, ge=0),
    public_weight: float = Query(35, ge=0),
    overhead_weight: float = Query(5, ge=0),
    compliance_weight: float = Query(15, ge=0),
):
    return core.controller_ranking(
        detector_weight=detector_weight,
        public_weight=public_weight,
        overhead_weight=overhead_weight,
        compliance_weight=compliance_weight,
    )


@app.get("/phase21")
def phase21():
    return core.phase21_summary().to_dict(orient="records")


@app.get("/final-claim", response_class=PlainTextResponse)
def final_claim():
    return core.read_text(core.PATHS["final_claim"], fallback="Final claim file not found.")


@app.get("/final-status", response_class=PlainTextResponse)
def final_status():
    return core.read_text(core.PATHS["final_status"], fallback="Final status file not found.")


@app.post("/export")
def export():
    path = Path("/opt/praxis/app/exports/praxis_controller_export.json")
    written = core.export_json(path)
    return {"written": str(written), "size_bytes": written.stat().st_size}
