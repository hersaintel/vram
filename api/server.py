"""Minimal FastAPI REST API for VRAM + browser dashboard."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from models.observation import Observation
from engine.reasoner import Reasoner
from storage.sqlite import SQLiteStorage
from engine.memory import Memory
from inputs.keycloak import KeycloakAdapter
from inputs.wazuh import WazuhAdapter
from inputs.postgres import PostgresAuditAdapter
from inputs.keycloak_webhook import KeycloakWebhookReceiver
from simulator.events import EventSimulator

STATIC_DIR = Path(__file__).resolve().parent / "static"

_storage = SQLiteStorage(in_memory=True)
_memory = Memory(backend=_storage)
reasoner = Reasoner(memory=_memory)

kc_adapter = KeycloakAdapter()
wz_adapter = WazuhAdapter()
pg_adapter = PostgresAuditAdapter()
kc_webhook = KeycloakWebhookReceiver()

app = FastAPI(
    title="VRAM API",
    description="Virtual Reasoning & Adaptive Memory — defensive cybersecurity reasoning engine",
    version="0.4.0",
)

if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class EventIn(BaseModel):
    event_type: str
    user: str | None = None
    host: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    action: str | None = None
    severity: int = 0
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    source: str = "api"
    timestamp: str | None = None


def _process(obs: Observation) -> dict[str, Any]:
    result = reasoner.process(obs)
    return {
        "observation_id": obs.id,
        "observation": obs.to_dict(),
        "explanation": result.explanation,
        "hypotheses": [h.to_dict() for h in result.updated_hypotheses],
        "new_hypotheses": [h.to_dict() for h in result.new_hypotheses],
        "predictions": [p.to_dict() for p in result.predictions],
        "narrative": result.narrative,
    }


def _reset_reasoner() -> None:
    """Clear in-memory state for a fresh demo run."""
    global _storage, _memory, reasoner
    SQLiteStorage._memory_conn = None
    _storage = SQLiteStorage(in_memory=True)
    _memory = Memory(backend=_storage)
    reasoner = Reasoner(memory=_memory)


def _scenario_observations(name: str) -> list[Observation]:
    sim = EventSimulator()
    mapping = {
        "normal": sim.scenario_normal,
        "credential-abuse": sim.scenario_credential_abuse,
        "exfiltration": sim.scenario_exfiltration,
        "false-positive": sim.scenario_false_positive,
    }
    if name not in mapping:
        raise HTTPException(status_code=404, detail=f"Unknown scenario: {name}")
    return mapping[name]()


@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_page() -> FileResponse:
    path = STATIC_DIR / "dashboard.html"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Dashboard not found")
    return FileResponse(path, media_type="text/html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "vram", "version": "0.4.0"}


@app.post("/events")
def post_event(event: EventIn) -> dict[str, Any]:
    kwargs: dict[str, Any] = dict(
        source=event.source,
        event_type=event.event_type,
        user=event.user,
        host=event.host,
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        action=event.action,
        severity=event.severity,
        tags=event.tags,
        metadata=event.metadata,
    )
    if event.timestamp:
        from datetime import datetime
        try:
            kwargs["timestamp"] = datetime.fromisoformat(
                event.timestamp.replace("Z", "+00:00")
            )
        except ValueError:
            pass
    obs = Observation(**kwargs)
    return _process(obs)


@app.post("/events/keycloak")
def post_keycloak(event: dict[str, Any]) -> dict[str, Any]:
    return _process(kc_adapter.parse_event(event))


@app.post("/events/wazuh")
def post_wazuh(event: dict[str, Any]) -> dict[str, Any]:
    return _process(wz_adapter.parse_event(event))


@app.post("/events/postgres")
def post_postgres(event: dict[str, Any]) -> dict[str, Any]:
    return _process(pg_adapter.parse_event(event))


@app.post("/webhooks/keycloak")
async def webhook_keycloak(request: Request) -> dict[str, Any]:
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    observations = kc_webhook.receive(payload)
    results = [_process(obs) for obs in observations]
    return {"received": len(observations), "results": results}


@app.get("/events")
def list_events(limit: int = 50) -> list[dict[str, Any]]:
    return [o.to_dict() for o in reasoner.memory.get_recent(limit=limit)]


@app.get("/hypotheses")
def list_hypotheses() -> list[dict[str, Any]]:
    return [h.to_dict() for h in reasoner.hypotheses.list_all()]


@app.get("/hypotheses/{hyp_id}")
def get_hypothesis(hyp_id: str) -> dict[str, Any]:
    h = reasoner.hypotheses.get(hyp_id)
    if not h:
        raise HTTPException(status_code=404, detail="Hypothesis not found")
    return h.to_dict()


@app.get("/predictions")
def list_predictions() -> list[dict[str, Any]]:
    recent = reasoner.memory.get_recent(limit=20)
    active = reasoner.hypotheses.list_active()
    preds = reasoner.predictor.predict(recent, active)
    return [p.to_dict() for p in preds]


@app.get("/timeline/{hypothesis_id}")
def timeline(hypothesis_id: str) -> dict[str, Any]:
    h = reasoner.hypotheses.get(hypothesis_id)
    if not h:
        raise HTTPException(status_code=404, detail="Hypothesis not found")
    user = h.related_users[0] if h.related_users else None
    obs = reasoner.memory.get_by_user(user) if user else []
    ordered = sorted(obs, key=lambda x: x.timestamp)
    return {
        "hypothesis": h.to_dict(),
        "events": [
            {
                "timestamp": o.timestamp.isoformat(),
                "source": o.source,
                "event_type": o.event_type,
                "user": o.user,
                "host": o.host,
                "source_ip": o.source_ip,
                "action": o.action,
                "severity": o.severity,
                "metadata": o.metadata,
            }
            for o in ordered
        ],
    }


@app.post("/demo/reset")
def demo_reset() -> dict[str, str]:
    _reset_reasoner()
    return {"status": "reset"}


@app.post("/demo/{scenario}")
def demo_scenario(scenario: str, mode: str = "all") -> dict[str, Any]:
    """Run a synthetic multi-source scenario into the shared reasoner.

    mode=all   — process all events immediately (dashboard watch)
    mode=queue — return serialisable event queue for step-by-step UI
    """
    observations = _scenario_observations(scenario)

    if mode == "queue":
        return {
            "scenario": scenario,
            "queue": [o.to_dict() for o in observations],
            "count": len(observations),
        }

    _reset_reasoner()
    results = []
    for obs in observations:
        results.append(_process(obs))

    return {
        "scenario": scenario,
        "events_processed": len(results),
        "hypotheses": [h.to_dict() for h in reasoner.hypotheses.list_all()],
        "last": results[-1] if results else None,
    }