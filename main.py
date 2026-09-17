#!/usr/bin/env python3
"""VRAM — Virtual Reasoning & Adaptive Memory.

Usage:
    python main.py --scenario normal
    python main.py --scenario credential-abuse
    python main.py --scenario exfiltration
    python main.py --scenario false-positive
    python main.py --demo              # alias for exfiltration
    python main.py --scenario exfiltration --dashboard
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from engine.reasoner import Reasoner
from outputs.dashboard import Dashboard
from outputs.timeline import Timeline
from simulator.events import EventSimulator
from storage.sqlite import SQLiteStorage


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("vram")


SCENARIOS = {
    "normal": ("SA Healthcare — Normal clinical activity", "scenario_normal"),
    "credential-abuse": ("SA Healthcare — Workforce credential abuse", "scenario_credential_abuse"),
    "exfiltration": ("SA Healthcare — Possible PHI Exfiltration", "scenario_exfiltration"),
    "false-positive": ("SA Healthcare — False Positive (MFA cooling)", "scenario_false_positive"),
}


def _print_step(obs, result) -> None:
    ts = obs.timestamp.strftime("%H:%M:%S")
    print(f"[{ts}] {obs.source.upper()}")
    print(f"         {obs.event_type.upper()}")
    print(f"         User: {obs.user or '-'}  Host: {obs.host or '-'}  IP: {obs.source_ip or '-'}")
    if obs.metadata.get("table"):
        print(f"         Table: {obs.metadata.get('table')}  Rows: {obs.metadata.get('rows', '-')}")
    print()
    print("[VRAM]")
    if result.new_hypotheses:
        for h in result.new_hypotheses:
            print(f"  NEW Hypothesis: {h.title}")
            print(f"  Confidence: {h.confidence:.2f}")
    for h in result.updated_hypotheses:
        print(f"  Hypothesis: {h.title}")
        print(f"  Confidence: {h.confidence:.2f}  [{h.status}]")
        if h.evidence:
            print("  Evidence:")
            for ev in h.evidence[-4:]:
                print(f"    - {ev.get('reason', ev)}")
    if result.predictions:
        for p in result.predictions:
            print(f"  Prediction: {p.predicted_event} (conf {p.confidence:.2f})")
            print(f"             {p.explanation}")
    if not result.updated_hypotheses and not result.new_hypotheses:
        print("  (no significant hypothesis change)")
    print()
    print("─" * 60)
    print()


def run_scenario(name: str, show_dashboard: bool = False) -> None:
    if name not in SCENARIOS:
        print(f"Unknown scenario: {name}")
        print(f"Available: {', '.join(SCENARIOS)}")
        return

    title, method = SCENARIOS[name]
    print("\n" + "=" * 60)
    print("  VRAM SECURITY REASONING ENGINE")
    print(f"  Scenario: {title}")
    print("=" * 60 + "\n")

    # Fresh in-memory state per run
    SQLiteStorage._memory_conn = None
    reasoner = Reasoner()
    simulator = EventSimulator()
    events = getattr(simulator, method)()
    last_predictions = []

    for obs in events:
        result = reasoner.process(obs)
        _print_step(obs, result)
        last_predictions = result.predictions

    # Final narrative for strongest hypothesis
    active = reasoner.hypotheses.list_active()
    if active:
        strongest = max(active, key=lambda h: h.confidence)
        related = []
        if strongest.related_users:
            related = reasoner.memory.get_by_user(strongest.related_users[0])
        print("VRAM NARRATIVE")
        print("─" * 60)
        print(reasoner.narrative.build_narrative(strongest, related))
        print("─" * 60)
        print()

    print(f"Scenario '{name}' complete.\n")

    if show_dashboard:
        dash = Dashboard(reasoner.memory, reasoner.hypotheses)
        print(dash.render(predictions=last_predictions, title=f"VRAM Dashboard — {title}"))
        if active:
            strongest = max(active, key=lambda h: h.confidence)
            related = reasoner.memory.get_by_user(
                strongest.related_users[0] if strongest.related_users else ""
            )
            print()
            print(Timeline().render(strongest, related))


def run_pgaudit_listener(dsn: str | None, log_path: str | None, cycles: int) -> None:
    """Poll Postgres audit table and/or tail a log file into the reasoner."""
    from inputs.pgaudit_listener import PgAuditListener, PgAuditListenerConfig
    import os

    dsn = dsn or os.environ.get("VRAM_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if not dsn and not log_path:
        # Default lab DSN
        dsn = "postgresql://vram:vram_lab_password@localhost:5433/enterprise"
        print(f"Using default lab DSN (override with --dsn or VRAM_DATABASE_URL)")

    cfg = PgAuditListenerConfig(dsn=dsn, log_path=log_path, poll_interval_seconds=1.5)
    listener = PgAuditListener(config=cfg)
    reasoner = Reasoner()

    print("VRAM pgaudit listener started")
    print(f"  dsn={dsn!r}")
    print(f"  log_path={log_path!r}")
    print(f"  max_cycles={cycles}")
    print("  (Ctrl+C to stop)\n")

    try:
        for i, obs in enumerate(listener.stream(max_cycles=cycles)):
            print(f"[audit] {obs.event_type} user={obs.user} table={obs.metadata.get('table')}")
            result = reasoner.process(obs)
            for h in result.updated_hypotheses:
                print(f"  → {h.title}: {h.confidence:.2f} [{h.status}]")
            print()
    except KeyboardInterrupt:
        print("\nListener stopped.")

def main() -> None:
    parser = argparse.ArgumentParser(description="VRAM — Virtual Reasoning & Adaptive Memory")
    parser.add_argument(
        "--scenario",
        choices=list(SCENARIOS.keys()),
        help="Run a multi-source lab scenario",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Alias for --scenario exfiltration",
    )
    parser.add_argument(
        "--false-positive",
        action="store_true",
        help="Alias for --scenario false-positive",
    )
    parser.add_argument(
        "--listen-pgaudit",
        action="store_true",
        help="Poll Postgres vram_audit_log and/or tail an audit log file",
    )
    parser.add_argument("--dsn", default=None, help="Postgres DSN for pgaudit listener")
    parser.add_argument("--audit-log", default=None, help="JSONL audit log file to tail")
    parser.add_argument("--cycles", type=int, default=30, help="Max poll cycles for listener")
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Show terminal dashboard at the end",
    )
    args = parser.parse_args()

    if args.listen_pgaudit:
        run_pgaudit_listener(args.dsn, args.audit_log, args.cycles)
    elif args.demo:
        run_scenario("exfiltration", show_dashboard=args.dashboard)
    elif args.false_positive:
        run_scenario("false-positive", show_dashboard=args.dashboard)
    elif args.scenario:
        run_scenario(args.scenario, show_dashboard=args.dashboard)
    else:
        print("VRAM Telemetry Integration Lab")
        print()
        print("  python main.py --scenario normal")
        print("  python main.py --scenario credential-abuse")
        print("  python main.py --scenario exfiltration")
        print("  python main.py --scenario false-positive")
        print("  python main.py --demo --dashboard")
        print()
        print("  python -m pytest")
        print("  uvicorn api.server:app --reload")
        print("  python main.py --listen-pgaudit")
        print("  python main.py --listen-pgaudit --dsn postgresql://vram:pass@localhost/enterprise")


if __name__ == "__main__":
    main()
