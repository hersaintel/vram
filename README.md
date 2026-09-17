# VRAM — Virtual Reasoning & Adaptive Memory

**Kennedy Maina : hersaintel**

**Disclaimer**

**VRAM** (Virtual Reasoning & Adaptive Memory), including its conceptual design, reasoning model, and terminology as used in this project, is the sole creation of the author. This Cornerstone submission is a work in progress and a limited prototype. It is intended to illustrate one core pillar of a broader long-term direction: a future adaptive reasoning capability (including the possibility of a dedicated adaptive language or formalism for contextual security reasoning).

Nothing in this demo claims that such a language or full adaptive system already exists, is complete, or is product-ready. Lab components (for example Keycloak, PostgreSQL, and Wazuh-style telemetry) and any IBM product names are used only to mirror architectural roles and to ground the case study; they are not presented as official products of, or endorsements by, IBM or other vendors. All healthcare scenarios and records are synthetic.

This work is submitted for educational assessment and defensive research illustration only.

---

**Full handoff:** [`DOCUMENTATION.md`](DOCUMENTATION.md) — case study, pathway mapping, live deployment, domain routing, demo script, teardown.

| | |
|--|--|
| **Live demo** | https://hersaspace.dpdns.org/ |
| **Health** | https://hersaspace.dpdns.org/health |
| **API docs** | https://hersaspace.dpdns.org/docs |
| **Container image** | `quay.io/6lackrose/vram:latest` |
| **OpenShift project** | `6lackrose-dev` |

Local, modular, **deterministic** cybersecurity reasoning engine with a multi-source telemetry lab.

VRAM does **not** replace a SIEM. It demonstrates a different approach:

> Traditional SIEMs primarily correlate events against predefined rules.  
> VRAM maintains contextual memory, constructs hypotheses, updates confidence as evidence accumulates, and generates predictions about likely next activity.

**Wazuh, PostgreSQL and Keycloak are laboratory components** used to demonstrate concepts analogous to enterprise security telemetry, database activity monitoring and identity management. **VRAM is not an implementation of IBM QRadar, IBM Guardium or IBM Verify.**

---

## Cornerstone alignment

- **Team:** Solo  
- **Pathway:** IBM Cyber Security Pathway (Verify / Guardium / QRadar **roles**; lab mirrors)  
- **Sector / country:** Healthcare — **South Africa** (synthetic; POPIA-aware framing)  
- **Audience feature:** Investigator contextual dashboard  
- **Live URL:** https://hersaspace.dpdns.org/ (Cloudflare → OpenShift Route)  
- **Case study:** [`docs/CASE_STUDY_SOUTH_AFRICA.md`](docs/CASE_STUDY_SOUTH_AFRICA.md)  
- **Pathway mapping:** [`docs/PATHWAY_MAPPING.md`](docs/PATHWAY_MAPPING.md)  
- **Demo script:** [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md)  
- **Runbook:** [`docs/RUNBOOK.md`](docs/RUNBOOK.md)  
- **Full documentation:** [`DOCUMENTATION.md`](DOCUMENTATION.md)  
- **OpenShift manifests:** [`deploy/openshift/`](deploy/openshift/)  
- **Container:** `Dockerfile` → `quay.io/6lackrose/vram:latest`

---

## Architecture

```
Keycloak (Identity) ──┐
                      ▼
Wazuh (Endpoint) ──► VRAM Reasoner ◄── PostgreSQL (DB Audit)
                      │
                 Memory → Context → Hypothesis
                      → Confidence → Prediction → Narrative → Alert
                      → Terminal dashboard  /  Browser dashboard
```

Every external event is converted into the VRAM **Observation** model by an adapter. Source-specific structures never enter the reasoning engine.

---

## Quick Start

```bash
cd vram
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Multi-source CLI scenarios
python main.py --scenario normal
python main.py --scenario credential-abuse
python main.py --scenario exfiltration
python main.py --scenario false-positive

# Terminal dashboard + timeline
python main.py --scenario exfiltration --dashboard

# Browser dashboard + API
uvicorn api.server:app --reload --host 0.0.0.0 --port 8000
# then open http://127.0.0.1:8000/  or  http://127.0.0.1:8000/dashboard

# Live pgaudit-style listener (needs Postgres lab up)
python main.py --listen-pgaudit
python main.py --listen-pgaudit \
  --dsn postgresql://vram:vram_lab_password@localhost:5433/enterprise

# Tests
python -m pytest
```

### Optional lab services (Docker)

```bash
cp .env.example .env

# Lightweight: Postgres + Keycloak only
docker compose up -d postgres keycloak

# Heavyweight: also start full Wazuh stack (~4GB+ RAM)
docker compose --profile wazuh up -d
```

Wazuh is **not** required for VRAM development — simulated Wazuh JSON events are enough.

**Default ports**

| Service | Host port | Notes |
|---------|-----------|--------|
| VRAM API + browser dashboard | **8000** | `http://127.0.0.1:8000/` |
| Keycloak | **8080** | Identity lab |
| VRAM lab Postgres | **5433** | Mapped away from 5432 to avoid clashing with other local DBs (e.g. n8n) |
| Wazuh API (optional) | 55000 | Profile `wazuh` only |
| Wazuh Dashboard (optional) | 8443 | Profile `wazuh` only |

### Container

```bash
docker build -t vram:latest .
docker run --rm -p 8000:8000 vram:latest
# or: docker run --rm -p 8000:8000 quay.io/6lackrose/vram:latest
```

---

## Browser dashboard

A web UI is served by FastAPI (no separate frontend build).

**Live:** https://hersaspace.dpdns.org/  

**Local:**

```bash
uvicorn api.server:app --reload --host 0.0.0.0 --port 8000
```

| URL | Purpose |
|-----|---------|
| http://127.0.0.1:8000/ | **Browser dashboard** |
| http://127.0.0.1:8000/dashboard | Same dashboard |
| http://127.0.0.1:8000/docs | Interactive OpenAPI docs |
| http://127.0.0.1:8000/health | Health JSON |

**Dashboard features**

- Live hypotheses with confidence bars and status badges  
- Recent multi-source observations (Keycloak / Wazuh / PostgreSQL)  
- Predictions and high-risk users/hosts  
- Investigation narrative / timeline for the strongest hypothesis  
- **Run scenario** — full synthetic play (PHI exfiltration, false-positive, etc.)  
- **Step next** — inject one event at a time  
- **Reset** — clear in-memory state  
- Auto-refresh every few seconds  

Static assets live in `api/static/dashboard.html`.

---

## What each source contributes

| Source | Role | Example events |
|--------|------|----------------|
| **Keycloak** | Identity / IAM | LOGIN, LOGIN_ERROR, MFA, ROLE_MAPPING, LOGOUT |
| **Wazuh** | Endpoint / SIEM-style telemetry | auth failure, privilege escalation, external connection |
| **PostgreSQL** | Database activity monitoring | SELECT on `patient_records` / encounters, large exports |

---

## Normalisation

Adapters:

- `inputs/keycloak.py` → `KeycloakAdapter`
- `inputs/wazuh.py` → `WazuhAdapter` (documented severity mapping)
- `inputs/postgres.py` → `PostgresAuditAdapter`
- `inputs/keycloak_webhook.py` → HTTP webhook helper for Keycloak events
- `inputs/pgaudit_listener.py` → poll `vram_audit_log` table and/or tail JSONL audit files

Flow: **External Event → Adapter → Observation → Memory → Reasoning**

---

## Reasoning

- **Rules** contribute evidence deltas (positive or negative) to hypotheses.
- **Confidence** is numeric in `[0.0, 1.0]` and can rise *or* fall.
- **Cross-source correlation** boosts confidence when Keycloak + Wazuh + PostgreSQL describe the same user.
- **MFA / normal activity** are mitigating signals (they reduce confidence; they do not prove legitimacy).
- **Post-MFA cooling** further reduces suspicion when low-risk activity continues without external transfer.
- Weak hypotheses can move to **weakening** or **dismissed**.
- **Predictions** are deterministic sequence-based (no ML).
- **Narratives** are generated only from stored observations — never invented.

---

## Demo: Possible PHI Exfiltration (South Africa healthcare, cross-source)

```
[09:03] KEYCLOAK   LOGIN                  → Credential Abuse ~0.10
[09:07] WAZUH      PRIVILEGE_ESCALATION   → PHI Exfiltration rises
[09:12] POSTGRESQL patient_records SELECT → confidence climbs
[09:15] POSTGRESQL ~30,000 row retrieval  → high confidence
[09:20] WAZUH      EXTERNAL_CONNECTION    → Possible PHI Exfiltration ≥ 0.80
```

CLI:

```bash
python main.py --scenario exfiltration --dashboard
```

Browser (local): open the dashboard → choose **PHI Exfiltration (SA)** → **Run scenario**.  
Browser (live): https://hersaspace.dpdns.org/

---

## False-positive reduction

The `false-positive` scenario shows confidence rising on suspicious signals, then falling after MFA and normal activity (no external connection).

```bash
python main.py --scenario false-positive --dashboard
```

---

## Live deployment (OpenShift + custom domain)

| Item | Value |
|------|--------|
| Image | `quay.io/6lackrose/vram:latest` |
| Project | `6lackrose-dev` |
| Service port | **8000** |
| Custom domain | **hersaspace.dpdns.org** (Cloudflare proxied CNAME → OpenShift router) |
| Route | OpenShift `edge` Route with host `hersaspace.dpdns.org` |

Manifests: `deploy/openshift/`.  
Details and teardown: `DOCUMENTATION.md` §4.

```bash
oc project 6lackrose-dev
oc get pods,svc,route
curl -sS https://hersaspace.dpdns.org/health
```

---

## REST API

| Endpoint | Description |
|----------|-------------|
| `GET /` · `GET /dashboard` | Browser dashboard (HTML) |
| `GET /health` | Health check |
| `POST /events` | Generic normalised event |
| `POST /events/keycloak` | Raw Keycloak event |
| `POST /events/wazuh` | Raw Wazuh-style alert |
| `POST /events/postgres` | Raw PostgreSQL audit event |
| `POST /webhooks/keycloak` | Keycloak Event Listener webhook |
| `GET /events` | Recent observations |
| `GET /hypotheses` | All hypotheses |
| `GET /hypotheses/{id}` | One hypothesis |
| `GET /predictions` | Current predictions |
| `GET /timeline/{hypothesis_id}` | Chronological investigation timeline |
| `POST /demo/{scenario}` | Run synthetic scenario (`?mode=all` or `?mode=queue`) |
| `POST /demo/reset` | Clear in-memory reasoning state |

Example scenario names: `normal`, `credential-abuse`, `exfiltration`, `false-positive`.

---

## Live Postgres audit listener

Polls the lab table `vram_audit_log` (created by `lab/init-db.sql`) and optionally tails a JSONL log file.

```bash
docker compose up -d postgres
python main.py --listen-pgaudit \
  --dsn postgresql://vram:vram_lab_password@localhost:5433/enterprise
```

Requires `psycopg2-binary` (listed in `requirements.txt`).

---

## Project layout

```
vram/
├── DOCUMENTATION.md   # full handoff (live URLs, domain, case study)
├── README.md
├── Dockerfile
├── docker-compose.yml
├── main.py
├── config.py
├── requirements.txt
├── engine/            # reasoner, memory, confidence, rules, hypotheses, predictor, narrative
├── models/            # Observation, Hypothesis, Prediction
├── inputs/            # keycloak, wazuh, postgres, webhook, pgaudit listener
├── outputs/           # terminal alerts, dashboard, timeline
├── storage/           # SQLite (in-memory default)
├── simulator/         # multi-source SA healthcare scenarios
├── api/
│   ├── server.py      # FastAPI + demo endpoints
│   └── static/
│       └── dashboard.html
├── deploy/openshift/  # Deployment, Service, Route
├── docs/
│   ├── CASE_STUDY_SOUTH_AFRICA.md
│   ├── PATHWAY_MAPPING.md
│   ├── DEMO_SCRIPT.md
│   └── RUNBOOK.md
├── lab/
│   └── init-db.sql    # synthetic clinical schema + vram_audit_log
└── tests/
```

---

## Design principles

1. Modular architecture  
2. Explainable decisions  
3. Deterministic reasoning (no LLM / ML in V1)  
4. Every hypothesis exposes supporting evidence  
5. Confidence can increase **or** decrease  
6. Never silently discard an observation  
7. No offensive capabilities — synthetic / authorised lab data only  

---

## Future work

- Long-term vision: adaptive reasoning language / formalism (out of scope for this prototype)  
- Deeper live Wazuh manager / agent integration  
- Native `pgaudit` log streaming  
- Keycloak Event Listener SPI packaging  
- Neo4j entity graph  
- Optional local LLM (Ollama) for narrative polish  
- Adaptive rule weighting  

---

## License

Research / educational prototype. Defensive use only. Synthetic data only.
