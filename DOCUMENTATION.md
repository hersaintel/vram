# VRAM — Full Project Documentation

**Virtual Reasoning & Adaptive Memory**

Cornerstone / Phase 3 — Solo submission  

**GitHub repository:** https://github.com/hersaintel/vram

**Disclaimer**

**VRAM** (Virtual Reasoning & Adaptive Memory), including its conceptual design, reasoning model, and terminology as used in this project, is the sole creation of the author. This Cornerstone submission is a work in progress and a limited prototype. It is intended to illustrate one core pillar of a broader long-term direction: a future adaptive reasoning capability (including the possibility of a dedicated adaptive language or formalism for contextual security reasoning).
Nothing in this demo claims that such a language or full adaptive system already exists, is complete, or is product-ready. Lab components (for example Keycloak, PostgreSQL, and Wazuh-style telemetry) and any IBM product names are used only to mirror architectural roles and to ground the case study; they are not presented as official products of, or endorsements by, IBM or other vendors. All healthcare scenarios and records are synthetic.
This work is submitted for educational assessment and defensive research illustration only.

| Field | Value |
|-------|--------|
| **Pathway** | IBM Cyber Security Pathway (Verify / Guardium / QRadar **roles**) |
| **Sector / country** | Healthcare — **South Africa** |
| **Audience feature** | Investigator-facing contextual dashboard |
| **Team** | Solo |
| **Data** | Synthetic only — no real patient or PHI |

---

## 1. What VRAM is

VRAM is a **deterministic, explainable** reasoning layer for cybersecurity telemetry. It does **not** replace a SIEM, IAM, or database activity monitor.

**Problem (context gap):** Identity, endpoint, and database events are often triaged in isolation. A sequence such as authentication → privilege escalation → sensitive clinical DB access → large export → external connection can indicate an evolving incident even when each event alone looks weak.

**VRAM pipeline:**

```text
Observation → Memory → Context → Hypothesis → Confidence → Prediction → Narrative → Alert
```

Confidence is numeric in `[0.0, 1.0]` and can **rise or fall** (including MFA / normal-activity cooling). No LLM/ML is required in V1.

---

## 2. IBM pathway likeness (hybrid model)

Lab components **mirror** IBM product roles. Real Verify / Guardium / QRadar are **not** required for this submission (confirmed with reviewer).

| IBM concept | Role | Lab stand-in |
|-------------|------|----------------|
| **IBM Verify** | Workforce identity, authn, MFA | **Keycloak** (+ webhook receiver) |
| **IBM Guardium** | DB activity / sensitive data | **PostgreSQL** audit JSON / `vram_audit_log` |
| **IBM QRadar** | Security event signals | **Wazuh**-style JSON alerts |
| **OpenShift** | Hybrid-cloud runtime (IBM/Red Hat ecosystem) | Deployment on OpenShift + optional custom domain |
| **VRAM** | Cross-source reasoning + investigator UX | Python reasoner + browser dashboard |

**Demo one-liner:**  
*Telemetry that would typically surface in a Verify / Guardium / QRadar-style stack is normalised into Observations; VRAM maintains context and shows how investigator confidence changes as evidence accumulates.*

Detailed mapping: `docs/PATHWAY_MAPPING.md`.

---

## 3. Case study — South Africa (Healthcare)

**Fictional organisation:** CapeLink Regional Health Network (Western Cape framing).  
**Regulatory note:** POPIA-aware handling of health information; all demo data is **synthetic**.

**Primary scenario:** Workforce account `alice` progresses from EHR portal login → privileged host activity → `patient_records` access → large retrieval → external connection. Hypothesis: **Possible PHI Exfiltration**.

**Secondary:** False-positive path with MFA and normal encounter-level access (confidence decreases).

Full write-up: `docs/CASE_STUDY_SOUTH_AFRICA.md`.

---

## 4. Live deployment (working)

### 4.1 Application URLs

| Environment | URL | Notes |
|-------------|-----|--------|
| **Custom domain (preferred demo)** | https://hersaspace.dpdns.org/ | Cloudflare → OpenShift |
| Health | https://hersaspace.dpdns.org/health | JSON health check |
| API docs | https://hersaspace.dpdns.org/docs | OpenAPI / Swagger |
| Dashboard | https://hersaspace.dpdns.org/ | Investigator UI |
| **OpenShift default host** | `https://vram-6lackrose-dev.apps.rm3.7wse.p1.openshiftapps.com` (or current Route) | May differ if Route was recreated with custom host only |

> If the custom host Route is active, the default `*.apps...` name may no longer serve the app; use **hersaspace.dpdns.org** for demos.

### 4.2 OpenShift

| Item | Value |
|------|--------|
| Cluster | Red Hat OpenShift (e.g. Service on AWS / sandbox) |
| Project | `6lackrose-dev` |
| Image | `quay.io/6lackrose/vram:latest` |
| Workloads | Deployment `vram`, Service `vram` (port **8000**), Route `vram` |
| Container | Uvicorn `api.server:app` on `0.0.0.0:8000` |

### 4.3 Custom domain routing (hersaspace.dpdns.org)

Traffic path:

```text
Browser (HTTPS)
    → Cloudflare (proxied CNAME, SSL Flexible or Full)
        → OpenShift router
            → Route host: hersaspace.dpdns.org (edge TLS optional)
                → Service vram:8000
                    → Pod (Uvicorn / VRAM dashboard + API)
```

**DNS (Cloudflare):**

| Type | Name | Target | Proxy |
|------|------|--------|--------|
| CNAME | `hersaspace` (or zone apex as configured) | OpenShift router / apps host (e.g. `router-default.apps.rm3.7wse.p1.openshiftapps.com` or the cluster apps hostname) | **Proxied** (orange cloud) |

**OpenShift Route (example):**

```bash
oc create route edge vram \
  --service=vram \
  --port=8000 \
  --hostname=hersaspace.dpdns.org \
  --insecure-policy=Redirect
```

**Why Cloudflare:** Provides a stable HTTPS name for reviewers; avoids browser issues when the raw OpenShift cert does not match a custom hostname; Brave/others that force HTTPS work cleanly on the custom domain.

**Disconnect after demo:**

1. Delete the Cloudflare CNAME (or disable the record).  
2. Optionally: `oc delete route vram` / `oc delete deployment vram svc vram`.  
3. DNS TTL may take a few minutes to clear.

### 4.4 Image registry

- **Quay.io:** `quay.io/6lackrose/vram:latest`  
- Built from project `Dockerfile` (`uvicorn` on port 8000).  
- Console “connect Quay” integration may be unavailable (Red Hat UI 404); **public image** or manual pull secret is sufficient.

### 4.5 Local / Docker (backup)

```bash
cd vram
docker build -t vram:latest .
docker run --rm -p 8000:8000 vram:latest
# http://127.0.0.1:8000/
```

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn api.server:app --host 0.0.0.0 --port 8000
python main.py --scenario exfiltration --dashboard
```

---

## 5. How to operate the demo (10–15 min)

Script: `docs/DEMO_SCRIPT.md`.

1. Open https://hersaspace.dpdns.org/  
2. Select **PHI Exfiltration (SA)** → **Run scenario** (step-through shows mid-run predictions).  
3. Point out multi-source events, **Possible PHI Exfiltration**, confidence, narrative, predictions.  
4. Optional: **Reset** → **False positive** (MFA cooling).  
5. Mention pathway mapping and synthetic SA healthcare case study.

**CLI backup:**

```bash
python main.py --scenario exfiltration --dashboard
python main.py --scenario false-positive --dashboard
```

---

## 6. Architecture & code layout

```text
vram/
├── DOCUMENTATION.md          ← this file
├── README.md
├── Dockerfile
├── docker-compose.yml        ← optional lab Postgres/Keycloak
├── main.py                   ← CLI scenarios + terminal dashboard
├── config.py
├── api/
│   ├── server.py             ← FastAPI + /demo + webhooks
│   └── static/dashboard.html ← browser investigator UI
├── engine/                   ← reasoner, memory, rules, confidence, predictor, narrative
├── models/                   ← Observation, Hypothesis, Prediction
├── inputs/                   ← keycloak, wazuh, postgres, webhook, pgaudit listener
├── outputs/                  ← terminal dashboard, timeline, alerts
├── simulator/events.py       ← SA healthcare synthetic scenarios
├── storage/                  ← SQLite (in-memory default)
├── lab/init-db.sql           ← synthetic clinical schema + vram_audit_log
├── deploy/openshift/         ← Deployment, Service, Route manifests
├── docs/
│   ├── CASE_STUDY_SOUTH_AFRICA.md
│   ├── PATHWAY_MAPPING.md
│   ├── DEMO_SCRIPT.md
│   └── RUNBOOK.md
└── tests/                    ← unit + integration (pytest)
```

**Normalisation:** External event → adapter → **Observation** → memory → rules/hypotheses. Source-specific JSON never enters the core reasoner.

---

## 7. Essential companion docs

| Document | Purpose |
|----------|---------|
| `docs/CASE_STUDY_SOUTH_AFRICA.md` | Sector, country, fictional hospital, POPIA framing |
| `docs/PATHWAY_MAPPING.md` | IBM ↔ lab component mapping |
| `docs/DEMO_SCRIPT.md` | Timed 10–15 min walkthrough |
| `docs/RUNBOOK.md` | Local / Docker / listener commands |
| `deploy/openshift/README.md` | Optional cluster deploy notes |
| `README.md` | Quick start and feature overview |

---

## 8. Scenarios

| CLI / UI name | Intent |
|---------------|--------|
| `exfiltration` | SA healthcare — possible PHI exfiltration (primary) |
| `false-positive` | MFA + normal activity reduces confidence |
| `credential-abuse` | Workforce login failures then success |
| `normal` | Benign clinical activity |

Hypothesis title for sensitive data path: **Possible PHI Exfiltration**.

---

## 9. API surface (summary)

| Endpoint | Role |
|----------|------|
| `GET /` `GET /dashboard` | Browser dashboard |
| `GET /health` | Health |
| `GET /docs` | OpenAPI UI |
| `POST /events` | Normalised event |
| `POST /events/keycloak` `.../wazuh` `.../postgres` | Raw lab events |
| `POST /webhooks/keycloak` | Identity webhook |
| `GET /events` `GET /hypotheses` `GET /predictions` | State |
| `GET /timeline/{id}` | Investigation timeline |
| `POST /demo/{scenario}` | Synthetic run (`mode=all` or `queue`) |
| `POST /demo/reset` | Clear in-memory state |

---

## 10. Design principles

1. Modular adapters and engine  
2. Explainable, evidence-backed hypotheses  
3. Deterministic reasoning (no ML/LLM in V1)  
4. Confidence can increase **or** decrease  
5. Observations are not silently dropped  
6. Defensive / educational use; synthetic data only  

---

## 11. Environment notes & limitations

- **TechZone:** Not required if OpenShift (or Docker) demo is live; capacity/links may fail — external OpenShift + custom domain is an accepted path when explained.  
- **Sandbox idle:** Pods may sleep after long idle; before a live review run `oc rollout restart deployment/vram` or hit the URL once.  
- **Lab Postgres:** Optional; host port **5433** in compose to avoid clashing with other local DBs.  
- **Secrets:** Do not commit `oc` tokens, Quay passwords, or kubeconfigs. Public demo URLs and synthetic data only.  

---

## 12. Submission checklist

- [x] Working build (OpenShift + https://hersaspace.dpdns.org)  
- [x] Pathway / sector / audience feature documented  
- [x] SA healthcare case study  
- [x] Investigator dashboard demo path  
- [x] IBM likeness mapping (hybrid lab)  
- [x] OpenShift manifests + Quay image  
- [x] Custom domain via Cloudflare  
- [x] Tests (`python -m pytest`)  
- [ ] Live 10–15 min demo (use `docs/DEMO_SCRIPT.md`)  
- [ ] After demo: optional DNS/Route teardown  

---

## 13. Quick verification commands

```bash
# Cluster
oc project 6lackrose-dev
oc get pods,svc,route
oc logs deployment/vram --tail=30

# Public
curl -sS https://hersaspace.dpdns.org/health

# Local tests
cd vram && python -m pytest -q
```

---

## 14. Acknowledgements

Development and deployment guidance included iterative lab design, multi-source adapters, browser dashboard, OpenShift/Quay/Cloudflare routing, and Cornerstone alignment (pathway, South Africa healthcare case study, documentation pack).

---

*VRAM — research / educational prototype. Defensive use only. Synthetic data only. Author: https://github.com/hersaintel*
