# Demo script — 10–15 minutes

**Case:** CapeLink Regional Health Network (fictional), South Africa  
**Feature:** Investigator contextual dashboard  
**Scenario:** Exfiltration → **Possible PHI Exfiltration**

## Setup

```bash
# Local
uvicorn api.server:app --host 0.0.0.0 --port 8000
# open http://127.0.0.1:8000/

# Or OpenShift Route URL if deployed
```

## Script

| Time | Speak / show |
|------|----------------|
| 0–1 min | **Problem:** POPIA-sensitive health data; siloed identity, endpoint, and DB alerts miss sequences. |
| 1–2 min | **Choices:** Solo, security pathway, Healthcare / South Africa, investigator dashboard. Synthetic data only. |
| 2–3 min | **IBM likeness:** Keycloak≈Verify, Postgres audit≈Guardium, Wazuh≈QRadar; VRAM = reasoning layer. OpenShift if live. |
| 3–10 min | **Live:** Dashboard → Exfiltration → Run scenario. Call out each source and confidence. |
| 10–12 min | Hypothesis **Possible PHI Exfiltration**, timeline, narrative, predictions mid-run. |
| 12–14 min | Optional: False positive + MFA cooling. |
| 14–15 min | Future work; Q&A. |

## Backup CLI

```bash
python main.py --scenario exfiltration --dashboard
python main.py --scenario false-positive --dashboard
```
