# Runbook — VRAM

## Local

```bash
cd vram
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q
python main.py --scenario exfiltration --dashboard
uvicorn api.server:app --host 0.0.0.0 --port 8000
```

- Dashboard: http://127.0.0.1:8000/  
- API docs: http://127.0.0.1:8000/docs  
- Health: http://127.0.0.1:8000/health  

## Docker

```bash
docker build -t vram:latest .
docker run --rm -p 8000:8000 vram:latest
```

## OpenShift (optional)

See `deploy/openshift/README.md`.

## Lab Postgres (optional)

Host port **5433** (avoids clashing with other local Postgres):

```bash
docker compose up -d postgres
python main.py --listen-pgaudit \
  --dsn postgresql://vram:vram_lab_password@localhost:5433/enterprise
```
