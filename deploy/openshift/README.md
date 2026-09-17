# OpenShift deploy (optional)

Prefer a **working local or external demo** if cluster capacity is limited.

## Prerequisites

- `oc` logged into the cluster  
- Image available to the cluster (`vram:latest` built and pushed, or build on-cluster)

## Build & push (example)

```bash
# From repo root (vram/)
docker build -t vram:latest .

# Tag/push to a registry your cluster can pull, then set image in deployment.yaml
# oc new-build --binary --name=vram
# oc start-build vram --from-dir=. --follow
```

## Deploy

```bash
oc new-project vram-lab --display-name="VRAM Cornerstone" || oc project vram-lab
oc apply -k deploy/openshift/
oc get route vram
```

Open the Route host in a browser for the investigator dashboard.

## If OpenShift is unavailable

Host with Docker or any cloud VM, expose port 8000 (or TLS reverse proxy), and note in the submission:

> Demo runs on [URL]. OpenShift deploy manifests are included under `deploy/openshift/` for pathway alignment when capacity allows.
