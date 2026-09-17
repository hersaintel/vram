# Pathway mapping — VRAM Cornerstone

**Pathway:** IBM security concepts (Verify / Guardium / QRadar roles)  
**Sector / country:** Healthcare — South Africa (synthetic; see `CASE_STUDY_SOUTH_AFRICA.md`)  
**Audience feature:** Investigator-facing contextual dashboard  

VRAM does **not** reimplement IBM products. Lab components **mirror** the telemetry roles those products play. The “missing layer” is cross-source **memory → hypothesis → confidence → narrative**.

| IBM concept | Architectural role | Lab stand-in | Example in demo |
|-------------|-------------------|--------------|-----------------|
| **IBM Verify** | Workforce identity, authn, MFA | **Keycloak** (+ `/webhooks/keycloak`) | LOGIN to `ehr-portal`, MFA |
| **IBM Guardium** | Database activity / sensitive data | **PostgreSQL** audit JSON / `vram_audit_log` | SELECT on `patient_records` |
| **IBM QRadar** | Security event signals | **Wazuh**-style JSON | Privilege escalation, external connection |
| **OpenShift** (optional deploy) | IBM/Red Hat hybrid cloud runtime | Deployment + Service + Route | Live dashboard URL for reviewers |
| **VRAM** | Reasoning & investigation UX | Python reasoner + browser UI | Possible PHI Exfiltration + narrative |

## Demo one-liner for reviewers

> “Identity, database, and security events that would typically surface in a Verify / Guardium / QRadar-style stack are normalised into VRAM Observations. VRAM maintains context and shows how investigator confidence changes as evidence accumulates — the layer those tools do not fully provide on their own.”
