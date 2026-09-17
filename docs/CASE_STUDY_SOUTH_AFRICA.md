# Case study — South Africa (Healthcare)

**Project:** VRAM (Virtual Reasoning & Adaptive Memory)  
**Pathway:** IBM security architecture concepts (Verify / Guardium / QRadar roles)  
**Sector:** Healthcare  
**Country:** South Africa  
**Audience feature:** Investigator-facing contextual dashboard  

> All identities, facilities, and clinical records in this case study are **synthetic**. No real patient data is used.

---

## Context

South African public and private healthcare providers operate under the **Protection of Personal Information Act (POPIA)** and sector guidance on health information. Hospitals and clinic groups typically combine:

- **Workforce identity** (staff login to clinical systems)
- **Endpoint / host security** (workstations, jump hosts, application servers)
- **Clinical databases** (EHR / patient administration / results stores)

Security operations often receive **isolated alerts** from each layer. A single failed login, a sudo event, or a large SQL result set may look benign alone. A **sequence** tied to the same workforce identity can indicate emerging **unauthorised access to personal health information (PHI)**.

VRAM addresses that **context gap**: it keeps memory across sources, updates hypotheses and confidence as evidence accumulates, and presents an explainable narrative for an investigator — without replacing identity, DAM, or SIEM products.

---

## Fictional organisation

| Field | Value |
|-------|--------|
| Organisation | **CapeLink Regional Health Network** (fictional) |
| Region | Western Cape, South Africa (fictional campus) |
| Systems | `ehr-portal` (clinical access), `ehr_lab` database, hosts `ehr-app-01`, clinic workstations |
| Oversight | Security operations / information governance (investigator persona) |

---

## Actors (synthetic)

| ID | Role | Notes |
|----|------|--------|
| `alice` | Clinical / technical staff account (synthetic) | Used in primary “possible PHI exfiltration” scenario |
| `jordan.lee` | Physician (synthetic) | Normal clinical activity scenario |
| `carol` | Staff account (synthetic) | False-positive / MFA cooling scenario |

---

## Primary incident narrative (demo)

1. **Identity:** `alice` authenticates to `ehr-portal` (Keycloak ≈ Verify-style identity).  
2. **Endpoint:** Privileged activity on `ehr-app-01` (Wazuh ≈ QRadar-style security signal).  
3. **Database:** Access to `patient_records` in `ehr_lab` (PostgreSQL audit ≈ Guardium-style DAM).  
4. **Volume:** Large retrieval (~30,000 rows) from sensitive clinical tables.  
5. **Network:** Unusual external connection from the same host context.  
6. **VRAM:** Hypothesis **Possible PHI Exfiltration** rises in confidence; investigator dashboard shows timeline, evidence, prediction, and narrative.

A second scenario shows **confidence reduction** after MFA and normal encounter-level access (false positive path).

---

## Why South Africa / healthcare (and portability)

The **security gap** (missing cross-source reasoning layer) is not country-specific. The same VRAM pattern can frame fintech, edtech, agritech, or retail. This submission anchors the **case study and data labels** in **South African healthcare + POPIA-aware sensitive data handling** (synthetic only) so the build is clearly sector-grounded for Cornerstone assessment.

---

## Alignment to Cornerstone choices

| Choice | This submission |
|--------|-----------------|
| Pathway | Security — architecture mirrored by lab telemetry + OpenShift when available |
| Sector | Healthcare |
| Country | South Africa |
| Audience feature | Investigator contextual dashboard |
| Team | Solo |
