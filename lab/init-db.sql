-- Synthetic healthcare lab schema — NO real personal data (PHI is fictional)
-- Cornerstone sector framing: Healthcare

CREATE TABLE IF NOT EXISTS staff (
    id SERIAL PRIMARY KEY,
    staff_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    role TEXT,
    department TEXT,
    email TEXT
);

CREATE TABLE IF NOT EXISTS patients (
    id SERIAL PRIMARY KEY,
    mrn TEXT NOT NULL,
    display_name TEXT NOT NULL,
    ward TEXT
);

CREATE TABLE IF NOT EXISTS encounters (
    id SERIAL PRIMARY KEY,
    patient_id INT REFERENCES patients(id),
    encounter_type TEXT,
    department TEXT,
    status TEXT
);

-- Sensitive clinical / PHI-style table (synthetic rows only)
CREATE TABLE IF NOT EXISTS patient_records (
    id SERIAL PRIMARY KEY,
    patient_id INT REFERENCES patients(id),
    record_type TEXT,
    summary TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_test (
    id SERIAL PRIMARY KEY,
    note TEXT
);

INSERT INTO staff (staff_id, display_name, role, department, email) VALUES
  ('S-1001', 'Alex Rivera', 'Registered Nurse', 'Ward A', 'alex.rivera@example.healthcare.local'),
  ('S-1002', 'Jordan Lee', 'Physician', 'Cardiology', 'jordan.lee@example.healthcare.local'),
  ('S-1003', 'Sam Okonkwo', 'Health Information Clerk', 'HIM', 'sam.okonkwo@example.healthcare.local')
ON CONFLICT DO NOTHING;

INSERT INTO patients (mrn, display_name, ward) VALUES
  ('MRN-90001', 'Patient A', 'Ward A'),
  ('MRN-90002', 'Patient B', 'Ward B'),
  ('MRN-90003', 'Patient C', 'ICU')
ON CONFLICT DO NOTHING;

INSERT INTO encounters (patient_id, encounter_type, department, status) VALUES
  (1, 'inpatient', 'Ward A', 'active'),
  (2, 'outpatient', 'Clinic', 'closed'),
  (3, 'inpatient', 'ICU', 'active');

INSERT INTO patient_records (patient_id, record_type, summary) VALUES
  (1, 'lab_result', 'Synthetic lab panel summary'),
  (1, 'medication', 'Synthetic medication list'),
  (2, 'imaging', 'Synthetic imaging note'),
  (3, 'discharge', 'Synthetic discharge summary');

-- VRAM audit log table for live pgaudit-style polling
CREATE TABLE IF NOT EXISTS vram_audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_time TIMESTAMPTZ DEFAULT NOW(),
    usename TEXT,
    session_user TEXT,
    dbname TEXT,
    client_addr INET,
    command TEXT,
    object_name TEXT,
    row_count BIGINT,
    statement TEXT,
    role TEXT
);

CREATE INDEX IF NOT EXISTS idx_vram_audit_id ON vram_audit_log(id);

INSERT INTO vram_audit_log (usename, dbname, client_addr, command, object_name, row_count, statement)
VALUES
  ('jordan.lee', 'ehr_lab', '10.0.1.42', 'SELECT', 'encounters', 5, 'SELECT * FROM encounters LIMIT 5'),
  ('alex.rivera', 'ehr_lab', '10.0.0.25', 'SELECT', 'patient_records', 30000, 'SELECT * FROM patient_records');