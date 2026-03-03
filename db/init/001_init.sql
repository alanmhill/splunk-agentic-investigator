CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS episodes (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMPTZ DEFAULT now(),
  scenario TEXT,
  src_ip TEXT,
  user_name TEXT,
  severity INT,
  summary TEXT,
  embedding vector(1536)  -- placeholder size for now
);

CREATE TABLE IF NOT EXISTS recommendations (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMPTZ DEFAULT now(),
  episode_id BIGINT REFERENCES episodes(id) ON DELETE CASCADE,
  recommendation TEXT,
  confidence NUMERIC(4,3),
  next_queries JSONB
);

-- Raw ingest layer from Splunk soc_notables
CREATE TABLE IF NOT EXISTS soc_notables (
  id BIGSERIAL PRIMARY KEY,
  ingested_at TIMESTAMPTZ DEFAULT now(),

  -- identity
  notable_key TEXT UNIQUE NOT NULL,
  notable_time TIMESTAMPTZ NOT NULL,

  -- detection metadata
  category TEXT,
  detection_id TEXT,
  detection_name TEXT,
  severity TEXT,
  risk_score INT,
  result_count INT,

  -- top-level extracted fields for dashboards
  src_ip TEXT,
  dest_host TEXT,
  users TEXT,
  metric_name TEXT,
  metric_value INT,

  -- full raw payload for traceability
  payload JSONB
);

CREATE INDEX idx_soc_notables_time ON soc_notables (notable_time);
CREATE INDEX idx_soc_notables_detection ON soc_notables (detection_id);
CREATE INDEX idx_soc_notables_src_ip ON soc_notables (src_ip);
CREATE INDEX idx_soc_notables_dest_host ON soc_notables (dest_host);

CREATE TABLE IF NOT EXISTS soc_evidence (
  id BIGSERIAL PRIMARY KEY,
  ingested_at TIMESTAMPTZ DEFAULT now(),

  -- join back to soc_notables
  notable_key TEXT NOT NULL,
  notable_time TIMESTAMPTZ NOT NULL,

  detection_id TEXT,
  src_ip TEXT,
  dest_host TEXT,

  metric_name TEXT,
  metric_value INT,

  users JSONB,

  -- idempotency for evidence rows
  evidence_key TEXT UNIQUE NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_soc_evidence_time ON soc_evidence (notable_time);
CREATE INDEX IF NOT EXISTS idx_soc_evidence_detection ON soc_evidence (detection_id);
CREATE INDEX IF NOT EXISTS idx_soc_evidence_src_ip ON soc_evidence (src_ip);
CREATE INDEX IF NOT EXISTS idx_soc_evidence_dest_host ON soc_evidence (dest_host);