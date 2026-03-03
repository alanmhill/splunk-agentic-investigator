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
  notable_time TIMESTAMPTZ,
  detection_id TEXT,
  detection_name TEXT,
  severity TEXT,
  risk_score INT,
  src_ip TEXT,
  user_name TEXT,
  payload JSONB,
  notable_key TEXT UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_soc_notables_time ON soc_notables (notable_time);
CREATE INDEX IF NOT EXISTS idx_soc_notables_detection ON soc_notables (detection_id);
CREATE INDEX IF NOT EXISTS idx_soc_notables_src_ip ON soc_notables (src_ip);