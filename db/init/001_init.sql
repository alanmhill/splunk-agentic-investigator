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