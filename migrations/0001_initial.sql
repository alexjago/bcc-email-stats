CREATE TABLE IF NOT EXISTS email_events (
  dedupe_key TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL,
  token_fingerprint TEXT,
  received_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_email_events_campaign_received
  ON email_events(campaign_id, received_at DESC);

CREATE INDEX IF NOT EXISTS idx_email_events_campaign_token
  ON email_events(campaign_id, token_fingerprint)
  WHERE token_fingerprint IS NOT NULL;
