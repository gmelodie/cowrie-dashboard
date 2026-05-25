CREATE TABLE IF NOT EXISTS sensors (
    id SERIAL PRIMARY KEY,
    ip VARCHAR(45) UNIQUE
);

-- Pre-seed the sensor row so cowrie's SELECT hits it and avoids the broken INSERT path
INSERT INTO sensors (ip) VALUES ('cowrie') ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS clients (
    id SERIAL PRIMARY KEY,
    version VARCHAR(50),
    "timestamp" TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions (
    id CHAR(32) PRIMARY KEY,
    starttime TIMESTAMP WITH TIME ZONE,
    endtime TIMESTAMP WITH TIME ZONE,
    sensor INTEGER REFERENCES sensors(id),
    ip VARCHAR(45),
    termsize VARCHAR(7) DEFAULT '',
    client INTEGER REFERENCES clients(id),
    protocol VARCHAR(8) DEFAULT 'ssh'
);

-- Existing schemas pre-date the protocol column; backfill assumes legacy SSH-only data.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS protocol VARCHAR(8) DEFAULT 'ssh';

CREATE TABLE IF NOT EXISTS auth (
    id SERIAL PRIMARY KEY,
    session CHAR(32) REFERENCES sessions(id),
    success BOOLEAN DEFAULT FALSE,
    username TEXT,
    password TEXT,
    "timestamp" TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS input (
    id SERIAL PRIMARY KEY,
    session CHAR(32) REFERENCES sessions(id),
    "timestamp" TIMESTAMP WITH TIME ZONE,
    realm VARCHAR(20),
    input TEXT,
    success BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS ttylog (
    id SERIAL PRIMARY KEY,
    session CHAR(32) REFERENCES sessions(id),
    ttylog VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS downloads (
    id SERIAL PRIMARY KEY,
    session CHAR(32) REFERENCES sessions(id),
    "timestamp" TIMESTAMP WITH TIME ZONE,
    url TEXT,
    outfile TEXT,
    shasum VARCHAR(64)
);

CREATE TABLE IF NOT EXISTS keyfingerprints (
    id SERIAL PRIMARY KEY,
    session CHAR(32) REFERENCES sessions(id),
    username TEXT,
    fingerprint VARCHAR(100)
);

DROP TABLE IF EXISTS web_form_submissions;
DROP TABLE IF EXISTS web_visits;

-- ── Geo/ASN enrichment ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ip_geo_cache (
    ip           VARCHAR(45) PRIMARY KEY,
    country_iso  CHAR(2),
    country_name VARCHAR(64),
    asn          INTEGER,
    asn_org      VARCHAR(128),
    looked_up_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS campaign_events (
    id                     SERIAL PRIMARY KEY,
    detected_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    onset_time             TIMESTAMPTZ NOT NULL,
    z_score                NUMERIC(6,2),
    spike_ratio            NUMERIC(5,3),
    new_asn_count          INTEGER,
    peak_rate_per_hour     NUMERIC(10,2),
    baseline_rate_per_hour NUMERIC(10,2),
    new_asns               JSONB,
    top_pairs              JSONB,
    credential_pattern     VARCHAR(16),
    active                 BOOLEAN DEFAULT TRUE,
    CONSTRAINT campaign_events_onset_unique UNIQUE (onset_time)
);

CREATE INDEX IF NOT EXISTS sessions_ip_idx       ON sessions (ip);
CREATE INDEX IF NOT EXISTS sessions_protocol_idx ON sessions (protocol);

-- ── Federation ────────────────────────────────────────────────────────────────
-- See honey/ for the Rust binary that drives these tables.

CREATE TABLE IF NOT EXISTS federation_peers (
    fingerprint       TEXT PRIMARY KEY,
    pubkey_b64        TEXT        NOT NULL,
    url               TEXT        NOT NULL,
    node_name         TEXT        NOT NULL DEFAULT '',
    contact           TEXT        NOT NULL DEFAULT '',
    status            TEXT        NOT NULL DEFAULT 'trusted',   -- trusted | revoked
    they_approved_us  BOOLEAN     NOT NULL DEFAULT FALSE,
    we_approved_them  BOOLEAN     NOT NULL DEFAULT FALSE,
    local_score       INTEGER     NOT NULL DEFAULT 0,
    added_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen         TIMESTAMPTZ,
    last_pull_at      TIMESTAMPTZ,
    entries_received  BIGINT      NOT NULL DEFAULT 0,
    bad_signatures    BIGINT      NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS federation_pending_requests (
    fingerprint  TEXT PRIMARY KEY,
    pubkey_b64   TEXT        NOT NULL,
    url          TEXT        NOT NULL,
    node_name    TEXT        NOT NULL DEFAULT '',
    contact      TEXT        NOT NULL DEFAULT '',
    description  TEXT        NOT NULL DEFAULT '',
    received_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- INVARIANT: rows here are ALWAYS from peers; /wordlist/fetch never serves them.
-- Local observations live in `auth`. Do not "optimise" by merging.
CREATE TABLE IF NOT EXISTS federated_wordlist_entries (
    id                  BIGSERIAL PRIMARY KEY,
    username            TEXT        NOT NULL,
    password            TEXT        NOT NULL,
    source_fingerprint  TEXT        NOT NULL
                                    REFERENCES federation_peers(fingerprint)
                                    ON DELETE CASCADE,
    count               BIGINT      NOT NULL DEFAULT 1,
    first_seen          TIMESTAMPTZ NOT NULL,
    last_seen           TIMESTAMPTZ NOT NULL,
    UNIQUE (username, password, source_fingerprint)
);
CREATE INDEX IF NOT EXISTS fwle_last_seen_idx ON federated_wordlist_entries (last_seen);
CREATE INDEX IF NOT EXISTS fwle_source_idx    ON federated_wordlist_entries (source_fingerprint);

CREATE TABLE IF NOT EXISTS federation_seen_nonces (
    nonce       TEXT PRIMARY KEY,
    sender      TEXT        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS fsn_exp_idx ON federation_seen_nonces (expires_at);
