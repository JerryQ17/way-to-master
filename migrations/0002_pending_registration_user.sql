DROP INDEX IF EXISTS idx_challenges_expiry;

CREATE TABLE challenges_v2 (
	challenge TEXT PRIMARY KEY NOT NULL,
	purpose TEXT NOT NULL CHECK (purpose IN ('registration', 'authentication')),
	user_id TEXT,
	display_name TEXT,
	expires_at INTEGER NOT NULL,
	consumed_at INTEGER,
	created_at INTEGER NOT NULL
);

INSERT INTO challenges_v2 (challenge, purpose, user_id, display_name, expires_at, consumed_at, created_at)
SELECT challenge, purpose, user_id, display_name, expires_at, consumed_at, created_at
FROM challenges;

DROP TABLE challenges;
ALTER TABLE challenges_v2 RENAME TO challenges;

CREATE INDEX idx_challenges_expiry ON challenges(expires_at);