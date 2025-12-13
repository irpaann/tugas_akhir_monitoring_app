-- ============================
-- TABLE: logs
-- ============================
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    ip TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status INTEGER NOT NULL,
    payload_preview TEXT,
    user_agent TEXT,
    threat_score INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs (timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_ip ON logs (ip);


-- ============================
-- TABLE: threats
-- ============================
CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    ip TEXT NOT NULL,
    type TEXT NOT NULL,
    description TEXT,
    payload TEXT,
    threat_score INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats (timestamp);
CREATE INDEX IF NOT EXISTS idx_threats_ip ON threats (ip);


-- ============================
-- TABLE: blocked_ips
-- ============================
CREATE TABLE IF NOT EXISTS blocked_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    reason TEXT,
    blocked_at DATETIME NOT NULL,
    total_attacks INTEGER DEFAULT 0
);


-- ============================
-- TABLE: config
-- ============================
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT
);

INSERT OR IGNORE INTO config (key, value) VALUES ('log_retention_days', '30');
INSERT OR IGNORE INTO config (key, value) VALUES ('dashboard_refresh', '10');
INSERT OR IGNORE INTO config (key, value) VALUES ('threat_threshold', '60');
INSERT OR IGNORE INTO config (key, value) VALUES ('admin_user', 'admin');
INSERT OR IGNORE INTO config (key, value) VALUES ('admin_pass', '');

