-- =====================================================
-- WBS 6.0.0 Sqlite database schema
-- =====================================================
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;  -- Better concurrency for multiprocessing
PRAGMA user_version = 1;    -- Schema version for migrations

-- Subnets
CREATE TABLE IF NOT EXISTS subnets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    created_by TEXT DEFAULT NULL
);

-- Users
CREATE TABLE IF NOT EXISTS users (
    handle TEXT PRIMARY KEY,
    password TEXT DEFAULT NULL,     -- bcrypt hash
    hostmasks TEXT DEFAULT '[]',    -- JSON array ["*!*@host1", "*!user@host2"]
    is_locked BOOLEAN DEFAULT 0,
    comment TEXT DEFAULT '',
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER DEFAULT (strftime('%s', 'now')),
    created_by TEXT DEFAULT NULL,
    updated_by TEXT DEFAULT NULL
);

-- User access
CREATE TABLE IF NOT EXISTS user_access (
    handle TEXT NOT NULL,
    channel TEXT DEFAULT NULL,
    has_partyline BOOLEAN DEFAULT 0,
    is_admin BOOLEAN DEFAULT 0,       -- +A - Botnet Admin
    is_owner BOOLEAN DEFAULT 0,       -- +n - Bot Owner
    is_friend BOOLEAN DEFAULT 0,      -- +f
    is_autoop BOOLEAN DEFAULT 0,      -- +a - auto op
    is_op BOOLEAN DEFAULT 0,          -- +o - op
    is_deop BOOLEAN DEFAULT 0,        -- +d - remove op
    is_autohop BOOLEAN DEFAULT 0,     -- +y - auto half op
    is_hop BOOLEAN DEFAULT 0,         -- +l - halfop
    is_dehop BOOLEAN DEFAULT 0,       -- +r - remove halfop
    is_voice BOOLEAN DEFAULT 0,       -- +v - voice
    is_devoice BOOLEAN DEFAULT 0,     -- +q - remove voice
    is_autokick BOOLEAN DEFAULT 0,    -- +k - auto kick/ban
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER DEFAULT (strftime('%s', 'now')),
    created_by TEXT DEFAULT NULL,
    updated_by TEXT DEFAULT NULL,
    last_seen TIMESTAMP DEFAULT NULL,
    subnet_id INTEGER DEFAULT NULL, -- NULL = all subnets, <id> = subnet-scoped
    PRIMARY KEY (handle, channel, subnet_id), 
    FOREIGN KEY (handle)    REFERENCES users(handle)  ON DELETE CASCADE,
    FOREIGN KEY (subnet_id) REFERENCES subnets(id)    ON DELETE SET NULL
);

-- Bots
CREATE TABLE IF NOT EXISTS bots (
    handle TEXT PRIMARY KEY,
    password TEXT DEFAULT NULL,
    hostmasks TEXT DEFAULT '[]',
    address TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 3333,
    role TEXT CHECK(role IN ('hub', 'backup', 'leaf', 'none')) DEFAULT 'none',
    share_level TEXT DEFAULT 'subnet', -- full/subnet/none
    comment TEXT DEFAULT '',
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Bot access
CREATE TABLE IF NOT EXISTS bot_access (
    handle TEXT NOT NULL,
    channel TEXT DEFAULT NULL,
    has_partyline BOOLEAN DEFAULT 0,
    is_friend BOOLEAN DEFAULT 0,
    is_op BOOLEAN DEFAULT 0,
    is_deop BOOLEAN DEFAULT 0,
    is_hop BOOLEAN DEFAULT 0,
    is_dehop BOOLEAN DEFAULT 0,
    is_voice BOOLEAN DEFAULT 0,
    is_devoice BOOLEAN DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER DEFAULT (strftime('%s', 'now')),
    created_by TEXT DEFAULT NULL,
    updated_by TEXT DEFAULT NULL,
    PRIMARY KEY(handle, channel),
    FOREIGN KEY(handle) REFERENCES bots(handle) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS bot_subnets (
    bot_handle   TEXT NOT NULL,
    subnet_id    INTEGER NOT NULL,
    added_at     INTEGER DEFAULT (strftime('%s', 'now')),
    added_by     TEXT DEFAULT NULL,
    PRIMARY KEY (bot_handle, subnet_id),
    FOREIGN KEY (bot_handle) REFERENCES bots(handle) ON DELETE CASCADE,
    FOREIGN KEY (subnet_id)  REFERENCES subnets(id)  ON DELETE CASCADE
);

-- Servers
CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    subnet_id INTEGER DEFAULT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    created_by TEXT DEFAULT NULL
);

-- Channels
CREATE TABLE IF NOT EXISTS channels (
    name TEXT PRIMARY KEY,
    modes TEXT DEFAULT '',
    bans TEXT DEFAULT '[]',         -- JSON ban list
    invites TEXT DEFAULT '[]',      -- JSON invite list  
    exempts TEXT DEFAULT '[]',      -- JSON Ban exemptions
    flood_pub INTEGER DEFAULT 15,
    flood_pub_time INTEGER DEFAULT 60,
    flood_ctcp INTEGER DEFAULT 3,
    flood_ctcp_time INTEGER DEFAULT 60,
    flood_join INTEGER DEFAULT 5,
    flood_join_time INTEGER DEFAULT 60,
    flood_kick INTEGER DEFAULT 3,
    flood_kick_time INTEGER DEFAULT 10,
    flood_deop INTEGER DEFAULT 3,
    flood_deop_time INTEGER DEFAULT 10,
    flood_nick INTEGER DEFAULT 5,
    flood_nick_time INTEGER DEFAULT 60,
    is_bitch BOOLEAN DEFAULT 0,
    is_autoop BOOLEAN DEFAULT 0,
    is_autovoice BOOLEAN DEFAULT 0,
    is_revenge BOOLEAN DEFAULT 0,
    is_revengebots BOOLEAN DEFAULT 0,
    is_protectfriends BOOLEAN DEFAULT 0,
    is_protectops BOOLEAN DEFAULT 0,
    is_dontkickops BOOLEAN DEFAULT 0,
    is_inactive BOOLEAN DEFAULT 0,
    is_enforcebans BOOLEAN DEFAULT 0,
    is_dynamicbans BOOLEAN DEFAULT 0,
    is_dynamicexempts BOOLEAN DEFAULT 0,
    is_dynamicinvites BOOLEAN DEFAULT 0,
    comment TEXT DEFAULT '',
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER DEFAULT (strftime('%s', 'now')),
    created_by TEXT DEFAULT NULL,
    updated_by TEXT DEFAULT NULL
);
CREATE TABLE IF NOT EXISTS channel_subnets (
    channel_name TEXT NOT NULL,
    subnet_id    INTEGER NOT NULL,
    added_at     INTEGER DEFAULT (strftime('%s', 'now')),
    added_by     TEXT DEFAULT NULL,
    PRIMARY KEY (channel_name, subnet_id),
    FOREIGN KEY (channel_name) REFERENCES channels(name) ON DELETE CASCADE,
    FOREIGN KEY (subnet_id)    REFERENCES subnets(id)    ON DELETE CASCADE
);

-- Runtime
CREATE TABLE IF NOT EXISTS runtime (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    expires_at INTEGER DEFAULT 0
);

-- Ignores
CREATE TABLE IF NOT EXISTS ignores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostmask TEXT UNIQUE NOT NULL,
    flags TEXT DEFAULT '',
    comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    creator TEXT NOT NULL
);

-- Loaded modules (plugin or game)
CREATE TABLE IF NOT EXISTS loaded_modules (
    name        TEXT    NOT NULL,
    type        TEXT    NOT NULL CHECK(type IN ('game', 'plugin')),
    scope       TEXT    DEFAULT NULL,   -- channel the game runs on (games only, NULL for plugins)
    owner       TEXT    DEFAULT NULL,   -- nick who started the game
    autoload    BOOLEAN DEFAULT 1,      -- 0 = skip on restart
    loaded_at   INTEGER DEFAULT (strftime('%s','now')),
    PRIMARY KEY (name, type)
);

-- Game session data
CREATE TABLE IF NOT EXISTS game_sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    game_name   TEXT    NOT NULL,
    scope       TEXT    NOT NULL,       -- "channel", "user"
    target      TEXT    NOT NULL,       -- "#chan", nick
    owner       TEXT    DEFAULT NULL,
    state       TEXT    DEFAULT 'running',
    data        TEXT    DEFAULT '{}',   -- JSON blob of session.data
    saved_at    INTEGER DEFAULT (strftime('%s','now')),
    UNIQUE(game_name, scope, target)
);

-- =====================================================
-- INDEXES (Optimized for Hot Paths)
-- =====================================================

-- Users & Access
CREATE INDEX IF NOT EXISTS idx_users_hostmasks ON users(hostmasks);
CREATE INDEX IF NOT EXISTS idx_user_access_handle_chan ON user_access(handle, channel);
CREATE INDEX IF NOT EXISTS idx_user_access_channel_handle ON user_access(channel, handle);
CREATE INDEX IF NOT EXISTS idx_user_access_handle_chan_subnet ON user_access(handle, channel, subnet_id);
CREATE INDEX IF NOT EXISTS idx_user_access_channel_subnet_handle ON user_access(channel, subnet_id, handle);
CREATE INDEX IF NOT EXISTS idx_user_access_subnet ON user_access(subnet_id);
CREATE INDEX IF NOT EXISTS idx_bot_subnets_handle ON bot_subnets(bot_handle);
CREATE INDEX IF NOT EXISTS idx_bot_subnets_subnet ON bot_subnets(subnet_id);

-- Channels 
CREATE INDEX IF NOT EXISTS idx_channel_subnets_channel ON channel_subnets(channel_name);
CREATE INDEX IF NOT EXISTS idx_channel_subnets_subnet ON channel_subnets(subnet_id);

-- Runtime
CREATE INDEX IF NOT EXISTS idx_runtime_key ON runtime(key);
CREATE INDEX IF NOT EXISTS idx_runtime_expires ON runtime(expires_at);

-- Ignores
CREATE INDEX IF NOT EXISTS idx_ignores_hostmask ON ignores(hostmask);

-- Modules
CREATE INDEX IF NOT EXISTS idx_loaded_modules_type   ON loaded_modules(name, type);
CREATE INDEX IF NOT EXISTS idx_game_sessions_lookup  ON game_sessions(game_name, scope, target);

-- =====================================================
-- TRIGGERS - PERFORMANCE & INTEGRITY
-- =====================================================

-- Timestamp auto-update (users/channels/access)
CREATE TRIGGER IF NOT EXISTS trig_users_update_ts
AFTER UPDATE ON users FOR EACH ROW
BEGIN
  UPDATE users SET updated_at=strftime('%s','now') WHERE handle=OLD.handle;
END;

CREATE TRIGGER IF NOT EXISTS trig_channels_update_ts
AFTER UPDATE ON channels FOR EACH ROW
BEGIN
  UPDATE channels SET updated_at=strftime('%s','now') WHERE name=OLD.name;
END;

CREATE TRIGGER IF NOT EXISTS trig_access_update_ts
AFTER UPDATE ON user_access FOR EACH ROW
BEGIN
  UPDATE user_access
  SET updated_at = strftime('%s','now')
  WHERE handle = OLD.handle
    AND channel = OLD.channel
    AND (
      subnet_id = OLD.subnet_id
      OR (subnet_id IS NULL AND OLD.subnet_id IS NULL)
    );
END;

-- Runtime cleanup
CREATE TRIGGER IF NOT EXISTS trig_runtime_cleanup
AFTER INSERT ON runtime
BEGIN
  DELETE FROM runtime WHERE expires_at > 0 AND expires_at < strftime('%s', 'now');
END;

-- Timestamp refresh on update
CREATE TRIGGER IF NOT EXISTS trig_runtime_update_ts
AFTER UPDATE ON runtime FOR EACH ROW
BEGIN
  UPDATE runtime SET updated_at = strftime('%s', 'now') WHERE key = OLD.key;
END;

-- =====================================================
-- POST-DEPLOY OPTIMIZE (run once after load)
-- =====================================================
/*
VACUUM;
ANALYZE;
PRAGMA optimize;
*/