-- =====================================================
-- WBS 6.0.0 Sqlite database schema
-- =====================================================
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;  -- Better concurrency for multiprocessing
PRAGMA user_version = 3;    -- Schema version for migrations


-- Users
CREATE TABLE IF NOT EXISTS users (
    handle TEXT PRIMARY KEY,
    password TEXT DEFAULT NULL,                  -- bcrypt hash
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
    subnet_id INTEGER DEFAULT NULL,
    has_partyline BOOLEAN DEFAULT 0,
    is_admin BOOLEAN DEFAULT 0,
    is_bot BOOLEAN DEFAULT 0,
    is_op BOOLEAN DEFAULT 0,
    is_deop BOOLEAN DEFAULT 0,
    is_voice BOOLEAN DEFAULT 0,
    is_devoice BOOLEAN DEFAULT 0,
    is_friend BOOLEAN DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER DEFAULT (strftime('%s', 'now')),
    created_by TEXT DEFAULT NULL,
    updated_by TEXT DEFAULT NULL,
    
    PRIMARY KEY(handle, channel),
    FOREIGN KEY(handle) REFERENCES users(handle) ON DELETE CASCADE,
    FOREIGN KEY(subnet_id) REFERENCES subnets(id) ON DELETE SET NULL
);

-- Bots
CREATE TABLE IF NOT EXISTS bots (
    handle TEXT PRIMARY KEY,
    address TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 3333,
    role TEXT CHECK(role IN ('hub', 'backup', 'leaf', 'none')) DEFAULT 'none',
    subnet_id INTEGER,
    share_level TEXT DEFAULT 'full', -- full/subnet/none
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY(subnet_id) REFERENCES subnets(id) ON DELETE SET NULL
);

-- Subnets
CREATE TABLE IF NOT EXISTS subnets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    created_by TEXT DEFAULT NULL
);

-- Channels
CREATE TABLE IF NOT EXISTS channels (
    name TEXT PRIMARY KEY,
    subnet_id INTEGER DEFAULT NULL,
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
    is_pubcom BOOLEAN DEFAULT 0,
    is_news BOOLEAN DEFAULT 0,
    is_url BOOLEAN DEFAULT 0,
    is_stats BOOLEAN DEFAULT 0,
    is_lock BOOLEAN DEFAULT 0,      -- CHANLOCK
    lock_by TEXT DEFAULT '',
    lock_at INTEGER DEFAULT 0,
    lock_reason TEXT DEFAULT '',
    is_topiclock BOOLEAN DEFAULT 0, -- TOPICLOCK
    topiclock TEXT DEFAULT '',
    topiclock_by TEXT DEFAULT '',
    topiclock_at INTEGER DEFAULT 0,
    topiclock_reason TEXT DEFAULT '',
    is_limit BOOLEAN DEFAULT 0,     -- LIMIT
    limit_add INTEGER DEFAULT 15,
    limit_rand INTEGER DEFAULT 200,
    limit_tolerance INTEGER DEFAULT 2,
    limit_delta INTEGER DEFAULT 300,
    limit_at INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER DEFAULT (strftime('%s', 'now')),
    created_by TEXT DEFAULT NULL,
    updated_by TEXT DEFAULT NULL,

    FOREIGN KEY(subnet_id) REFERENCES subnets(id) ON DELETE CASCADE
);

-- Runtime
CREATE TABLE IF NOT EXISTS runtime (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    expires_at INTEGER DEFAULT 0
);

-- =====================================================
-- TRACKING & STATS
-- =====================================================

-- Seen
CREATE TABLE IF NOT EXISTS seen (
    nick TEXT NOT NULL,
    handle TEXT,                    -- Matched user handle (if authed)
    channel TEXT,
    action TEXT CHECK(action IN ('JOIN','PART','QUIT','KICK','NICK','MSG','PUBMSG')),
    hostmask TEXT,
    message TEXT DEFAULT '',
    user_agent TEXT DEFAULT '',
    last_seen INTEGER NOT NULL,
    PRIMARY KEY(nick, channel, last_seen)
);

-- =====================================================
-- INDEXES (Optimized for Hot Paths)
-- =====================================================

-- Users & Access
CREATE INDEX IF NOT EXISTS idx_users_hostmasks ON users(hostmasks);
CREATE INDEX IF NOT EXISTS idx_user_access_handle_chan ON user_access(handle, channel);
CREATE INDEX IF NOT EXISTS idx_user_access_channel_handle ON user_access(channel, handle);
CREATE INDEX IF NOT EXISTS idx_user_access_subnet ON user_access(subnet_id);

-- Channels 
CREATE INDEX IF NOT EXISTS idx_channels_subnet_name ON channels(subnet_id, name);
CREATE INDEX IF NOT EXISTS idx_channels_name_subnet ON channels(name, subnet_id);

-- Runtime
CREATE INDEX IF NOT EXISTS idx_runtime_key ON runtime(key);
CREATE INDEX IF NOT EXISTS idx_runtime_expires ON runtime(expires_at);

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
  UPDATE user_access SET updated_at=strftime('%s','now') 
  WHERE handle=OLD.handle AND channel=OLD.channel;
END;

-- Seen cleanup (30 days, batched)
CREATE TRIGGER IF NOT EXISTS trig_seen_cleanup
AFTER INSERT ON seen
WHEN (SELECT COUNT(*) FROM seen WHERE last_seen<strftime('%s','now')-2592000)>5000
BEGIN
  DELETE FROM seen WHERE last_seen<strftime('%s','now')-2592000;
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