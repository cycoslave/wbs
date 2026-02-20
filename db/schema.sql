-- =====================================================
-- WBS 6.0 ENHANCED SCHEMA (Production-Ready)
-- Multiprocessing-Safe | Full Botnet | Partyline/DCC
-- =====================================================
-- Changes from v6.0:
-- + Schema versioning (migrations)
-- + DCC sessions table (telnet/TLS partyline)
-- + Botnet share granularity (user/chan/ignores)
-- + IRC state tracking (nicknames, mode tracking)
-- + Flood protection tables
-- + Enhanced indexes for hot paths
-- + Additional triggers for data integrity
-- =====================================================

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;  -- Better concurrency for multiprocessing
PRAGMA user_version = 2;    -- Schema version for migrations

-- =====================================================
-- CORE BOTNET TABLES
-- =====================================================

-- Subnets (isolated IRC networks/channel groups)
CREATE TABLE IF NOT EXISTS subnets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    irc_network TEXT DEFAULT '',
    irc_server TEXT DEFAULT '',     -- NEW: Current server (irc.libera.chat:6697)
    irc_ssl BOOLEAN DEFAULT 1,      -- NEW: TLS connection
    channels TEXT DEFAULT '[]',     -- JSON ["#chan1"]
    owner_handle TEXT,
    auto_rejoin BOOLEAN DEFAULT 1,  -- NEW: Auto-rejoin on kick
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY(owner_handle) REFERENCES users(handle) ON DELETE SET NULL
);

-- Bots (Eggdrop-style handles + attributes)
CREATE TABLE IF NOT EXISTS bots (
    handle TEXT PRIMARY KEY,
    address TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 3333,
    role TEXT CHECK(role IN ('hub', 'leaf', 'none')) DEFAULT 'none',
    is_linked BOOLEAN DEFAULT 0,
    is_online BOOLEAN DEFAULT 0,
    subnet_id INTEGER,
    flags TEXT DEFAULT '',          -- +ghplsr (botattr)
    listen_port INTEGER DEFAULT 0,
    last_ping INTEGER DEFAULT 0,
    share_level TEXT DEFAULT 'full', -- full/subnet/none
    share_flags TEXT DEFAULT 'ucbgi', -- NEW: u=users c=chans b=bans g=global i=ignores
    version TEXT DEFAULT 'WBS6.0',
    uptime_start INTEGER DEFAULT 0, -- NEW: Track actual uptime
    nick TEXT DEFAULT '',           -- NEW: Current IRC nickname
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY(subnet_id) REFERENCES subnets(id) ON DELETE SET NULL
);

-- Bot links (bidirectional hub<->leaf relationships)
CREATE TABLE IF NOT EXISTS bot_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bot_handle TEXT NOT NULL,
    linked_bot_handle TEXT NOT NULL,
    flags TEXT DEFAULT '',          -- Link-specific flags
    link_type TEXT DEFAULT 'tcp',   -- tcp/tls/relay
    linked_at INTEGER DEFAULT (strftime('%s', 'now')),
    last_seen INTEGER DEFAULT 0,
    last_activity INTEGER DEFAULT 0, -- NEW: Last non-ping activity
    lag_ms INTEGER DEFAULT 0,
    retry_count INTEGER DEFAULT 0,  -- NEW: Failed reconnect attempts
    FOREIGN KEY(bot_handle) REFERENCES bots(handle) ON DELETE CASCADE,
    FOREIGN KEY(linked_bot_handle) REFERENCES bots(handle) ON DELETE CASCADE,
    UNIQUE(bot_handle, linked_bot_handle)
);

-- =====================================================
-- USERS & ACCESS
-- =====================================================

-- Global users (partyline/DCC authentication)
CREATE TABLE IF NOT EXISTS users (
    handle TEXT PRIMARY KEY,
    password TEXT,                  -- bcrypt hash ($2b$12$...)
    flags TEXT DEFAULT '',          -- +fhoimnptx (global flags)
    last_seen INTEGER DEFAULT 0,     -- CHANGED: Unix timestamp
    hostmask TEXT DEFAULT '',       -- Primary hostmask (deprecated, use hostmasks)
    hostmasks TEXT DEFAULT '[]',    -- JSON array ["*!*@host1", "*!user@host2"]
    comment TEXT DEFAULT '',
    xtra TEXT DEFAULT '{}',         -- NEW: JSON for custom fields
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Channels
CREATE TABLE IF NOT EXISTS channels (
    name TEXT PRIMARY KEY,
    subnet_id INTEGER DEFAULT 1,
    settings TEXT DEFAULT '{}',     -- JSON: {limit:50, enforce_bans:true, chanmode:"+ntk"}
    bans TEXT DEFAULT '[]',         -- JSON ban list
    invites TEXT DEFAULT '[]',      -- JSON invite list  
    exempts TEXT DEFAULT '[]',      -- NEW: Ban exemptions
    users_count INTEGER DEFAULT 0,
    topic TEXT DEFAULT '',          -- NEW: Current topic
    topic_by TEXT DEFAULT '',       -- NEW: Who set topic
    topic_at INTEGER DEFAULT 0,     -- NEW: When topic was set
    bot_flags TEXT DEFAULT '',      -- Bot's modes in channel (+o)
    chanmode TEXT DEFAULT '',       -- NEW: Current channel modes (+ntk key)
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY(subnet_id) REFERENCES subnets(id) ON DELETE CASCADE
);

-- Per-user/channel flags
CREATE TABLE IF NOT EXISTS user_chan_flags (
    handle TEXT NOT NULL,
    channel TEXT NOT NULL,
    flags TEXT DEFAULT '',          -- +vopqa (channel-specific)
    info TEXT DEFAULT '',           -- NEW: User info text (.chinfo)
    last_updated INTEGER DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY(handle, channel),
    FOREIGN KEY(handle) REFERENCES users(handle) ON DELETE CASCADE,
    FOREIGN KEY(channel) REFERENCES channels(name) ON DELETE CASCADE
);

-- =====================================================
-- PARTYLINE & DCC
-- =====================================================

-- DCC/Telnet sessions (active connections)
CREATE TABLE IF NOT EXISTS dcc_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    handle TEXT NOT NULL,
    session_type TEXT CHECK(session_type IN ('chat', 'telnet', 'file', 'bot')) DEFAULT 'chat',
    host TEXT NOT NULL,
    port INTEGER DEFAULT 0,
    bot_handle TEXT,                -- Which bot owns this session
    channel INTEGER DEFAULT 0,      -- Partyline channel (0=global)
    connected_at INTEGER DEFAULT (strftime('%s', 'now')),
    last_activity INTEGER DEFAULT (strftime('%s', 'now')),
    idle_time INTEGER DEFAULT 0,
    away BOOLEAN DEFAULT 0,         -- NEW: .away status
    away_msg TEXT DEFAULT '',       -- NEW: Away message
    FOREIGN KEY(handle) REFERENCES users(handle) ON DELETE CASCADE,
    FOREIGN KEY(bot_handle) REFERENCES bots(handle) ON DELETE CASCADE
);

-- Partyline chat log (persistent chat history)
CREATE TABLE IF NOT EXISTS partyline_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER DEFAULT (strftime('%s', 'now')),
    channel INTEGER DEFAULT 0,      -- 0=global, 1+= custom channels
    handle TEXT NOT NULL,
    message TEXT NOT NULL,
    bot_handle TEXT,                -- NEW: Which bot relayed it
    FOREIGN KEY(handle) REFERENCES users(handle) ON DELETE SET NULL,
    FOREIGN KEY(bot_handle) REFERENCES bots(handle) ON DELETE SET NULL
);

-- =====================================================
-- TRACKING & STATS
-- =====================================================

-- Seen tracking (gseen + whowas)
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

-- Bot lag/ping stats
CREATE TABLE IF NOT EXISTS bot_lag (
    bot_handle TEXT NOT NULL,
    linked_bot_handle TEXT NOT NULL,
    lag_ms INTEGER DEFAULT 0,
    ping_sent INTEGER DEFAULT 0,
    pong_rcvd INTEGER DEFAULT 0,
    avg_lag_ms INTEGER DEFAULT 0,   -- NEW: Rolling average
    last_updated INTEGER DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY(bot_handle, linked_bot_handle),
    FOREIGN KEY(bot_handle) REFERENCES bots(handle) ON DELETE CASCADE,
    FOREIGN KEY(linked_bot_handle) REFERENCES bots(handle) ON DELETE CASCADE
);

-- IRC nickname tracking (current nicks on each bot/subnet)
CREATE TABLE IF NOT EXISTS irc_nicks (
    bot_handle TEXT NOT NULL,
    channel TEXT NOT NULL,
    nick TEXT NOT NULL,
    hostmask TEXT DEFAULT '',
    modes TEXT DEFAULT '',          -- +ov flags
    joined_at INTEGER DEFAULT (strftime('%s', 'now')),
    last_seen INTEGER DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY(bot_handle, channel, nick),
    FOREIGN KEY(bot_handle) REFERENCES bots(handle) ON DELETE CASCADE,
    FOREIGN KEY(channel) REFERENCES channels(name) ON DELETE CASCADE
);

-- Flood protection tracking
CREATE TABLE IF NOT EXISTS flood_tracking (
    hostmask TEXT NOT NULL,
    channel TEXT NOT NULL,
    event_type TEXT CHECK(event_type IN ('msg', 'join', 'nick', 'ctcp')) NOT NULL,
    event_count INTEGER DEFAULT 1,
    window_start INTEGER DEFAULT (strftime('%s', 'now')),
    last_event INTEGER DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY(hostmask, channel, event_type)
);

-- =====================================================
-- INDEXES (Optimized for Hot Paths)
-- =====================================================

-- Existing indexes
CREATE INDEX IF NOT EXISTS idx_bots_subnet ON bots(subnet_id);
CREATE INDEX IF NOT EXISTS idx_bots_online ON bots(is_online, is_linked);
CREATE INDEX IF NOT EXISTS idx_bot_links_bot ON bot_links(bot_handle);
CREATE INDEX IF NOT EXISTS idx_bot_links_linked ON bot_links(linked_bot_handle);
CREATE INDEX IF NOT EXISTS idx_users_flags ON users(flags);
CREATE INDEX IF NOT EXISTS idx_user_chan_channel ON user_chan_flags(channel);
CREATE INDEX IF NOT EXISTS idx_channels_subnet ON channels(subnet_id);
CREATE INDEX IF NOT EXISTS idx_seen_nick ON seen(nick);
CREATE INDEX IF NOT EXISTS idx_seen_channel ON seen(channel);

-- NEW indexes for performance
CREATE INDEX IF NOT EXISTS idx_dcc_sessions_handle ON dcc_sessions(handle);
CREATE INDEX IF NOT EXISTS idx_dcc_sessions_bot ON dcc_sessions(bot_handle, channel);
CREATE INDEX IF NOT EXISTS idx_partyline_log_channel ON partyline_log(channel, timestamp);
CREATE INDEX IF NOT EXISTS idx_irc_nicks_channel ON irc_nicks(channel);
CREATE INDEX IF NOT EXISTS idx_bot_links_activity ON bot_links(last_activity);
CREATE INDEX IF NOT EXISTS idx_flood_tracking_cleanup ON flood_tracking(window_start);

-- =====================================================
-- VIEWS
-- =====================================================

-- Active botnet (online + linked bots)
CREATE VIEW IF NOT EXISTS active_botnet AS
SELECT 
    b.*,
    s.name as subnet_name,
    s.irc_network,
    COUNT(DISTINCT bl.linked_bot_handle) as link_count,
    AVG(bl.lag_ms) as avg_lag_ms,
    MAX(bl.last_seen) as last_link_activity
FROM bots b 
LEFT JOIN subnets s ON b.subnet_id = s.id
LEFT JOIN bot_links bl ON b.handle = bl.bot_handle
WHERE b.is_online = 1 AND b.is_linked = 1
GROUP BY b.handle;

-- Partyline who (active sessions)
CREATE VIEW IF NOT EXISTS partyline_who AS
SELECT 
    d.handle,
    d.channel,
    d.bot_handle,
    d.idle_time,
    d.away,
    u.flags as user_flags,
    (strftime('%s', 'now') - d.last_activity) as seconds_idle
FROM dcc_sessions d
JOIN users u ON d.handle = u.handle
WHERE d.session_type IN ('chat', 'telnet')
ORDER BY d.channel, d.handle;

-- Channel user list (for .chanwho / .chanseen)
CREATE VIEW IF NOT EXISTS channel_users AS
SELECT 
    n.channel,
    n.nick,
    n.hostmask,
    n.modes as nick_modes,
    ucf.flags as user_flags,
    ucf.handle,
    n.joined_at,
    (strftime('%s', 'now') - n.last_seen) as idle_seconds
FROM irc_nicks n
LEFT JOIN user_chan_flags ucf ON n.channel = ucf.channel
WHERE n.last_seen > (strftime('%s', 'now') - 300)  -- Active in last 5min
ORDER BY n.channel, n.nick;

-- =====================================================
-- TRIGGERS (Data Integrity & Auto-Cleanup)
-- =====================================================

-- Auto-clean old seen records (keep 30 days)
CREATE TRIGGER IF NOT EXISTS cleanup_seen
AFTER INSERT ON seen
BEGIN
    DELETE FROM seen WHERE last_seen < (strftime('%s', 'now') - 2592000);
END;

-- Update bot last_ping when link updates
CREATE TRIGGER IF NOT EXISTS update_bot_ping
AFTER UPDATE OF last_seen ON bot_links
FOR EACH ROW
BEGIN
    UPDATE bots SET last_ping = NEW.last_seen WHERE handle = NEW.bot_handle;
END;

-- Cascade cleanup on channel deletion
CREATE TRIGGER IF NOT EXISTS cleanup_chan_flags
AFTER DELETE ON channels
FOR EACH ROW
BEGIN
    DELETE FROM user_chan_flags WHERE channel = OLD.name;
    DELETE FROM irc_nicks WHERE channel = OLD.name;
END;

-- Update channel user count on nick join
CREATE TRIGGER IF NOT EXISTS update_chan_users_join
AFTER INSERT ON irc_nicks
FOR EACH ROW
BEGIN
    UPDATE channels 
    SET users_count = (
        SELECT COUNT(*) FROM irc_nicks 
        WHERE channel = NEW.channel
    )
    WHERE name = NEW.channel;
END;

-- Update channel user count on nick part
CREATE TRIGGER IF NOT EXISTS update_chan_users_part
AFTER DELETE ON irc_nicks
FOR EACH ROW
BEGIN
    UPDATE channels 
    SET users_count = (
        SELECT COUNT(*) FROM irc_nicks 
        WHERE channel = OLD.channel
    )
    WHERE name = OLD.channel;
END;

-- Auto-cleanup stale flood tracking (5 min windows)
CREATE TRIGGER IF NOT EXISTS cleanup_flood_tracking
AFTER INSERT ON flood_tracking
BEGIN
    DELETE FROM flood_tracking 
    WHERE window_start < (strftime('%s', 'now') - 300);
END;

-- Auto-cleanup stale DCC sessions (24h idle)
CREATE TRIGGER IF NOT EXISTS cleanup_stale_dcc
AFTER UPDATE ON dcc_sessions
FOR EACH ROW
WHEN (strftime('%s', 'now') - NEW.last_activity) > 86400
BEGIN
    DELETE FROM dcc_sessions WHERE id = NEW.id;
END;

-- Update DCC idle time
CREATE TRIGGER IF NOT EXISTS update_dcc_idle
AFTER UPDATE OF last_activity ON dcc_sessions
FOR EACH ROW
BEGIN
    UPDATE dcc_sessions 
    SET idle_time = (strftime('%s', 'now') - NEW.last_activity)
    WHERE id = NEW.id;
END;

-- Clean partyline logs older than 90 days
CREATE TRIGGER IF NOT EXISTS cleanup_partyline_log
AFTER INSERT ON partyline_log
BEGIN
    DELETE FROM partyline_log 
    WHERE timestamp < (strftime('%s', 'now') - 7776000);
END;

-- =====================================================
-- SEED DATA (CORRECTED ORDER)
-- =====================================================

-- 1. USERS FIRST (referenced by subnets)
INSERT OR IGNORE INTO users (handle, flags, hostmasks, comment) 
VALUES 
    ('owner', '+fhoimn', '["*!*@localhost","*!*@127.0.0.1"]', 'Botnet owner'),
    ('botowner', '+fho', '["*!*@127.0.0.1"]', 'DCC partyline user'),
    ('console', '+f', '["console@wbs"]', 'Foreground console user');

-- 2. NOW SUBNETS (can reference users)
INSERT OR IGNORE INTO subnets (id, name, irc_network, irc_server, irc_ssl, channels, owner_handle) 
VALUES (1, 'default', 'Libera.Chat', 'irc.libera.chat:6697', 1, '["#wbs-test","#botnet"]', 'owner');

-- 3. BOTS (references subnets)
INSERT OR IGNORE INTO bots (handle, address, port, role, subnet_id, flags, listen_port, share_flags, nick) 
VALUES 
    ('WBS', '127.0.0.1', 3333, 'leaf', 1, '+sp', 0, 'ucbgi', 'WBS'),
    ('WBS-Hub', '127.0.0.1', 4444, 'hub', 1, '+ghplsr', 4444, 'ucbgi', 'WBS-Hub');

-- 4. CHANNELS (references subnets)
INSERT OR IGNORE INTO channels (name, subnet_id, settings, bot_flags) 
VALUES 
    ('#wbs-test', 1, '{"limit":50,"enforce_bans":true,"flood_lines":5,"flood_time":10}', '+o'),
    ('#botnet', 1, '{"limit":20,"secret":true}', '+o');

-- 5. USER_CHAN_FLAGS (references users + channels)
INSERT OR IGNORE INTO user_chan_flags (handle, channel, flags, info) 
VALUES 
    ('owner', '#wbs-test', '+oamnf', 'Permanent owner'),
    ('owner', '#botnet', '+oamnf', 'Botnet admin'),
    ('botowner', '#botnet', '+vo', 'Trusted user');

-- 6. BOT_LINKS LAST (references bots)
INSERT OR IGNORE INTO bot_links (bot_handle, linked_bot_handle, flags, link_type)
VALUES ('WBS', 'WBS-Hub', '+sp', 'tcp');


-- =====================================================
-- UTILITY FUNCTIONS (SQLite doesn't have UDFs, but helpers)
-- =====================================================
-- Use these queries in Python code for common operations:

-- Check if user matches hostmask:
-- SELECT handle FROM users WHERE ? GLOB json_extract(hostmasks, '$[*]');

-- Get user's effective flags for channel:
-- SELECT u.flags || COALESCE(ucf.flags, '') as effective_flags
-- FROM users u
-- LEFT JOIN user_chan_flags ucf ON u.handle = ucf.handle AND ucf.channel = ?
-- WHERE u.handle = ?;

-- Check flood limits:
-- SELECT event_count FROM flood_tracking 
-- WHERE hostmask = ? AND channel = ? AND event_type = ?
-- AND window_start > (strftime('%s', 'now') - ?);

CREATE TABLE IF NOT EXISTS runtime (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);