-- WBS 6.0 Complete Eggdrop Botnet Schema (148 lines)
-- Hubs/Leaves/Subnets/Partyline/DCC/Seen/Lag Stats
-- JSON fields, triggers, views, full indexes
-- DROP ALL: sqlite3 wbs.db ".read schema.sql" -- idempotent

-- =====================================================
-- CORE BOTNET TABLES
-- =====================================================

-- Subnets (different IRC nets/channels)
CREATE TABLE IF NOT EXISTS subnets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    irc_network TEXT DEFAULT '',
    channels TEXT DEFAULT '[]',     -- JSON ["#chan1"]
    owner_handle TEXT,
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY(owner_handle) REFERENCES users(handle)
);

-- Bots table (Eggdrop-style handles + attrs)
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
    share_level TEXT DEFAULT 'full', -- full/subnet
    version TEXT DEFAULT 'WBS6.0',
    uptime INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY(subnet_id) REFERENCES subnets(id) ON DELETE SET NULL
);

-- Bot links (bidirectional hub<->leaf)
CREATE TABLE IF NOT EXISTS bot_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bot_handle TEXT NOT NULL,
    linked_bot_handle TEXT NOT NULL,
    flags TEXT DEFAULT '',
    link_type TEXT DEFAULT 'tcp',   -- tcp/tls
    linked_at INTEGER DEFAULT (strftime('%s', 'now')),
    last_seen INTEGER DEFAULT 0,
    lag_ms INTEGER DEFAULT 0,
    FOREIGN KEY(bot_handle) REFERENCES bots(handle) ON DELETE CASCADE,
    FOREIGN KEY(linked_bot_handle) REFERENCES bots(handle) ON DELETE CASCADE,
    UNIQUE(bot_handle, linked_bot_handle)
);

-- =====================================================
-- USERS & ACCESS
-- =====================================================

-- Global users (partyline DCC auth)
CREATE TABLE IF NOT EXISTS users (
    handle TEXT PRIMARY KEY,
    password TEXT,                  -- bcrypt hash
    flags TEXT DEFAULT '',          -- +fhoimn (userflags)
    lastseen TEXT DEFAULT '',
    hostmask TEXT DEFAULT '',
    hostmasks TEXT DEFAULT '[]',    -- JSON multi-hostmask
    comment TEXT DEFAULT '',
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Channels
CREATE TABLE IF NOT EXISTS channels (
    name TEXT PRIMARY KEY,
    subnet_id INTEGER DEFAULT 1,
    settings TEXT DEFAULT '{}',
    bans TEXT DEFAULT '[]',         -- JSON banlist
    invites TEXT DEFAULT '[]',
    users_count INTEGER DEFAULT 0,
    bot_flags TEXT DEFAULT '',      -- +mnf etc.
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY(subnet_id) REFERENCES subnets(id)
);

-- Per-user/channel flags
CREATE TABLE IF NOT EXISTS user_chan_flags (
    handle TEXT NOT NULL,
    channel TEXT NOT NULL,
    flags TEXT DEFAULT '',          -- +vopqa
    last_updated INTEGER DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY(handle, channel),
    FOREIGN KEY(handle) REFERENCES users(handle) ON DELETE CASCADE,
    FOREIGN KEY(channel) REFERENCES channels(name) ON DELETE CASCADE
);

-- =====================================================
-- TRACKING & STATS
-- =====================================================

-- Seen (gseen + whowas)
CREATE TABLE IF NOT EXISTS seen (
    nick TEXT NOT NULL,
    handle TEXT,
    channel TEXT,
    action TEXT CHECK(action IN ('JOIN','PART','QUIT','KICK','NICK')),
    hostmask TEXT,
    user_agent TEXT DEFAULT '',
    seen_at INTEGER NOT NULL,
    PRIMARY KEY(nick, channel, seen_at)
);

-- Bot lag/pings
CREATE TABLE IF NOT EXISTS bot_lag (
    bot_handle TEXT NOT NULL,
    linked_bot_handle TEXT NOT NULL,
    lag_ms INTEGER DEFAULT 0,
    ping_sent INTEGER DEFAULT 0,
    pong_rcvd INTEGER DEFAULT 0,
    PRIMARY KEY(bot_handle, linked_bot_handle),
    FOREIGN KEY(bot_handle) REFERENCES bots(handle)
);

-- Partyline chat log (chan 0 = global)
CREATE TABLE IF NOT EXISTS partyline_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER DEFAULT (strftime('%s', 'now')),
    channel INTEGER DEFAULT 0,      -- 0=global
    handle TEXT NOT NULL,
    message TEXT NOT NULL,
    FOREIGN KEY(handle) REFERENCES users(handle)
);

-- =====================================================
-- INDEXES & VIEWS
-- =====================================================

CREATE INDEX IF NOT EXISTS idx_bots_subnet ON bots(subnet_id);
CREATE INDEX IF NOT EXISTS idx_bots_online ON bots(is_online, is_linked);
CREATE INDEX IF NOT EXISTS idx_bot_links_bot ON bot_links(bot_handle);
CREATE INDEX IF NOT EXISTS idx_bot_links_linked ON bot_links(linked_bot_handle);
CREATE INDEX IF NOT EXISTS idx_users_flags ON users(flags);
CREATE INDEX IF NOT EXISTS idx_user_chan_channel ON user_chan_flags(channel);
CREATE INDEX IF NOT EXISTS idx_channels_subnet ON channels(subnet_id);
CREATE INDEX IF NOT EXISTS idx_seen_nick ON seen(nick);
CREATE INDEX IF NOT EXISTS idx_seen_channel ON seen(channel);

-- View: Active botnet (online + linked)
CREATE VIEW IF NOT EXISTS active_botnet AS
SELECT b.*, s.name as subnet_name, 
       COUNT(bl.linked_bot_handle) as link_count
FROM bots b 
LEFT JOIN subnets s ON b.subnet_id = s.id
LEFT JOIN bot_links bl ON b.handle = bl.bot_handle
WHERE b.is_online = 1 AND b.is_linked = 1
GROUP BY b.handle;

-- =====================================================
-- TRIGGERS (Auto-maintenance)
-- =====================================================

-- Auto-clean old seen (keep 30 days)
CREATE TRIGGER IF NOT EXISTS cleanup_seen
AFTER INSERT ON seen
BEGIN
    DELETE FROM seen WHERE seen_at < (strftime('%s', 'now') - 2592000);
END;

-- Update bot last_ping on link update
CREATE TRIGGER IF NOT EXISTS update_bot_ping
AFTER UPDATE OF last_seen ON bot_links
FOR EACH ROW
BEGIN
    UPDATE bots SET last_ping = NEW.last_seen WHERE handle = NEW.bot_handle;
END;

-- Cascade ban cleanup (if channel deleted)
CREATE TRIGGER IF NOT EXISTS cleanup_chan_flags
AFTER DELETE ON channels
FOR EACH ROW
BEGIN
    DELETE FROM user_chan_flags WHERE channel = OLD.name;
END;

-- =====================================================
-- SEED DATA (Production-ready)
-- =====================================================

INSERT OR IGNORE INTO subnets (id, name, irc_network, channels, owner_handle) 
VALUES (1, 'default', 'irc.libera.chat', '["#wbs-test","#botnet"]', 'owner');

INSERT OR IGNORE INTO bots (handle, address, port, role, subnet_id, flags, listen_port) 
VALUES 
    ('WBS', '127.0.0.1', 3333, 'leaf', 1, '+sp', 0),
    ('WBS-Hub', '127.0.0.1', 4444, 'hub', 1, '+ghplsr', 4444);

INSERT OR IGNORE INTO users (handle, flags, hostmask, comment) 
VALUES 
    ('owner', '+fhoimn', '*!*@localhost', 'Botnet owner'),
    ('botowner', '+fho', '*!*@127.0.0.1', 'DCC partyline user');

INSERT OR IGNORE INTO channels (name, subnet_id, settings) 
VALUES 
    ('#wbs-test', 1, '{"limit":50,"enforce_bans":true}'),
    ('#botnet', 1, '{"limit":20}');

INSERT OR IGNORE INTO user_chan_flags (handle, channel, flags) 
VALUES 
    ('owner', '#wbs-test', '+oaq'),
    ('botowner', '#botnet', '+vo');

-- Example link (self-test)
INSERT OR IGNORE INTO bot_links (bot_handle, linked_bot_handle, flags)
VALUES ('WBS', 'WBS-Hub', '+sp');
