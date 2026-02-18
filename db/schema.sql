-- db/schema.sql: Cleaned Eggdrop-inspired schema for wbs
-- Supports users, channels, botnet (hub/leaf), subnets, seen, lag tracking
-- Uses SQLite3 with foreign keys, indexes for performance

PRAGMA foreign_keys = ON;

-- Core key-value config (bot settings, networks, etc.)
CREATE TABLE config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Users (handles, global flags, laston, etc.)
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    handle TEXT UNIQUE NOT NULL,
    password TEXT,
    info TEXT,
    email TEXT,
    url TEXT,
    laston INTEGER DEFAULT 0,
    flags TEXT DEFAULT '',  -- global flags: +fhoimn etc. [web:6]
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Channels (per-network settings, flags)
CREATE TABLE channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    network TEXT NOT NULL,
    chanmode TEXT DEFAULT '+nt',
    settings TEXT DEFAULT '',  -- serialized extras
    flags TEXT DEFAULT '',    -- +idle +secret etc.
    lock_reason TEXT DEFAULT '',
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    UNIQUE(name, network)
);

-- User-channel access (channel-specific flags)
CREATE TABLE user_channels (
    user_id INTEGER NOT NULL,
    channel_id INTEGER NOT NULL,
    flags TEXT DEFAULT '',  -- channel flags: +oav etc. [web:6]
    PRIMARY KEY (user_id, channel_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE
);

-- Bots (linked bots, hub/leaf roles)
CREATE TABLE bots (
    handle TEXT PRIMARY KEY,
    address TEXT NOT NULL,
    port INTEGER NOT NULL,
    role TEXT CHECK(role IN ('hub', 'leaf', 'none')) DEFAULT 'none',
    is_linked BOOLEAN DEFAULT 0,
    is_online BOOLEAN DEFAULT 0,
    subnet_id INTEGER,
    flags TEXT DEFAULT '',  -- botattr: +ghplsr [web:21]
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (subnet_id) REFERENCES subnets(id)
);

-- Subnets (botnet groupings, network/channel filters)
CREATE TABLE subnets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    network TEXT,  -- optional IRC network
    channels TEXT DEFAULT '',  -- comma-separated or JSON
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Botnet peers/links (detailed hub/leaf connections)
CREATE TABLE botnet_peers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bot_handle TEXT NOT NULL,
    subnet_id INTEGER,
    host TEXT,
    port INTEGER,
    cert_hash TEXT,  -- TLS
    flags TEXT DEFAULT '',
    FOREIGN KEY (bot_handle) REFERENCES bots(handle),
    FOREIGN KEY (subnet_id) REFERENCES subnets(id)
);

-- Seen module (gseen.mod like) [web:1 equivalent structure]
CREATE TABLE seen (
    nick TEXT PRIMARY KEY,
    lastseen INTEGER NOT NULL,
    hostmask TEXT,
    channels TEXT,  -- comma-separated
    action TEXT     -- JOIN/PART/QUIT
);

-- Botnet lag/pings
CREATE TABLE botnet_lag (
    peer_id INTEGER NOT NULL,
    ts REAL NOT NULL,
    rtt REAL,
    FOREIGN KEY (peer_id) REFERENCES botnet_peers(id),
    PRIMARY KEY (peer_id, ts)
);

-- Toggles/settings (task_botnet etc.)
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value INTEGER DEFAULT 0  -- 0/1
);

-- Indexes for performance
CREATE INDEX idx_users_handle ON users(handle);
CREATE INDEX idx_channels_name_net ON channels(network, name);
CREATE INDEX idx_user_channels_user ON user_channels(user_id);
CREATE INDEX idx_bots_handle ON bots(handle);
CREATE INDEX idx_seen_time ON seen(lastseen DESC);
CREATE INDEX idx_botnet_lag_peer ON botnet_lag(peer_id);

-- Initial seeds (from config.json)
INSERT OR IGNORE INTO config (key, value) VALUES
    ('botnet_enabled', '1'),
    ('default_network', 'irc.example.net'),
    ('default_channels', '#chan1,#chan2');

INSERT OR IGNORE INTO settings (key, value) VALUES
    ('task_botnet', 1),
    ('task_limit', 1);

CREATE TABLE IF NOT EXISTS bots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    subnet_id INTEGER,
    is_active BOOLEAN DEFAULT 1,
    last_seen TEXT,
    FOREIGN KEY (subnet_id) REFERENCES subnets(id)
);

CREATE TABLE IF NOT EXISTS bot_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bot_id INTEGER NOT NULL,
    linked_bot_id INTEGER NOT NULL,
    link_type TEXT NOT NULL,
    FOREIGN KEY (bot_id) REFERENCES bots(id),
    FOREIGN KEY (linked_bot_id) REFERENCES bots(id)
);

CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE users (handle TEXT PRIMARY KEY, flags TEXT, pass TEXT);
CREATE TABLE channels (name TEXT PRIMARY KEY, flags TEXT);
CREATE TABLE botnets (subnet TEXT, network TEXT, channels TEXT);