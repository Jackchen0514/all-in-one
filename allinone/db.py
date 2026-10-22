"""SQLite storage. All access goes through a single connection guarded by a lock."""
import os
import secrets
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password      TEXT NOT NULL UNIQUE,          -- connection password for every protocol
    sub_token     TEXT NOT NULL UNIQUE,          -- subscription link token
    enabled       INTEGER NOT NULL DEFAULT 1,
    expire_at     INTEGER NOT NULL DEFAULT 0,    -- unix seconds, 0 = never
    traffic_limit INTEGER NOT NULL DEFAULT 0,    -- bytes, 0 = unlimited
    upload        INTEGER NOT NULL DEFAULT 0,    -- bytes, client -> server
    download      INTEGER NOT NULL DEFAULT 0,    -- bytes, server -> client
    reset_day     INTEGER NOT NULL DEFAULT 0,    -- 1..28: auto reset traffic monthly on this day, 0 = off
    traffic_multiplier REAL NOT NULL DEFAULT 1.0, -- counted traffic = actual traffic * multiplier
    ss_port       INTEGER NOT NULL DEFAULT 0,    -- this user's port on every shadowsocks node
    outbound_group_id INTEGER NOT NULL DEFAULT 0, -- outbound_groups.id, 0 = direct (anytls nodes only)
    last_reset_at INTEGER NOT NULL DEFAULT 0,
    note          TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    type         TEXT NOT NULL DEFAULT 'hysteria2', -- hysteria2 | anytls | shadowsocks
    address      TEXT NOT NULL,                 -- host clients connect to
    port         TEXT NOT NULL DEFAULT '443',   -- hysteria2 / anytls listen port (unused for shadowsocks)
    ss_method    TEXT NOT NULL DEFAULT 'aes-256-gcm',
    traffic_multiplier REAL NOT NULL DEFAULT 1.0, -- node rate: counted = actual * user multiplier * this
    sni          TEXT NOT NULL DEFAULT '',
    insecure     INTEGER NOT NULL DEFAULT 0,
    obfs_password TEXT NOT NULL DEFAULT '',     -- salamander obfs, empty = off
    hop_ports    TEXT NOT NULL DEFAULT '',      -- port hopping range(s) redirected to port, e.g. 20000-30000
    hop_interval INTEGER NOT NULL DEFAULT 30,   -- client hop interval in seconds
    api_url      TEXT NOT NULL DEFAULT '',      -- hysteria trafficStats url, e.g. http://1.2.3.4:9999
    api_secret   TEXT NOT NULL DEFAULT '',
    auth_token   TEXT NOT NULL UNIQUE,          -- identifies the node when it calls our auth / agent endpoints
    enabled      INTEGER NOT NULL DEFAULT 1,
    sort         INTEGER NOT NULL DEFAULT 0,
    last_sync_at INTEGER NOT NULL DEFAULT 0,
    last_error   TEXT NOT NULL DEFAULT '',
    online       INTEGER NOT NULL DEFAULT 0,
    agent_seen_at INTEGER NOT NULL DEFAULT 0,      -- last config pull by the node sync agent
    agent_port   TEXT NOT NULL DEFAULT '',          -- listen port the agent reported as applied
    agent_obfs   TEXT NOT NULL DEFAULT '',          -- obfs password the agent reported as applied
    agent_hop    TEXT NOT NULL DEFAULT '',          -- hop ports the agent reported as applied
    agent_version TEXT NOT NULL DEFAULT '',         -- allinone-agent version (anytls / shadowsocks nodes)
    created_at   INTEGER NOT NULL
);

-- Last cumulative byte counter an allinone-agent reported per user, to turn counters into deltas.
CREATE TABLE IF NOT EXISTS node_counters (
    node_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    value   INTEGER NOT NULL,
    PRIMARY KEY (node_id, user_id)
);

-- Chained SOCKS5 exits users can be routed through (applied on anytls nodes by allinone-agent).
CREATE TABLE IF NOT EXISTS outbound_groups (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    socks5_url TEXT NOT NULL,                   -- host:port or socks5://user:pass@host:port
    note       TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Latest connectivity test of a group, run by the agent on each anytls node.
CREATE TABLE IF NOT EXISTS outbound_status (
    group_id   INTEGER NOT NULL,
    node_id    INTEGER NOT NULL,
    ok         INTEGER NOT NULL,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    error      TEXT NOT NULL DEFAULT '',
    checked_at INTEGER NOT NULL,
    PRIMARY KEY (group_id, node_id)
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS traffic_logs (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id  INTEGER NOT NULL,
    node_id  INTEGER NOT NULL,
    upload   INTEGER NOT NULL,
    download INTEGER NOT NULL,
    ts       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_traffic_logs_user_ts ON traffic_logs(user_id, ts);
"""

USER_FIELDS = (
    "username", "password", "enabled", "expire_at", "traffic_limit",
    "upload", "download", "reset_day", "traffic_multiplier", "note", "ss_port", "outbound_group_id",
)
NODE_FIELDS = (
    "name", "type", "address", "port", "ss_method", "traffic_multiplier", "sni", "insecure", "obfs_password",
    "hop_ports", "hop_interval", "api_url", "api_secret", "enabled", "sort",
)
NODE_TYPES = ("hysteria2", "anytls", "shadowsocks")
GROUP_FIELDS = ("name", "socks5_url", "note")


def now() -> int:
    return int(time.time())


def gen_token(n: int = 16) -> str:
    return secrets.token_urlsafe(n)


class DB:
    def __init__(self, path: str):
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.lock = threading.RLock()
        with self.lock:
            self.conn.executescript(SCHEMA)
            self._migrate()

    def _migrate(self):
        """Add columns introduced after a database was created."""
        for table, name, ddl in (("nodes", "agent_seen_at", "INTEGER NOT NULL DEFAULT 0"),
                                 ("nodes", "agent_port", "TEXT NOT NULL DEFAULT ''"),
                                 ("nodes", "agent_obfs", "TEXT NOT NULL DEFAULT ''"),
                                 ("nodes", "hop_ports", "TEXT NOT NULL DEFAULT ''"),
                                 ("nodes", "hop_interval", "INTEGER NOT NULL DEFAULT 30"),
                                 ("nodes", "agent_hop", "TEXT NOT NULL DEFAULT ''"),
                                 ("users", "traffic_multiplier", "REAL NOT NULL DEFAULT 1.0"),
                                 ("users", "ss_port", "INTEGER NOT NULL DEFAULT 0"),
                                 ("nodes", "type", "TEXT NOT NULL DEFAULT 'hysteria2'"),
                                 ("nodes", "ss_method", "TEXT NOT NULL DEFAULT 'aes-256-gcm'"),
                                 ("nodes", "agent_version", "TEXT NOT NULL DEFAULT ''"),
                                 ("nodes", "traffic_multiplier", "REAL NOT NULL DEFAULT 1.0"),
                                 ("users", "outbound_group_id", "INTEGER NOT NULL DEFAULT 0")):
            cols = {r[1] for r in self.conn.execute("PRAGMA table_info(%s)" % table)}
            if name not in cols:
                self.conn.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, name, ddl))
        self.conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_ss_port ON users(ss_port) WHERE ss_port>0")

    # ---- low level -------------------------------------------------------
    def q(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def q1(self, sql, args=()):
        rows = self.q(sql, args)
        return rows[0] if rows else None

    def x(self, sql, args=()):
        with self.lock:
            return self.conn.execute(sql, args)

    def tx(self):
        """Usage: with db.tx(): ...  (BEGIN/COMMIT under the lock)."""
        return _Tx(self)

    # ---- settings --------------------------------------------------------
    def get_setting(self, key, default=None):
        r = self.q1("SELECT value FROM settings WHERE key=?", (key,))
        return r["value"] if r else default

    def set_setting(self, key, value):
        self.x("INSERT INTO settings(key,value) VALUES(?,?) "
               "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))

    # ---- users -----------------------------------------------------------
    def list_users(self, search="", status="", limit=100, offset=0):
        where, args = [], []
        if search:
            where.append("(username LIKE ? OR note LIKE ?)")
            args += ["%" + search + "%"] * 2
        t = now()
        if status == "active":
            where.append("enabled=1 AND (expire_at=0 OR expire_at>?) "
                         "AND (traffic_limit=0 OR upload+download<traffic_limit)")
            args.append(t)
        elif status == "disabled":
            where.append("enabled=0")
        elif status == "expired":
            where.append("expire_at>0 AND expire_at<=?")
            args.append(t)
        elif status == "overlimit":
            where.append("traffic_limit>0 AND upload+download>=traffic_limit")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self.q1("SELECT COUNT(*) c FROM users " + w, args)["c"]
        rows = self.q("SELECT * FROM users %s ORDER BY id DESC LIMIT ? OFFSET ?" % w,
                      args + [limit, offset])
        return rows, total

    def get_user(self, username):
        return self.q1("SELECT * FROM users WHERE username=?", (username,))

    def get_user_by_password(self, password):
        return self.q1("SELECT * FROM users WHERE password=?", (password,))

    def get_user_by_sub(self, token):
        return self.q1("SELECT * FROM users WHERE sub_token=?", (token,))

    def create_user(self, data):
        t = now()
        row = {
            "username": data["username"],
            "password": data.get("password") or gen_token(12),
            "sub_token": gen_token(16),
            "enabled": int(bool(data.get("enabled", 1))),
            "expire_at": int(data.get("expire_at", 0)),
            "traffic_limit": int(data.get("traffic_limit", 0)),
            "upload": int(data.get("upload", 0)),
            "download": int(data.get("download", 0)),
            "reset_day": int(data.get("reset_day", 0)),
            "traffic_multiplier": float(data.get("traffic_multiplier", 1.0)),
            "ss_port": int(data.get("ss_port", 0)),
            "outbound_group_id": int(data.get("outbound_group_id", 0)),
            "last_reset_at": t,
            "note": data.get("note", ""),
            "created_at": t,
            "updated_at": t,
        }
        cols = ",".join(row)
        self.x("INSERT INTO users(%s) VALUES(%s)" % (cols, ",".join("?" * len(row))),
               tuple(row.values()))
        return self.get_user(row["username"])

    def update_user(self, username, data):
        sets = {k: v for k, v in data.items() if k in USER_FIELDS + ("sub_token", "last_reset_at")}
        if not sets:
            return self.get_user(username)
        sets["updated_at"] = now()
        self.x("UPDATE users SET %s WHERE username=?" % ",".join(k + "=?" for k in sets),
               tuple(sets.values()) + (username,))
        return self.get_user(sets.get("username", username))

    def delete_user(self, username):
        u = self.get_user(username)
        if u:
            with self.tx():
                self.x("DELETE FROM traffic_logs WHERE user_id=?", (u["id"],))
                self.x("DELETE FROM node_counters WHERE user_id=?", (u["id"],))
                self.x("DELETE FROM users WHERE id=?", (u["id"],))
        return u

    # ---- nodes -----------------------------------------------------------
    def list_nodes(self, enabled_only=False):
        w = "WHERE enabled=1" if enabled_only else ""
        return self.q("SELECT * FROM nodes %s ORDER BY sort, id" % w)

    def get_node(self, node_id):
        return self.q1("SELECT * FROM nodes WHERE id=?", (node_id,))

    def get_node_by_token(self, token):
        return self.q1("SELECT * FROM nodes WHERE auth_token=?", (token,))

    def create_node(self, data):
        row = {k: data[k] for k in NODE_FIELDS if k in data}
        row["auth_token"] = gen_token(16)
        row["created_at"] = now()
        cols = ",".join(row)
        cur = self.x("INSERT INTO nodes(%s) VALUES(%s)" % (cols, ",".join("?" * len(row))),
                     tuple(row.values()))
        return self.get_node(cur.lastrowid)

    def update_node(self, node_id, data):
        sets = {k: v for k, v in data.items()
                if k in NODE_FIELDS + ("last_sync_at", "last_error", "online", "auth_token",
                                      "agent_seen_at", "agent_port", "agent_obfs", "agent_hop",
                                      "agent_version")}
        if sets:
            self.x("UPDATE nodes SET %s WHERE id=?" % ",".join(k + "=?" for k in sets),
                   tuple(sets.values()) + (node_id,))
        return self.get_node(node_id)

    def delete_node(self, node_id):
        n = self.get_node(node_id)
        if n:
            with self.tx():
                self.x("DELETE FROM node_counters WHERE node_id=?", (node_id,))
                self.x("DELETE FROM outbound_status WHERE node_id=?", (node_id,))
                self.x("DELETE FROM nodes WHERE id=?", (node_id,))
        return n

    # ---- outbound groups -------------------------------------------------
    def list_groups(self):
        return self.q("SELECT * FROM outbound_groups ORDER BY id")

    def get_group(self, group_id):
        return self.q1("SELECT * FROM outbound_groups WHERE id=?", (group_id,))

    def get_group_by_name(self, name):
        return self.q1("SELECT * FROM outbound_groups WHERE name=?", (name,))

    def create_group(self, data):
        t = now()
        cur = self.x("INSERT INTO outbound_groups(name, socks5_url, note, created_at, updated_at) VALUES(?,?,?,?,?)",
                     (data["name"], data["socks5_url"], data.get("note", ""), t, t))
        return self.get_group(cur.lastrowid)

    def update_group(self, group_id, data):
        sets = {k: v for k, v in data.items() if k in GROUP_FIELDS}
        if sets:
            sets["updated_at"] = now()
            with self.tx():
                self.x("UPDATE outbound_groups SET %s WHERE id=?" % ",".join(k + "=?" for k in sets),
                       tuple(sets.values()) + (group_id,))
                if "socks5_url" in sets:  # old test results no longer apply
                    self.x("DELETE FROM outbound_status WHERE group_id=?", (group_id,))
        return self.get_group(group_id)

    def delete_group(self, group_id):
        """Users of the group fall back to direct."""
        with self.tx():
            self.x("UPDATE users SET outbound_group_id=0, updated_at=? WHERE outbound_group_id=?", (now(), group_id))
            self.x("DELETE FROM outbound_status WHERE group_id=?", (group_id,))
            self.x("DELETE FROM outbound_groups WHERE id=?", (group_id,))


class _Tx:
    def __init__(self, db):
        self.db = db

    def __enter__(self):
        self.db.lock.acquire()
        self.db.conn.execute("BEGIN")
        return self.db

    def __exit__(self, et, ev, tb):
        try:
            self.db.conn.execute("ROLLBACK" if et else "COMMIT")
        finally:
            self.db.lock.release()
        return False
