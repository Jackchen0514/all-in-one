"""Business logic: user status, node auth, traffic sync, node agents, enforcement, subscriptions."""
import base64
import calendar
import datetime
import hashlib
import hmac
import logging
import re
import secrets
import threading
import urllib.parse

from . import hy2
from .db import DB, NODE_TYPES, gen_token, now

log = logging.getLogger("allinone")

GB = 1024 ** 3
# Shadowsocks ciphers that accept an arbitrary password (the 2022 ciphers need a fixed-size key).
SS_METHODS = ("aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305")
# Prefix of the outbound groups the agent manages on anytls-server ("aio-<panel id> <name>").
GROUP_PREFIX = "aio-"


def normalize_socks5_url(v):
    """`host:port` or `socks5://[user[:pass]@]host:port` (what anytls-server accepts) -> the
    trimmed value; raises ValueError otherwise."""
    v = str(v or "").strip()
    u = urllib.parse.urlsplit(v if "://" in v else "socks5://" + v)
    if u.scheme not in ("socks5", "socks") or u.path not in ("", "/") or u.query or u.fragment:
        raise ValueError("socks5_url must be host:port or socks5://user:pass@host:port")
    try:
        port = u.port
    except ValueError:
        port = None
    if not u.hostname or not port:
        raise ValueError("socks5_url needs a host and a port (1-65535)")
    return v


class Service:
    def __init__(self, cfg, db: DB):
        self.cfg = cfg
        self.db = db
        self._sync_lock = threading.Lock()
        self._stop = threading.Event()
        self.secret = db.get_setting("secret")
        if not self.secret:
            self.secret = secrets.token_hex(32)
            db.set_setting("secret", self.secret)
        if not cfg.admin_pass:
            stored = db.get_setting("admin_pass")
            if not stored:
                stored = secrets.token_urlsafe(12)
                db.set_setting("admin_pass", stored)
                log.warning("Generated admin password: %s  (set HY2M_ADMIN_PASS to override)", stored)
            cfg.admin_pass = stored
        self.assign_missing_ss_ports()

    # ---- admin auth ------------------------------------------------------
    def login(self, username, password):
        ok = hmac.compare_digest(username or "", self.cfg.admin_user) & \
            hmac.compare_digest(password or "", self.cfg.admin_pass)
        if not ok:
            return None
        exp = now() + self.cfg.session_ttl
        payload = "%s|%d" % (username, exp)
        sig = hmac.new(self.secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        return base64.urlsafe_b64encode(("%s|%s" % (payload, sig)).encode()).decode(), exp

    def check_token(self, token):
        if not token:
            return False
        if self.cfg.api_token and hmac.compare_digest(token, self.cfg.api_token):
            return True
        try:
            user, exp, sig = base64.urlsafe_b64decode(token.encode()).decode().rsplit("|", 2)
        except Exception:
            return False
        want = hmac.new(self.secret.encode(), ("%s|%s" % (user, exp)).encode(),
                        hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, want) and int(exp) > now() and user == self.cfg.admin_user

    # ---- users -----------------------------------------------------------
    @staticmethod
    def user_status(u, t=None):
        t = t or now()
        if not u["enabled"]:
            return "disabled"
        if u["expire_at"] and u["expire_at"] <= t:
            return "expired"
        if u["traffic_limit"] and u["upload"] + u["download"] >= u["traffic_limit"]:
            return "overlimit"
        return "active"

    def present_user(self, u):
        u = dict(u)
        u["used"] = u["upload"] + u["download"]
        u["remaining"] = max(0, u["traffic_limit"] - u["used"]) if u["traffic_limit"] else None
        u["status"] = self.user_status(u)
        u["enabled"] = bool(u["enabled"])
        u["subscription_url"] = self.sub_url(u)
        return u

    def alloc_ss_port(self, exclude=()):
        used = {r["ss_port"] for r in self.db.q("SELECT ss_port FROM users WHERE ss_port>0")}
        used.update(exclude)
        for p in range(self.cfg.ss_port_min, self.cfg.ss_port_max + 1):
            if p not in used:
                return p
        raise ValueError("no free shadowsocks port left in %d-%d" % (self.cfg.ss_port_min, self.cfg.ss_port_max))

    def assign_missing_ss_ports(self):
        """Users created before shadowsocks support (e.g. an imported hy2mgr database) get a port."""
        with self.db.lock:
            for u in self.db.q("SELECT username FROM users WHERE ss_port=0 ORDER BY id"):
                self.db.update_user(u["username"], {"ss_port": self.alloc_ss_port()})

    def sub_url(self, u):
        base = self.cfg.public_url or ""
        return "%s/sub/%s" % (base, u["sub_token"])

    def extend_user(self, username, days=0, seconds=0):
        """Add time. If already expired (or never set), count from now."""
        u = self.db.get_user(username)
        if not u:
            return None
        delta = int(days * 86400) + int(seconds)
        t = now()
        base = u["expire_at"] if u["expire_at"] > t else t
        new = max(t, base + delta) if delta >= 0 else max(0, u["expire_at"] + delta)
        return self.db.update_user(username, {"expire_at": new})

    def reset_traffic(self, username):
        return self.db.update_user(username, {"upload": 0, "download": 0, "last_reset_at": now()})

    def adjust_used(self, username, delta_bytes):
        """Add delta_bytes (may be negative) to the used traffic, never below 0. A negative
        delta takes from download first, then upload."""
        with self.db.tx():
            u = self.db.get_user(username)
            if not u:
                return None
            up, down = u["upload"], u["download"] + int(delta_bytes)
            if down < 0:
                up, down = max(0, up + down), 0
            return self.db.update_user(username, {"upload": up, "download": down})

    def add_traffic_limit(self, username, delta_bytes):
        u = self.db.get_user(username)
        if not u:
            return None
        return self.db.update_user(username, {"traffic_limit": max(0, u["traffic_limit"] + int(delta_bytes))})

    def regenerate(self, username, password=True, sub=True):
        data = {}
        if password:
            data["password"] = gen_token(12)
        if sub:
            data["sub_token"] = gen_token(16)
        u = self.db.update_user(username, data)
        if password:
            self.kick_everywhere([username])
        return u

    # ---- hysteria2 http auth --------------------------------------------
    def authenticate(self, node_token, auth):
        node = self.db.get_node_by_token(node_token)
        if not node or not node["enabled"] or node["type"] != "hysteria2":
            return False, ""
        u = self.db.get_user_by_password(auth or "")
        if not u or self.user_status(u) != "active":
            return False, ""
        return True, u["username"]

    # ---- traffic sync & enforcement -------------------------------------
    def hy2_nodes(self):
        """Enabled hysteria2 nodes with a traffic stats API (the ones the panel polls itself).
        anytls / shadowsocks nodes are driven by allinone-agent, which pulls state and pushes
        counters, so changes reach them within one agent interval instead."""
        return [n for n in self.db.list_nodes(enabled_only=True) if n["type"] == "hysteria2" and n["api_url"]]

    def kick_everywhere(self, usernames):
        for n in self.hy2_nodes():
            try:
                hy2.kick(n, usernames)
            except hy2.NodeAPIError as e:
                log.warning("kick on node %s failed: %s", n["name"], e)

    def sync_node(self, node):
        traffic = hy2.fetch_traffic(node, clear=True)
        t = now()
        with self.db.tx():
            for name, st in traffic.items():
                up, down = int(st.get("tx", 0)), int(st.get("rx", 0))
                if not up and not down:
                    continue
                u = self.db.q1("SELECT id, traffic_multiplier FROM users WHERE username=?", (name,))
                if not u:
                    continue
                # Quota and history use counted traffic (actual * user multiplier * node multiplier).
                m = u["traffic_multiplier"] * node["traffic_multiplier"]
                up, down = int(round(up * m)), int(round(down * m))
                self.db.x("UPDATE users SET upload=upload+?, download=download+? WHERE id=?",
                          (up, down, u["id"]))
                self.db.x("INSERT INTO traffic_logs(user_id,node_id,upload,download,ts) "
                          "VALUES(?,?,?,?,?)", (u["id"], node["id"], up, down, t))
        online = hy2.fetch_online(node)
        # Kick connected users who are no longer allowed (expired / over limit / disabled / deleted)
        bad = []
        for name in online:
            u = self.db.get_user(name)
            if not u or self.user_status(u, t) != "active":
                bad.append(name)
        if bad:
            hy2.kick(node, bad)
            for name in bad:
                online.pop(name, None)
        self.db.update_node(node["id"], {"last_sync_at": t, "last_error": "",
                                         "online": sum(int(v) for v in online.values())})
        return {"users": len(traffic), "online": len(online), "kicked": bad}

    def sync_all(self):
        with self._sync_lock:
            self.auto_reset()
            # keep 180 days of per-sync traffic history
            self.db.x("DELETE FROM traffic_logs WHERE ts<?", (now() - 180 * 86400,))
            result = {}
            for n in self.hy2_nodes():
                try:
                    result[n["id"]] = self.sync_node(n)
                except Exception as e:
                    log.warning("sync node %s failed: %s", n["name"], e)
                    self.db.update_node(n["id"], {"last_error": str(e)[:500]})
                    result[n["id"]] = {"error": str(e)}
            return result

    # ---- import from standalone anytls-go / ssmanager ---------------------
    def import_users(self, source, items, groups=None):
        """Adopt users of a standalone anytls-go server (items = its GET /api/users) or of the
        ssmanager panel (items = rows of its `ports` table). Existing panel users are never
        modified: an item whose username already exists with the same password is reported as
        `exists`, any other conflict is skipped with a reason."""
        created, skipped = [], []
        methods = {}
        gmap, groups_created = self.import_groups(groups) if source == "anytls" else ({}, [])
        for it in items:
            try:
                data = (self._from_anytls if source == "anytls" else self._from_ssmanager)(it)
            except (KeyError, TypeError, ValueError) as e:
                skipped.append({"item": str(it.get("username") or it.get("server_port") or "?")
                                if isinstance(it, dict) else "?", "reason": "invalid item: %s" % e})
                continue
            if source == "anytls":
                try:
                    data["outbound_group_id"] = gmap.get(int(it.get("outbound_group_id") or 0), 0)
                except (TypeError, ValueError):
                    pass
            if source == "ssmanager":
                methods[it.get("method") or "aes-256-gcm"] = methods.get(it.get("method") or "aes-256-gcm", 0) + 1
            name = data["username"]
            with self.db.lock:
                old = self.db.get_user(name)
                if old and old["password"] == data["password"]:
                    if source == "ssmanager" and old["ss_port"] != data["ss_port"]:
                        skipped.append({"item": name, "reason": "exists with ss_port %d" % old["ss_port"]})
                    else:
                        skipped.append({"item": name, "reason": "exists"})
                    continue
                if old:
                    skipped.append({"item": name, "reason": "username already used by another user"})
                    continue
                if self.db.get_user_by_password(data["password"]):
                    skipped.append({"item": name, "reason": "password already used by another user"})
                    continue
                if data.get("ss_port") and self.db.q1("SELECT 1 FROM users WHERE ss_port=?", (data["ss_port"],)):
                    skipped.append({"item": name, "reason": "ss_port %d already in use" % data["ss_port"]})
                    continue
                if not data.get("ss_port"):
                    data["ss_port"] = self.alloc_ss_port()
                used = data.pop("used", 0)
                self.db.create_user(data)
                self.db.update_user(name, {"download": used})
            created.append(name)
        out = {"created": created, "skipped": skipped}
        if source == "anytls":
            out["groups_created"] = groups_created
        if source == "ssmanager":
            out["methods"] = methods
        return out

    @staticmethod
    def _clean_name(name, fallback):
        """Make `name` a valid panel username; names without any ASCII letter / digit
        (e.g. a Chinese remark) become `fallback`."""
        name = re.sub(r"[^A-Za-z0-9_.@-]", "_", str(name or "").strip())[:64]
        return name if re.search(r"[A-Za-z0-9]", name) else fallback

    @staticmethod
    def _rfc3339(v):
        """RFC3339 / ISO 8601 (anytls expires_at, ssmanager expires_at) -> unix seconds, 0 = never."""
        if not v or str(v).startswith("0001-"):
            return 0
        v = str(v).replace("Z", "+00:00")
        v = re.sub(r"\.(\d{6})\d+", r".\1", v)  # Go may emit nanoseconds
        return int(datetime.datetime.fromisoformat(v).timestamp())

    def _from_anytls(self, it):
        usage = it.get("usage") or {}
        cycle = it.get("traffic_reset_cycle") or "none"
        reset_day = 0
        if cycle == "monthly":
            reset_at = self._rfc3339(it.get("traffic_reset_at"))
            reset_day = min(28, datetime.datetime.fromtimestamp(reset_at).day) if reset_at else 1
        mult = float(it.get("traffic_multiplier") or 1.0)
        name = self._clean_name(it["username"], "anytls%d" % int(it.get("id") or 0))
        return {"username": name, "password": str(it["password"]),
                "enabled": bool(it.get("enabled", True)), "expire_at": self._rfc3339(it.get("expires_at")),
                "traffic_limit": max(0, int(it.get("traffic_limit_bytes") or 0)),
                "traffic_multiplier": mult if 0 < mult <= 100 else 1.0, "reset_day": reset_day,
                "used": max(0, int(usage.get("traffic_used_bytes", it.get("traffic_used_bytes")) or 0)),
                "note": "imported from anytls" + ("" if cycle in ("none", "monthly") else " (%s reset not supported)" % cycle)}

    def _from_ssmanager(self, it):
        port = int(it["server_port"])
        if not 1 <= port <= 65535:
            raise ValueError("bad server_port")
        name = self._clean_name(it.get("remark"), "ss%d" % port)
        if self.db.get_user(name) and self.db.get_user(name)["password"] != str(it["password"]):
            name = "%s-ss%d" % (name[:56], port)
        mult = float(it.get("traffic_multiplier") or 1.0)
        return {"username": name, "password": str(it["password"]), "ss_port": port,
                # ssmanager disables over-limit / expired ports itself; here that status is derived
                # from the limit / expiry, so only a port disabled by hand stays disabled.
                "enabled": bool(it.get("enabled", 1)) or bool(it.get("limit_exceeded")) or bool(it.get("expired")),
                "expire_at": self._rfc3339(it.get("expires_at")),
                "traffic_limit": max(0, int(it.get("traffic_limit_bytes") or 0)),
                "traffic_multiplier": mult if 0 < mult <= 100 else 1.0,
                "used": max(0, int(it.get("total_bytes") or 0)),
                "note": "imported from ssmanager port %d" % port + (" (%s)" % it["remark"] if it.get("remark") else "")}

    # ---- allinone-agent (anytls / shadowsocks nodes) --------------------
    def agent_state(self, node):
        """Desired state for the agent on `node`. Inactive users stay in the anytls list (blocked)
        so their open sessions are cut; on shadowsocks their port is simply removed."""
        t = now()
        on = bool(node["enabled"])
        users = self.db.q("SELECT * FROM users ORDER BY id")
        out = {"type": node["type"], "node_id": node["id"], "name": node["name"]}
        if node["type"] == "anytls":
            out["users"] = [{"username": u["username"], "password": u["password"],
                             "active": on and self.user_status(u, t) == "active",
                             "outbound_group_id": u["outbound_group_id"]} for u in users]
            out["outbound_groups"] = [{"id": g["id"], "name": g["name"], "socks5_url": g["socks5_url"]}
                                      for g in self.db.list_groups()]
        elif node["type"] == "shadowsocks":
            out["method"] = node["ss_method"]
            out["ports"] = [{"port": u["ss_port"], "password": u["password"], "username": u["username"]}
                            for u in users if on and u["ss_port"] and self.user_status(u, t) == "active"]
        return out

    def agent_report(self, node, body):
        """Body: {"counters": {username: cumulative bytes}, "online": n, "error": "", "version": ""}.
        Counters are cumulative per node; a counter that went down (process restarted, user
        re-created) counts from zero. The very first report of a node only records a baseline,
        so pre-existing usage on an adopted server is not billed."""
        counters = body.get("counters")
        counters = {} if counters is None else counters
        if not isinstance(counters, dict):
            raise ValueError("counters must be an object")
        first = node["last_sync_at"] == 0
        t = now()
        users = 0
        with self.db.tx():
            for name, val in counters.items():
                try:
                    val = max(0, int(val))
                except (TypeError, ValueError):
                    continue
                u = self.db.q1("SELECT id, traffic_multiplier FROM users WHERE username=?", (name,))
                if not u:
                    continue
                row = self.db.q1("SELECT value FROM node_counters WHERE node_id=? AND user_id=?",
                                 (node["id"], u["id"]))
                if row is None:
                    delta = 0 if first else val
                else:
                    delta = val - row["value"] if val >= row["value"] else val
                self.db.x("INSERT INTO node_counters(node_id,user_id,value) VALUES(?,?,?) "
                          "ON CONFLICT(node_id,user_id) DO UPDATE SET value=excluded.value",
                          (node["id"], u["id"], val))
                # Both protocols only expose a combined counter; it is booked as download.
                counted = int(round(delta * u["traffic_multiplier"] * node["traffic_multiplier"]))
                if counted > 0:
                    users += 1
                    self.db.x("UPDATE users SET download=download+? WHERE id=?", (counted, u["id"]))
                    self.db.x("INSERT INTO traffic_logs(user_id,node_id,upload,download,ts) "
                              "VALUES(?,?,0,?,?)", (u["id"], node["id"], counted, t))
        try:
            online = max(0, int(body.get("online") or 0))
        except (TypeError, ValueError):
            online = 0
        self._store_outbound_results(node, body.get("outbounds"), t)
        self.db.update_node(node["id"], {"last_sync_at": t, "agent_seen_at": t, "online": online,
                                         "last_error": str(body.get("error") or "")[:500],
                                         "agent_version": str(body.get("version") or "")[:40]})
        return {"ok": True, "users": users, "baseline": first}

    def _store_outbound_results(self, node, results, t):
        """results: {"<group id>": {"ok": bool, "latency_ms": n, "error": "", "at": unix}}"""
        if not isinstance(results, dict):
            return
        for gid, res in results.items():
            try:
                gid = int(gid)
                ok, latency = bool(res.get("ok")), max(0, int(res.get("latency_ms") or 0))
                at = int(res.get("at") or t)
            except (AttributeError, TypeError, ValueError):
                continue
            if not self.db.get_group(gid):
                continue
            self.db.x("INSERT INTO outbound_status(group_id,node_id,ok,latency_ms,error,checked_at) VALUES(?,?,?,?,?,?) "
                      "ON CONFLICT(group_id,node_id) DO UPDATE SET ok=excluded.ok, latency_ms=excluded.latency_ms, "
                      "error=excluded.error, checked_at=excluded.checked_at",
                      (gid, node["id"], int(ok), latency, str(res.get("error") or "")[:300], min(at, t)))

    def present_group(self, g):
        g = dict(g)
        g["users"] = self.db.q1("SELECT COUNT(*) n FROM users WHERE outbound_group_id=?", (g["id"],))["n"]
        g["status"] = self.db.q(
            "SELECT s.node_id, n.name node, s.ok, s.latency_ms, s.error, s.checked_at FROM outbound_status s "
            "JOIN nodes n ON n.id=s.node_id WHERE s.group_id=? ORDER BY n.sort, n.id", (g["id"],))
        for st in g["status"]:
            st["ok"] = bool(st["ok"])
        return g

    def import_groups(self, groups):
        """anytls-go outbound groups (its GET /api/outbound-groups) -> {anytls id: panel id}.
        A group with the same name and address is reused; groups the agent manages are skipped."""
        gmap, created = {}, []
        for g in groups or []:
            try:
                gid, name = int(g["id"]), str(g["name"]).strip()[:64]
                url = normalize_socks5_url(g["socks5_url"])
            except (KeyError, TypeError, ValueError):
                continue
            if gid == 0 or not name or re.match(GROUP_PREFIX + r"\d+ ", name):
                continue
            with self.db.lock:
                old = self.db.get_group_by_name(name)
                if old and old["socks5_url"] != url:
                    name = "%s (anytls %d)" % (name[:48], gid)
                    old = self.db.get_group_by_name(name)
                if not old:
                    old = self.db.create_group({"name": name, "socks5_url": url, "note": "imported from anytls"})
                    created.append(name)
            gmap[gid] = old["id"]
        return gmap, created

    def auto_reset(self, today=None):
        """Monthly traffic reset for users with reset_day set."""
        today = today or datetime.datetime.now()
        reset = []
        for u in self.db.q("SELECT username, reset_day, last_reset_at FROM users WHERE reset_day>0"):
            y, m = today.year, today.month
            day = min(u["reset_day"], 28)
            if today.day < day:
                m -= 1
                if m == 0:
                    y, m = y - 1, 12
            boundary = int(datetime.datetime(y, m, min(day, calendar.monthrange(y, m)[1])).timestamp())
            if u["last_reset_at"] < boundary:
                self.reset_traffic(u["username"])
                reset.append(u["username"])
        if reset:
            log.info("auto reset traffic: %s", ", ".join(reset))
        return reset

    def run_loop(self):
        while not self._stop.wait(self.cfg.sync_interval):
            try:
                self.sync_all()
            except Exception:
                log.exception("sync loop error")

    def stop(self):
        self._stop.set()

    # ---- overview --------------------------------------------------------
    def stats(self):
        t = now()
        users = self.db.q("SELECT * FROM users")
        counts = {"total": len(users), "active": 0, "disabled": 0, "expired": 0, "overlimit": 0}
        for u in users:
            counts[self.user_status(u, t)] += 1
        nodes = self.db.list_nodes()
        tot = self.db.q1("SELECT COALESCE(SUM(upload),0) up, COALESCE(SUM(download),0) down FROM users")
        day = self.db.q1("SELECT COALESCE(SUM(upload),0) up, COALESCE(SUM(download),0) down "
                         "FROM traffic_logs WHERE ts>?", (t - 86400,))
        return {
            "users": counts,
            "nodes": {"total": len(nodes), "enabled": sum(1 for n in nodes if n["enabled"]),
                      "online_connections": sum(n["online"] for n in nodes),
                      "by_type": {k: sum(1 for n in nodes if n["type"] == k) for k in NODE_TYPES}},
            "traffic": {"upload": tot["up"], "download": tot["down"],
                        "last_24h_upload": day["up"], "last_24h_download": day["down"]},
        }

    # ---- subscriptions ---------------------------------------------------
    @staticmethod
    def _split_port(port):
        port = str(port).strip()
        first = port.split(",")[0].split("-")[0]
        return int(first), (port if ("-" in port or "," in port) else "")

    @staticmethod
    def _host(addr):
        return "[%s]" % addr if ":" in addr and not addr.startswith("[") else addr

    def node_uri(self, node, u):
        """Share link for one node, or None if the user has nothing to connect to there."""
        host, tag = self._host(node["address"]), urllib.parse.quote(node["name"])
        pw = urllib.parse.quote(u["password"], safe="")
        if node["type"] == "shadowsocks":
            if not u["ss_port"]:
                return None
            # SIP002: userinfo = base64url("method:password") without padding
            info = base64.urlsafe_b64encode(("%s:%s" % (node["ss_method"], u["password"])).encode())
            return "ss://%s@%s:%d#%s" % (info.decode().rstrip("="), host, u["ss_port"], tag)
        q = {}
        if node["sni"]:
            q["sni"] = node["sni"]
        if node["insecure"]:
            q["insecure"] = "1"
        if node["type"] == "anytls":
            return "anytls://%s@%s:%s/%s#%s" % (pw, host, self._split_port(node["port"])[0],
                                                ("?" + urllib.parse.urlencode(q)) if q else "", tag)
        if node["obfs_password"]:
            q["obfs"] = "salamander"
            q["obfs-password"] = node["obfs_password"]
        port = node["port"]
        if node["hop_ports"]:
            # Single port in the authority + mport: parsed by v2rayN / NekoBox style clients,
            # clients without hopping support still connect to the listen port.
            port = str(self._split_port(node["port"])[0])
            q["mport"] = node["hop_ports"]
        return "hysteria2://%s@%s:%s/%s#%s" % (
            pw, host, port, ("?" + urllib.parse.urlencode(q)) if q else "", tag)

    def links(self, u):
        out = []
        for n in self.db.list_nodes(enabled_only=True):
            link = self.node_uri(n, u)
            if link:
                out.append(link)
        return out

    def clash_config(self, u):
        def s(v):
            return '"%s"' % str(v).replace("\\", "\\\\").replace('"', '\\"')
        nodes = [n for n in self.db.list_nodes(enabled_only=True)
                 if n["type"] != "shadowsocks" or u["ss_port"]]
        lines = ["proxies:"]
        for n in nodes:
            lines += ["  - name: %s" % s(n["name"]), "    type: %s" % ("ss" if n["type"] == "shadowsocks" else n["type"]),
                      "    server: %s" % s(n["address"])]
            if n["type"] == "shadowsocks":
                lines += ["    port: %d" % u["ss_port"], "    cipher: %s" % n["ss_method"],
                          "    password: %s" % s(u["password"]), "    udp: true"]
                continue
            port, ports = self._split_port(n["port"])
            lines.append("    port: %d" % port)
            if n["type"] == "hysteria2":
                ports = n["hop_ports"] or ports
                if ports:
                    lines.append("    ports: %s" % s(ports.replace(",", "/")))
                if n["hop_ports"]:
                    lines.append("    hop-interval: %d" % n["hop_interval"])
            lines.append("    password: %s" % s(u["password"]))
            if n["type"] == "anytls":
                lines += ["    client-fingerprint: chrome", "    udp: true"]
            if n["sni"]:
                lines.append("    sni: %s" % s(n["sni"]))
            if n["insecure"]:
                lines.append("    skip-cert-verify: true")
            if n["type"] == "hysteria2" and n["obfs_password"]:
                lines += ["    obfs: salamander", "    obfs-password: %s" % s(n["obfs_password"])]
        if not nodes:
            lines[0] = "proxies: []"
        names = [s(n["name"]) for n in nodes]
        lines += ["proxy-groups:", "  - name: Proxy", "    type: select",
                  "    proxies: [%s]" % ", ".join(names + ['"DIRECT"']),
                  "rules:", "  - MATCH,Proxy"]
        return "\n".join(lines) + "\n"

    def userinfo_header(self, u):
        return "upload=%d; download=%d; total=%d; expire=%d" % (
            u["upload"], u["download"], u["traffic_limit"], u["expire_at"])

    def node_server_config(self, node, manager_url):
        """Example hysteria2 server config.yaml for a node."""
        listen_port, _ = self._split_port(node["port"])
        secret = node["api_secret"] or "CHANGE_ME"
        api_listen = ":9999"
        if node["api_url"]:
            p = urllib.parse.urlparse(node["api_url"])
            if p.port:
                api_listen = ":%d" % p.port
        cfg = [
            "listen: :%d" % listen_port,
            "",
            "# Use your own certificate, or replace with an `acme:` block",
            "tls:",
            "  cert: /etc/hysteria/server.crt",
            "  key: /etc/hysteria/server.key",
            "",
        ]
        if node["obfs_password"]:
            cfg += ["obfs:", "  type: salamander", "  salamander:",
                    "    password: %s" % node["obfs_password"], ""]
        cfg += [
            "auth:",
            "  type: http",
            "  http:",
            "    url: %s/hy2/auth/%s" % (manager_url.rstrip("/"), node["auth_token"]),
            "    insecure: false",
            "",
            "trafficStats:",
            "  listen: %s" % api_listen,
            "  secret: %s" % secret,
            "",
            "masquerade:",
            "  type: proxy",
            "  proxy:",
            "    url: https://www.bing.com/",
            "    rewriteHost: true",
        ]
        return "\n".join(cfg) + "\n"
