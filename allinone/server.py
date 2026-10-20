"""HTTP server: admin REST API, hysteria2 auth endpoint, node agent endpoints, subscriptions, admin UI."""
import base64
import json
import logging
import math
import os
import re
import sqlite3
import ssl
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import REPO_URL, __version__, commit
from .db import NODE_TYPES, gen_token, now
from .service import GB, SS_METHODS, Service

log = logging.getLogger("allinone")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
COMMIT = commit()
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")


class APIError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


ROUTES = []


def route(method, pattern, auth=True):
    rx = re.compile("^" + re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", pattern) + "$")

    def deco(fn):
        ROUTES.append((method, rx, auth, fn))
        return fn
    return deco


# ---------------------------------------------------------------------------
# input helpers

def _int(v, name, lo=None, hi=None):
    try:
        v = int(v)
    except (TypeError, ValueError):
        raise APIError(400, "%s must be an integer" % name)
    if (lo is not None and v < lo) or (hi is not None and v > hi):
        raise APIError(400, "%s out of range" % name)
    return v


def _num(v, name):
    try:
        return float(v)
    except (TypeError, ValueError):
        raise APIError(400, "%s must be a number" % name)


def _multiplier(v):
    v = _num(v, "traffic_multiplier")
    if not 0 <= v <= 100:
        raise APIError(400, "traffic_multiplier must be between 0 and 100")
    return round(v, 4)


def _used_bytes(body, key, gb_key, lo=0):
    if key in body:
        return _int(body[key], key, lo)
    v = _num(body[gb_key], gb_key)
    if not math.isfinite(v) or abs(v) > 1e9:
        raise APIError(400, "%s out of range" % gb_key)
    if lo is not None and v < lo:
        raise APIError(400, "%s must be >= %s" % (gb_key, lo))
    return int(round(v * GB))


def parse_user_input(body, creating):
    """Normalise user fields. Accepts convenience aliases:
    traffic_limit_gb, expire_days (from now), expire_at (unix seconds)."""
    out = {}
    if "username" in body:
        if not isinstance(body["username"], str) or not USERNAME_RE.match(body["username"]):
            raise APIError(400, "username must match [A-Za-z0-9_.@-]{1,64}")
        out["username"] = body["username"]
    elif creating:
        raise APIError(400, "username is required")
    if body.get("password") not in (None, ""):
        if not isinstance(body["password"], str) or len(body["password"]) < 6:
            raise APIError(400, "password must be a string of at least 6 chars")
        out["password"] = body["password"]
    if "enabled" in body:
        out["enabled"] = int(bool(body["enabled"]))
    if "traffic_limit" in body:
        out["traffic_limit"] = _int(body["traffic_limit"], "traffic_limit", 0)
    if "traffic_limit_gb" in body:
        out["traffic_limit"] = max(0, int(_num(body["traffic_limit_gb"], "traffic_limit_gb") * GB))
    if "expire_at" in body:
        out["expire_at"] = _int(body["expire_at"], "expire_at", 0)
    if "expire_days" in body:
        d = _num(body["expire_days"], "expire_days")
        out["expire_at"] = 0 if d <= 0 else now() + int(d * 86400)
    if "reset_day" in body:
        out["reset_day"] = _int(body["reset_day"], "reset_day", 0, 28)
    if "traffic_multiplier" in body:
        out["traffic_multiplier"] = _multiplier(body["traffic_multiplier"])
    if "upload" in body:
        out["upload"] = _int(body["upload"], "upload", 0)
    if "download" in body:
        out["download"] = _int(body["download"], "download", 0)
    # used / used_gb set the total used traffic (booked as download, upload cleared)
    if "used" in body or "used_gb" in body:
        if "upload" in body or "download" in body:
            raise APIError(400, "use either used/used_gb or upload/download")
        out["upload"], out["download"] = 0, _used_bytes(body, "used", "used_gb")
    if "note" in body:
        out["note"] = str(body["note"])[:500]
    if "ss_port" in body:
        out["ss_port"] = _int(body["ss_port"], "ss_port", 1, 65535)
    return out


NODE_STR = ("name", "address", "port", "sni", "obfs_password", "hop_ports", "api_url", "api_secret")
AGENT_TYPES = ("anytls", "shadowsocks")


def _check_ranges(spec, name):
    """'20000-30000' or '20000-30000,40000-41000' (single ports allowed)."""
    if not re.match(r"^\d+(-\d+)?(,\d+(-\d+)?)*$", spec):
        raise APIError(400, "%s must look like 20000-30000 or 20000-30000,40000-41000" % name)
    for part in spec.split(","):
        a, _, b = part.partition("-")
        a, b = int(a), int(b or a)
        if not (1 <= a <= b <= 65535):
            raise APIError(400, "%s: invalid range %s" % (name, part))


def parse_node_input(body, creating, node_type="hysteria2"):
    out = {}
    for k in NODE_STR:
        if k in body:
            out[k] = str(body[k] if body[k] is not None else "").strip()
    if "type" in body:
        if body["type"] not in NODE_TYPES:
            raise APIError(400, "type must be one of " + "/".join(NODE_TYPES))
        out["type"] = body["type"]
    node_type = out.get("type", node_type)
    if "ss_method" in body:
        if body["ss_method"] not in SS_METHODS:
            raise APIError(400, "ss_method must be one of " + "/".join(SS_METHODS))
        out["ss_method"] = body["ss_method"]
    if "port" in out and node_type == "shadowsocks":
        out.pop("port")  # every user has their own port, see users.ss_port
    if "port" in out and node_type == "anytls" and not re.match(r"^\d+$", out["port"]):
        raise APIError(400, "anytls port must be a single port, e.g. 8443")
    if "port" in out and not re.match(r"^\d+([-,]\d+)*$", out["port"]):
        raise APIError(400, "port must look like 443, 20000-30000 or 443,8443")
    if out.get("hop_ports"):
        out["hop_ports"] = out["hop_ports"].replace(" ", "").replace(":", "-")
        _check_ranges(out["hop_ports"], "hop_ports")
    if "hop_interval" in body:
        out["hop_interval"] = _int(body["hop_interval"], "hop_interval", 5, 3600)
    if "traffic_multiplier" in body:
        out["traffic_multiplier"] = _multiplier(body["traffic_multiplier"])
    for k in ("insecure", "enabled"):
        if k in body:
            out[k] = int(bool(body[k]))
    if "sort" in body:
        out["sort"] = _int(body["sort"], "sort")
    if creating:
        for k in ("name", "address"):
            if not out.get(k):
                raise APIError(400, "%s is required" % k)
    return out


# ---------------------------------------------------------------------------
# handlers  (h = request handler, svc = Service, m = path params, body = JSON)

@route("POST", "/api/v1/login", auth=False)
def api_login(h, svc, m, body):
    res = svc.login(body.get("username"), body.get("password"))
    if not res:
        raise APIError(401, "invalid credentials")
    return {"token": res[0], "expire_at": res[1]}


@route("GET", "/api/v1/version")
def api_version(h, svc, m, body):
    return {"version": __version__, "commit": COMMIT, "repo": REPO_URL}


@route("GET", "/api/v1/settings")
def api_settings(h, svc, m, body):
    return {"ss_port_range": "%d-%d" % (svc.cfg.ss_port_min, svc.cfg.ss_port_max),
            "sync_interval": svc.cfg.sync_interval, "public_url": svc.cfg.public_url}


@route("GET", "/api/v1/stats")
def api_stats(h, svc, m, body):
    return svc.stats()


@route("POST", "/api/v1/sync")
def api_sync(h, svc, m, body):
    return svc.sync_all()


# ---- users ----
def _get_user(svc, name):
    u = svc.db.get_user(urllib.parse.unquote(name))
    if not u:
        raise APIError(404, "user not found")
    return u


@route("GET", "/api/v1/users")
def api_users(h, svc, m, body):
    q = h.query
    limit = _int(q.get("limit", 50), "limit", 1, 1000)
    offset = _int(q.get("offset", 0), "offset", 0)
    rows, total = svc.db.list_users(q.get("search", ""), q.get("status", ""), limit, offset)
    return {"total": total, "items": [svc.present_user(u) for u in rows]}


@route("POST", "/api/v1/users")
def api_user_create(h, svc, m, body):
    data = parse_user_input(body, creating=True)
    if svc.db.get_user(data["username"]):
        raise APIError(409, "username already exists")
    try:
        with svc.db.lock:
            if "ss_port" not in data:
                data["ss_port"] = svc.alloc_ss_port()
            u = svc.db.create_user(data)
    except ValueError as e:
        raise APIError(409, str(e))
    except sqlite3.IntegrityError:
        raise APIError(409, "username, password or ss_port already in use")
    return svc.present_user(u), 201


@route("GET", "/api/v1/users/{name}")
def api_user_get(h, svc, m, body):
    u = svc.present_user(_get_user(svc, m["name"]))
    u["links"] = svc.links(u)
    return u


@route("PATCH", "/api/v1/users/{name}")
def api_user_update(h, svc, m, body):
    old = _get_user(svc, m["name"])
    data = parse_user_input(body, creating=False)
    if "username" in data and data["username"] != old["username"] and svc.db.get_user(data["username"]):
        raise APIError(409, "username already exists")
    try:
        u = svc.db.update_user(old["username"], data)
    except sqlite3.IntegrityError:
        raise APIError(409, "username, password or ss_port already in use")
    # Credentials changed or user no longer allowed -> drop live connections.
    if ("password" in data and data["password"] != old["password"]) or \
            ("username" in data and data["username"] != old["username"]) or \
            svc.user_status(u) != "active":
        svc.kick_everywhere([old["username"]])
    return svc.present_user(u)


@route("DELETE", "/api/v1/users/{name}")
def api_user_delete(h, svc, m, body):
    u = _get_user(svc, m["name"])
    svc.db.delete_user(u["username"])
    svc.kick_everywhere([u["username"]])
    return {"deleted": u["username"]}


@route("POST", "/api/v1/users/{name}/reset-traffic")
def api_user_reset(h, svc, m, body):
    u = _get_user(svc, m["name"])
    return svc.present_user(svc.reset_traffic(u["username"]))


@route("POST", "/api/v1/users/{name}/extend")
def api_user_extend(h, svc, m, body):
    """Body: {"days": 30} (may be negative / fractional) and/or {"seconds": n}."""
    u = _get_user(svc, m["name"])
    days = _num(body.get("days", 0), "days")
    secs = _int(body.get("seconds", 0), "seconds")
    u = svc.extend_user(u["username"], days, secs)
    if svc.user_status(u) != "active":
        svc.kick_everywhere([u["username"]])
    return svc.present_user(u)


@route("POST", "/api/v1/users/{name}/add-traffic")
def api_user_add_traffic(h, svc, m, body):
    """Body: {"gb": 10} or {"bytes": n}. Negative values reduce the limit."""
    u = _get_user(svc, m["name"])
    delta = _int(body["bytes"], "bytes") if "bytes" in body else int(_num(body.get("gb", 0), "gb") * GB)
    u = svc.add_traffic_limit(u["username"], delta)
    if svc.user_status(u) != "active":
        svc.kick_everywhere([u["username"]])
    return svc.present_user(u)


@route("POST", "/api/v1/users/{name}/set-traffic")
def api_user_set_traffic(h, svc, m, body):
    """Set the used traffic. Body, one of:
    {"gb": 12.5} / {"bytes": n}             total used (booked as download, upload cleared)
    {"upload": n, "download": n}            exact bytes per direction
    {"add_gb": -2} / {"add_bytes": n}       adjust relative to the current value (min 0)"""
    u = _get_user(svc, m["name"])
    forms = [k for k in (("gb", "bytes"), ("upload", "download"), ("add_gb", "add_bytes"))
             if any(x in body for x in k)]
    if len(forms) != 1 or {"gb", "bytes"} <= set(body) or {"add_gb", "add_bytes"} <= set(body):
        raise APIError(400, "body needs exactly one of gb/bytes, upload/download, add_gb/add_bytes")
    if forms[0] == ("add_gb", "add_bytes"):
        u = svc.adjust_used(u["username"], _used_bytes(body, "add_bytes", "add_gb", lo=None))
    else:
        if forms[0] == ("gb", "bytes"):
            data = {"upload": 0, "download": _used_bytes(body, "bytes", "gb")}
        else:
            data = {k: _int(body.get(k, u[k]), k, 0) for k in ("upload", "download")}
        u = svc.db.update_user(u["username"], data)
    if svc.user_status(u) != "active":
        svc.kick_everywhere([u["username"]])
    return svc.present_user(u)


@route("POST", "/api/v1/users/{name}/regenerate")
def api_user_regen(h, svc, m, body):
    """Body: {"password": true, "sub": true}"""
    u = _get_user(svc, m["name"])
    u = svc.regenerate(u["username"], bool(body.get("password", True)), bool(body.get("sub", True)))
    return svc.present_user(u)


@route("POST", "/api/v1/users/{name}/kick")
def api_user_kick(h, svc, m, body):
    u = _get_user(svc, m["name"])
    svc.kick_everywhere([u["username"]])
    return {"kicked": u["username"]}


@route("GET", "/api/v1/users/{name}/traffic")
def api_user_traffic(h, svc, m, body):
    """Daily usage history. ?days=30"""
    u = _get_user(svc, m["name"])
    days = _int(h.query.get("days", 30), "days", 1, 366)
    rows = svc.db.q(
        "SELECT date(ts,'unixepoch','localtime') day, SUM(upload) upload, SUM(download) download "
        "FROM traffic_logs WHERE user_id=? AND ts>? GROUP BY day ORDER BY day",
        (u["id"], now() - days * 86400))
    return {"username": u["username"], "items": rows}


@route("POST", "/api/v1/import")
def api_import(h, svc, m, body):
    """Body: {"source": "anytls" | "ssmanager", "items": [...]} -- see Service.import_users."""
    if body.get("source") not in ("anytls", "ssmanager"):
        raise APIError(400, "source must be anytls or ssmanager")
    if not isinstance(body.get("items"), list):
        raise APIError(400, "items must be a list")
    try:
        return svc.import_users(body["source"], body["items"])
    except ValueError as e:
        raise APIError(409, str(e))


# ---- nodes ----
def _get_node(svc, nid):
    n = svc.db.get_node(_int(nid, "id"))
    if not n:
        raise APIError(404, "node not found")
    return n


def present_node(n):
    n = dict(n)
    for k in ("insecure", "enabled"):
        n[k] = bool(n[k])
    if n["type"] in AGENT_TYPES:
        # allinone-agent reports every ~30s; treat it as synced while it keeps reporting.
        n["agent_synced"] = n["agent_seen_at"] > now() - 180
    else:
        # Whether the node sync agent has applied the current port / obfs settings.
        listen_port = str(Service._split_port(n["port"])[0])
        n["agent_synced"] = bool(n["agent_seen_at"]) and n["agent_port"] == listen_port \
            and n["agent_obfs"] == n["obfs_password"] and n["agent_hop"] == n["hop_ports"]
    n.pop("agent_obfs")
    return n


@route("GET", "/api/v1/nodes")
def api_nodes(h, svc, m, body):
    return {"items": [present_node(n) for n in svc.db.list_nodes()]}


@route("POST", "/api/v1/nodes")
def api_node_create(h, svc, m, body):
    return present_node(svc.db.create_node(parse_node_input(body, creating=True))), 201


@route("GET", "/api/v1/nodes/{id}")
def api_node_get(h, svc, m, body):
    return present_node(_get_node(svc, m["id"]))


@route("PATCH", "/api/v1/nodes/{id}")
def api_node_update(h, svc, m, body):
    n = _get_node(svc, m["id"])
    data = parse_node_input(body, creating=False, node_type=n["type"])
    if body.get("regenerate_auth_token"):
        data["auth_token"] = gen_token(16)
    return present_node(svc.db.update_node(n["id"], data))


@route("DELETE", "/api/v1/nodes/{id}")
def api_node_delete(h, svc, m, body):
    n = _get_node(svc, m["id"])
    svc.db.delete_node(n["id"])
    return {"deleted": n["id"]}


@route("POST", "/api/v1/nodes/{id}/sync")
def api_node_sync(h, svc, m, body):
    n = _get_node(svc, m["id"])
    if n["type"] in AGENT_TYPES:
        raise APIError(400, "%s nodes report through allinone-agent every ~30s" % n["type"])
    if not n["api_url"]:
        raise APIError(400, "node has no api_url configured")
    try:
        return svc.sync_node(n)
    except Exception as e:
        svc.db.update_node(n["id"], {"last_error": str(e)[:500]})
        raise APIError(502, str(e))


@route("GET", "/api/v1/nodes/{id}/config")
def api_node_config(h, svc, m, body):
    n = _get_node(svc, m["id"])
    manager = svc.cfg.public_url or h.base_url()
    if n["type"] in AGENT_TYPES:
        entry = {"token": n["auth_token"], "type": n["type"]}
        if n["type"] == "anytls":
            entry.update({"api": "https://127.0.0.1:8843", "api_key": "<anytls-server -api-key>"})
        else:
            entry["manager"] = "127.0.0.1:6100"
        agent = {"panel": manager, "interval": 30, "nodes": [entry]}
        return {"agent_config": json.dumps(agent, indent=2, ensure_ascii=False),
                "state_url": "%s/agent/%s/state" % (manager, n["auth_token"])}
    return {"yaml": svc.node_server_config(n, manager),
            "auth_url": "%s/hy2/auth/%s" % (manager, n["auth_token"])}


# ---- node sync agent ----
@route("GET", "/hy2/node/{token}/config", auth=False)
def hy2_node_config(h, svc, m, body):
    """Polled by hy2mgr-node-sync on each node. Query: port / obfs / hop = what is applied now."""
    n = svc.db.get_node_by_token(m["token"])
    if not n or n["type"] != "hysteria2":
        raise APIError(404, "not found")
    svc.db.update_node(n["id"], {"agent_seen_at": now(), "agent_port": h.query.get("port", ""),
                                 "agent_obfs": h.query.get("obfs", ""), "agent_hop": h.query.get("hop", "")})
    return {"listen_port": Service._split_port(n["port"])[0], "port": n["port"],
            "obfs_password": n["obfs_password"], "hop_ports": n["hop_ports"]}


# ---- allinone-agent (anytls / shadowsocks nodes) ----
def _agent_node(svc, token):
    n = svc.db.get_node_by_token(token)
    if not n or n["type"] not in AGENT_TYPES:
        raise APIError(404, "not found")
    return n


@route("GET", "/agent/{token}/state", auth=False)
def agent_state(h, svc, m, body):
    n = _agent_node(svc, m["token"])
    svc.db.update_node(n["id"], {"agent_seen_at": now()})
    return svc.agent_state(n)


@route("POST", "/agent/{token}/report", auth=False)
def agent_report(h, svc, m, body):
    try:
        return svc.agent_report(_agent_node(svc, m["token"]), body)
    except ValueError as e:
        raise APIError(400, str(e))


# ---- hysteria2 auth callback ----
@route("POST", "/hy2/auth/{token}", auth=False)
def hy2_auth(h, svc, m, body):
    ok, uid = svc.authenticate(m["token"], body.get("auth"))
    return {"ok": ok, "id": uid}


# ---- subscription ----
@route("GET", "/sub/{token}", auth=False)
def sub(h, svc, m, body):
    u = svc.db.get_user_by_sub(m["token"])
    if not u:
        raise APIError(404, "not found")
    fmt = h.query.get("format", "")
    ua = (h.headers.get("User-Agent") or "").lower()
    if not fmt and any(k in ua for k in ("clash", "mihomo", "stash")):
        fmt = "clash"
    headers = {
        "Subscription-Userinfo": svc.userinfo_header(u),
        "Profile-Update-Interval": "12",
        "Content-Disposition": 'attachment; filename="%s"' % u["username"],
    }
    if svc.user_status(u) != "active":
        links = []
    else:
        links = svc.links(u)
    if fmt == "clash":
        text = svc.clash_config(u) if links else "proxies: []\n"
        return RawResponse(text.encode(), "text/yaml; charset=utf-8", headers)
    if fmt == "raw":
        return RawResponse("\n".join(links).encode(), "text/plain; charset=utf-8", headers)
    return RawResponse(base64.b64encode("\n".join(links).encode()), "text/plain; charset=utf-8", headers)


class RawResponse:
    def __init__(self, data, ctype, headers=None):
        self.data, self.ctype, self.headers = data, ctype, headers or {}


# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    svc = None  # set by make_server
    server_version = "allinone"
    protocol_version = "HTTP/1.1"
    timeout = 60  # idle keep-alive / slow TLS handshake

    def log_message(self, fmt, *args):
        log.debug("%s - %s", self.address_string(), fmt % args)

    def base_url(self):
        host = self.headers.get("Host") or "127.0.0.1"
        proto = self.headers.get("X-Forwarded-Proto") or ("https" if self.server.tls else "http")
        return "%s://%s" % (proto, host)

    def _send(self, status, data, ctype, headers=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _json(self, status, obj):
        self._send(status, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def _dispatch(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        self.query = dict(urllib.parse.parse_qsl(parsed.query))
        try:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            body = {}
            if raw:
                try:
                    body = json.loads(raw)
                except ValueError:
                    raise APIError(400, "invalid JSON body")
                if not isinstance(body, dict):
                    raise APIError(400, "JSON body must be an object")

            if self.command == "GET" and not path.startswith(("/api/", "/sub/", "/hy2/", "/agent/")):
                return self._static(path)

            path_matched = False
            for method, rx, need_auth, fn in ROUTES:
                mt = rx.match(path)
                if not mt:
                    continue
                path_matched = True
                if method != self.command:
                    continue
                if need_auth:
                    auth = self.headers.get("Authorization", "")
                    token = auth[7:] if auth.lower().startswith("bearer ") else self.headers.get("X-API-Token", "")
                    if not self.svc.check_token(token.strip()):
                        raise APIError(401, "unauthorized")
                res = fn(self, self.svc, mt.groupdict(), body)
                status = 200
                if isinstance(res, tuple):
                    res, status = res
                if isinstance(res, RawResponse):
                    return self._send(status, res.data, res.ctype, res.headers)
                return self._json(status, res)
            raise APIError(405 if path_matched else 404,
                           "method not allowed" if path_matched else "not found")
        except APIError as e:
            self._json(e.status, {"error": e.message})
        except Exception as e:
            log.exception("unhandled error on %s %s", self.command, self.path)
            self._json(500, {"error": "internal error: %s" % e})

    def _static(self, path):
        name = "index.html" if path in ("/", "") else path.lstrip("/")
        full = os.path.realpath(os.path.join(STATIC_DIR, name))
        if not full.startswith(os.path.realpath(STATIC_DIR) + os.sep) or not os.path.isfile(full):
            full = os.path.join(STATIC_DIR, "index.html")
        ctype = {"html": "text/html", "js": "application/javascript", "css": "text/css",
                 "svg": "image/svg+xml"}.get(full.rsplit(".", 1)[-1], "application/octet-stream")
        with open(full, "rb") as f:
            self._send(200, f.read(), ctype + "; charset=utf-8")

    do_GET = do_POST = do_PATCH = do_PUT = do_DELETE = do_HEAD = _dispatch


class Server(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        # TLS handshake failures, resets and timeouts from scanners: not worth a traceback.
        log.debug("connection error from %s", client_address, exc_info=True)


def make_server(svc, host, port, tls_cert="", tls_key=""):
    Handler.svc = svc
    srv = Server((host, port), Handler)
    srv.daemon_threads = True
    srv.tls = bool(tls_cert and tls_key)
    if srv.tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(tls_cert, tls_key)
        # Handshake lazily in the worker thread so a slow client can't block accept().
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
    return srv
