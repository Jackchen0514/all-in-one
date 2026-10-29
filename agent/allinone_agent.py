#!/usr/bin/env python3
"""allinone-agent: keeps the anytls-server / ssmanager processes on this machine in sync with the
allinone panel. Standard library only (Python 3.8+).

Every cycle, for each node listed in the config:
  1. read the cumulative per-user byte counters from the local server and POST them to
     <panel>/agent/<token>/report (the panel turns them into deltas, applies limits and history);
  2. GET <panel>/agent/<token>/state and apply it:
       anytls      -> local admin API (/api/users): create / update / delete users; inactive users
                      are disabled with an expiry in the past so open sessions are cut too.
                      The panel's outbound groups (SOCKS5 chain proxies) are kept in sync as
                      anytls groups named "aio-<id> <name>" and tested every few minutes.
       shadowsocks -> local ssmanager manager protocol (UDP): add / remove one port per user

Only outbound connections to the panel are needed. Config (default /etc/allinone/agent.json):

  {"panel": "https://panel.example.com", "interval": 30, "nodes": [
     {"token": "<node auth token>", "type": "anytls",
      "api": "https://127.0.0.1:8843", "api_key": "<anytls-server -api-key>"},
     {"token": "<node auth token>", "type": "shadowsocks", "manager": "127.0.0.1:6100"}]}

Usage: allinone-agent [--config PATH] [--once]
"""
import argparse
import json
import logging
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

VERSION = "0.3.0"
STATE_DIR = os.environ.get("AIO_AGENT_STATE_DIR", "/var/lib/allinone-agent")
BLOCKED_UNTIL = "2000-01-01T00:00:00Z"  # anytls expiry used to block an inactive user
GROUP_RE = re.compile(r"^aio-(\d+) ")     # anytls outbound groups managed by the agent
TEST_EVERY = 300                         # seconds between connectivity tests of a group
TESTS_PER_CYCLE = 5                      # each test can take up to ~5 s
log = logging.getLogger("allinone-agent")


class AgentError(Exception):
    pass


def port_free(port):
    """True when nothing listens on TCP `port` (anytls listens on 0.0.0.0)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def http_json(method, url, body=None, headers=None, insecure=False, timeout=15):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    ctx = None
    if insecure and url.startswith("https:"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        detail = e.read()[:200].decode(errors="replace").strip()
        raise AgentError("HTTP %d from %s %s %s" % (e.code, method, url, detail))
    except Exception as e:
        raise AgentError("%s %s: %s" % (method, url, e))
    if not raw.strip():
        return None
    try:
        return json.loads(raw)
    except ValueError:
        raise AgentError("invalid JSON from %s" % url)


def open_firewall(port, protos=("tcp", "udp")):
    """Best effort: allow a new port in an active ufw / firewalld.
    Cloud security groups are outside our reach."""
    def ok(cmd):
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    try:
        if shutil.which("ufw") and b"Status: active" in subprocess.run(["ufw", "status"], stdout=subprocess.PIPE).stdout:
            for proto in protos:
                ok(["ufw", "allow", "%d/%s" % (port, proto)])
        elif shutil.which("firewall-cmd") and ok(["firewall-cmd", "--state"]):
            for proto in protos:
                ok(["firewall-cmd", "--permanent", "--add-port=%d/%s" % (port, proto)])
            ok(["firewall-cmd", "--reload"])
    except OSError:
        pass


# ---------------------------------------------------------------------------
class AnyTLS:
    """Drives anytls-server through its admin API. Usernames on the server = panel usernames.
    The panel does all accounting, so per-user quota / reset / multiplier on the server are kept
    neutral; IP / connection limits set by hand on the server are left alone."""

    NEUTRAL = {"traffic_limit_bytes": 0, "traffic_multiplier": 1.0, "traffic_reset_cycle": "none"}
    UNIT_MARK = "managed by allinone-agent"  # only a unit written by install.sh is edited

    def __init__(self, cfg, memo=None):
        self.api = cfg.get("api", "https://127.0.0.1:8843").rstrip("/")
        self.key = cfg.get("api_key", "")
        self.unit = cfg.get("unit", "/etc/systemd/system/anytls-server.service")
        # kept across cycles by Agent: {"tests": {panel group id: result}, "no_test": bool}
        self.memo = memo if memo is not None else {}

    def _call(self, method, path, body=None):
        # anytls reuses its public certificate for the admin API, which never matches 127.0.0.1
        return http_json(method, self.api + path, body, {"Authorization": "Bearer " + self.key}, insecure=True)

    def users(self):
        return {u["username"]: u for u in (self._call("GET", "/api/users") or [])}

    def collect(self):
        users = self.users()
        counters = {name: int((u.get("usage") or {}).get("traffic_used_bytes", u.get("traffic_used_bytes", 0)))
                    for name, u in users.items()}
        online = sum(int((u.get("usage") or {}).get("active_conns", 0)) for u in users.values())
        return counters, online

    @staticmethod
    def _blocked(u):
        exp = u.get("expires_at") or ""
        return not u.get("enabled") or not (exp == "" or exp.startswith("0001-"))

    def sync_groups(self, want_groups, needed):
        """Create / update the managed anytls groups. Returns ({panel id: anytls id}, stale groups,
        changes), or (None, [], 0) when this anytls-server has no outbound groups (< v0.0.33)."""
        try:
            have = self._call("GET", "/api/outbound-groups") or []
        except AgentError as e:
            if "HTTP 404" not in str(e):
                raise
            if needed:
                raise AgentError("anytls-server is too old for outbound groups (needs v0.0.33+); "
                                 "run update.sh on this node")
            return None, [], 0
        managed = {}
        for g in have:
            m = GROUP_RE.match(g.get("name") or "")
            if m and g.get("id"):
                managed[int(m.group(1))] = g
        gmap, changed = {}, 0
        for w in want_groups:
            name = "aio-%d %s" % (w["id"], w["name"])
            h = managed.pop(w["id"], None)
            if h is None:
                h = self._call("POST", "/api/outbound-groups", {"name": name, "socks5_url": w["socks5_url"]})
                changed += 1
            elif h.get("name") != name or h.get("socks5_url") != w["socks5_url"]:
                self._call("PUT", "/api/outbound-groups/%d" % h["id"], {"name": name, "socks5_url": w["socks5_url"]})
                changed += 1
            gmap[w["id"]] = h["id"]
        return gmap, list(managed.values()), changed

    def test_groups(self, want_groups, gmap):
        """Connectivity test of each group from this server, every TEST_EVERY seconds (and right
        after its address changes). Results are reported to the panel on the next cycle."""
        tests = self.memo.setdefault("tests", {})
        for gid in [g for g in tests if g not in gmap]:
            del tests[gid]
        if self.memo.get("no_test"):
            return
        t, done = int(time.time()), 0
        for w in want_groups:
            old = tests.get(w["id"])
            if done >= TESTS_PER_CYCLE or w["id"] not in gmap or \
                    (old and old["url"] == w["socks5_url"] and t - old["at"] < TEST_EVERY):
                continue
            done += 1
            try:
                r = self._call("POST", "/api/outbound-groups/%d/test" % gmap[w["id"]], {}) or {}
            except AgentError as e:
                if "HTTP 404" in str(e):  # anytls-server v0.0.33 has groups but no test endpoint
                    self.memo["no_test"] = True
                    return
                r = {"success": False, "error": str(e)}
            tests[w["id"]] = {"ok": bool(r.get("success")), "latency_ms": int(r.get("latency_ms") or 0),
                              "error": str(r.get("error") or "")[:300], "at": t, "url": w["socks5_url"]}

    # ---- listen port (the node's port in the panel) ----
    LISTEN_RE = re.compile(r"(?m)^(ExecStart=.*\s-l\s+\S*:)(\d+)(?=\s|$)")

    def _read_unit(self):
        try:
            with open(self.unit) as f:
                text = f.read()
        except OSError:
            return None, None
        m = self.LISTEN_RE.search(text)
        return text, (int(m.group(2)) if m and self.UNIT_MARK in text else None)

    def listen_port(self):
        """Port anytls-server is configured to listen on, None if the unit is not ours."""
        return self._read_unit()[1]

    def _restart(self):
        subprocess.run(["systemctl", "daemon-reload"], check=False)
        subprocess.run(["systemctl", "restart", "anytls-server"], check=False)
        for _ in range(10):
            time.sleep(1)
            if subprocess.run(["systemctl", "is-active", "-q", "anytls-server"]).returncode == 0:
                try:
                    self._call("GET", "/api/users")
                    return True
                except AgentError:
                    pass
        return False

    def apply_port(self, want):
        """Moves anytls-server to the panel's port: rewrites -l in its unit and restarts it.
        A busy port or a server that does not come back is rolled back and reported."""
        try:
            want = int(want)
        except (TypeError, ValueError):
            return 0
        text, have = self._read_unit()
        if have is None or want == have or not 0 < want < 65536:
            self.memo.pop("port_failed", None)
            return 0
        if self.memo.get("port_failed") == want:  # don't restart anytls every cycle; retried on agent restart
            raise AgentError("anytls-server did not start on port %d earlier, kept port %d" % (want, have))
        if not port_free(want):
            raise AgentError("cannot move anytls-server to port %d: it is already in use on this server" % want)
        new = self.LISTEN_RE.sub(lambda m: m.group(1) + str(want), text, count=1)
        with open(self.unit, "w") as f:
            f.write(new)
        open_firewall(want, ("tcp",))
        if self._restart():
            log.info("anytls-server now listens on port %d (was %d)", want, have)
            return 1
        with open(self.unit, "w") as f:
            f.write(text)
        self._restart()
        self.memo["port_failed"] = want
        raise AgentError("anytls-server did not start on port %d, kept port %d (journalctl -u anytls-server)"
                         % (want, have))

    def results(self):
        return {str(gid): {k: v for k, v in res.items() if k != "url"}
                for gid, res in self.memo.get("tests", {}).items()}

    def apply(self, state):
        have = self.users()
        want = {u["username"]: u for u in state.get("users", [])}
        changed = 0
        # outbound groups: absent from the state of an older panel -> leave them alone
        want_groups = state.get("outbound_groups")
        gmap, stale = None, []
        if want_groups is not None:
            needed = bool(want_groups) and any(u.get("outbound_group_id") for u in want.values())
            gmap, stale, changed = self.sync_groups(want_groups, needed)
        for name, w in want.items():
            body = {"password": w["password"], "enabled": bool(w["active"]),
                    "expires_at": "" if w["active"] else BLOCKED_UNTIL}
            if gmap is not None:
                body["outbound_group_id"] = gmap.get(w.get("outbound_group_id") or 0, 0)
            h = have.get(name)
            if h is None:
                body.update(self.NEUTRAL, username=name)
                self._call("POST", "/api/users", body)
                changed += 1
                continue
            neutral = all(h.get(k) == v for k, v in self.NEUTRAL.items())
            group_ok = gmap is None or h.get("outbound_group_id", 0) == body["outbound_group_id"]
            if h.get("password") != w["password"] or self._blocked(h) == bool(w["active"]) or not neutral \
                    or not group_ok:
                body.update(self.NEUTRAL)
                self._call("PUT", "/api/users/%d" % h["id"], body)
                changed += 1
        for name, h in have.items():
            if name not in want:
                self._call("DELETE", "/api/users/%d" % h["id"])
                changed += 1
        for g in stale:  # after users moved off them
            self._call("DELETE", "/api/outbound-groups/%d" % g["id"])
            changed += 1
        if gmap:
            self.test_groups(want_groups, gmap)
        changed += self.apply_port(state.get("listen_port"))
        return changed


# ---------------------------------------------------------------------------
class Shadowsocks:
    """Drives shadowsocks-rust ssmanager through its UDP manager protocol: one port per user.
    The ports applied (with password / method / owner) are kept in a state file, so password
    changes are detected and counters can be attributed to users across restarts."""

    def __init__(self, cfg, token):
        host, _, port = cfg.get("manager", "127.0.0.1:6100").rpartition(":")
        self.addr = (host.strip("[]") or "127.0.0.1", int(port))
        self.timeout = float(cfg.get("timeout", 3))
        self.state_file = cfg.get("state") or os.path.join(STATE_DIR, "ss-%s.json" % token[:12])

    def _send(self, msg):
        fam = socket.AF_INET6 if ":" in self.addr[0] else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_DGRAM)
        try:
            s.settimeout(self.timeout)
            s.sendto(msg.encode(), self.addr)
            data, _ = s.recvfrom(65535)
        except socket.timeout:
            raise AgentError("ssmanager at %s:%d did not answer %r" % (self.addr[0], self.addr[1], msg.split(":")[0]))
        except OSError as e:
            raise AgentError("ssmanager at %s:%d: %s" % (self.addr[0], self.addr[1], e))
        finally:
            s.close()
        return data.decode("utf-8", "replace").strip()

    @staticmethod
    def _body(reply):
        """Replies look like `stat: {...}`, `[...]` or `{"servers": [...]}`."""
        starts = [i for i in (reply.find("{"), reply.find("[")) if i != -1]
        if not starts:
            return None
        try:
            return json.loads(reply[min(starts):])
        except ValueError:
            return None

    def _ok(self, reply, op):
        if not reply.lower().startswith("ok"):
            raise AgentError("ssmanager %s failed: %s" % (op, reply[:200]))

    def remote_ports(self):
        b = self._body(self._send("list"))
        servers = b if isinstance(b, list) else (b or {}).get("servers", [])
        return {int(x["server_port"]) for x in servers}

    def load(self):
        try:
            with open(self.state_file) as f:
                return {int(k): v for k, v in json.load(f).items()}
        except (OSError, ValueError):
            return {}

    def save(self, applied):
        os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
        tmp = self.state_file + ".tmp"
        with open(tmp, "w") as f:
            json.dump({str(k): v for k, v in applied.items()}, f)
        os.replace(tmp, self.state_file)

    def collect(self):
        stat = self._body(self._send("ping")) or {}
        owners = self.load()
        counters = {}
        for port, n in stat.items():
            o = owners.get(int(port))
            if o:
                counters[o["username"]] = int(n)
        online = 0
        try:  # conn-stat needs the Jackchen0514/shadowsocks-rust fork >= v1.23.9
            b = self._body(self._send("conn-stat"))
            servers = b if isinstance(b, list) else (b or {}).get("servers", [])
            online = sum(int(x.get("tcp_conn_count", 0)) for x in servers)
        except AgentError:
            pass
        return counters, online

    def apply(self, state):
        method = state.get("method") or "aes-256-gcm"
        want = {int(p["port"]): {"password": p["password"], "method": method, "username": p["username"]}
                for p in state.get("ports", [])}
        applied = self.load()
        remote = self.remote_ports()
        changed = 0
        for port in sorted(remote - set(want)):
            self._ok(self._send("remove: " + json.dumps({"server_port": port})), "remove")
            applied.pop(port, None)
            changed += 1
        for port, w in sorted(want.items()):
            a = applied.get(port)
            if port in remote and a and a["password"] == w["password"] and a["method"] == w["method"]:
                applied[port] = w  # owner may have been renamed
                continue
            if port in remote:
                self._ok(self._send("remove: " + json.dumps({"server_port": port})), "remove")
            elif port not in applied:
                open_firewall(port)
            self._ok(self._send("add: " + json.dumps({"server_port": port, "password": w["password"],
                                                      "method": w["method"]})), "add")
            applied[port] = w
            changed += 1
        for port in list(applied):
            if port not in want:
                applied.pop(port)
        self.save(applied)
        return changed


DRIVERS = {"anytls": lambda c, memo: AnyTLS(c, memo), "shadowsocks": lambda c, memo: Shadowsocks(c, c["token"])}


# ---------------------------------------------------------------------------
class Agent:
    def __init__(self, config_path):
        self.config_path = config_path
        self.errors = {}  # token -> last apply error, reported on the next cycle
        self.memo = {}    # token -> driver state kept across cycles (anytls group tests)

    def load_config(self):
        with open(self.config_path) as f:
            cfg = json.load(f)
        if not cfg.get("panel") or not isinstance(cfg.get("nodes"), list):
            raise AgentError("%s: 'panel' and 'nodes' are required" % self.config_path)
        return cfg

    def cycle_node(self, panel, node):
        token = node["token"]
        if node.get("type") not in DRIVERS:
            raise AgentError("unknown node type %r" % node.get("type"))
        drv = DRIVERS[node["type"]](node, self.memo.setdefault(token, {}))
        base = "%s/agent/%s" % (panel.rstrip("/"), token)
        report = {"counters": {}, "online": 0, "version": VERSION, "error": self.errors.pop(token, "")}
        try:
            report["counters"], report["online"] = drv.collect()
        except AgentError as e:
            report["error"] = report["error"] or str(e)
        if hasattr(drv, "results"):
            report["outbounds"] = drv.results()
        if hasattr(drv, "listen_port"):
            report["port"] = drv.listen_port()
        http_json("POST", base + "/report", report)
        state = http_json("GET", base + "/state")
        if state.get("type") != node["type"]:
            raise AgentError("panel says node %s is %s, config says %s" % (token[:8], state.get("type"), node["type"]))
        try:
            changed = drv.apply(state)
        except AgentError as e:
            self.errors[token] = str(e)
            raise
        if changed:
            log.info("%s node %s: applied %d change(s)", node["type"], state.get("name", token[:8]), changed)

    def run_once(self):
        cfg = self.load_config()
        ok = True
        for node in cfg["nodes"]:
            try:
                self.cycle_node(cfg["panel"], node)
            except Exception as e:
                ok = False
                log.warning("%s node %s: %s", node.get("type"), str(node.get("token", ""))[:8], e)
        return ok, max(5, int(cfg.get("interval", 30)))

    def run(self):
        while True:
            try:
                _, interval = self.run_once()
            except Exception as e:
                log.error("%s", e)
                interval = 30
            time.sleep(interval)


def main(argv=None):
    p = argparse.ArgumentParser(description="allinone node agent (anytls / shadowsocks)")
    p.add_argument("--config", default=os.environ.get("AIO_AGENT_CONFIG", "/etc/allinone/agent.json"))
    p.add_argument("--once", action="store_true", help="run one cycle and exit (non-zero on errors)")
    p.add_argument("--version", action="version", version=VERSION)
    a = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    agent = Agent(a.config)
    if a.once:
        ok, _ = agent.run_once()
        return 0 if ok else 1
    agent.run()


if __name__ == "__main__":
    sys.exit(main())
