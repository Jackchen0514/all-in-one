"""anytls / shadowsocks nodes: panel agent endpoints, subscriptions, and allinone-agent end to end
against fake anytls-server admin API and fake ssmanager."""
import base64
import json
import os
import re
import socket
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from agent import allinone_agent
from allinone.config import Config
from allinone.db import DB
from allinone.service import Service
from tests import test_api


class FakeAnyTLS:
    """Mimics anytls-server's /api/users admin API (and /api/outbound-groups when groups=True,
    like anytls-go >= v0.0.34)."""

    def __init__(self, key="k", groups=False):
        self.users, self.next_id, self.calls = {}, 1, []
        self.groups, self.next_gid, self.tested = {}, 1, []
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, status, obj=None):
                data = json.dumps(obj).encode() if obj is not None else b""
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _handle(self):
                if self.headers.get("Authorization") != "Bearer " + key:
                    return self._reply(401, {"error": "unauthorized"})
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n)) if n else {}
                fake.calls.append((self.command, self.path))
                m = re.match(r"^/api/users/(\d+)$", self.path)
                g = re.match(r"^/api/outbound-groups(?:/(\d+))?(/test)?$", self.path)
                if g and groups:
                    return self._groups(g, body)
                if self.path == "/api/users" and self.command == "GET":
                    return self._reply(200, [dict(u, usage={"traffic_used_bytes": u["used"], "active_conns": u["conns"]})
                                             for u in fake.users.values()])
                if self.path == "/api/users" and self.command == "POST":
                    u = {"id": fake.next_id, "username": body["username"], "password": body["password"],
                         "enabled": body.get("enabled", True), "expires_at": body.get("expires_at") or "0001-01-01T00:00:00Z",
                         "traffic_limit_bytes": body.get("traffic_limit_bytes", 0),
                         "traffic_multiplier": body.get("traffic_multiplier", 0),
                         "traffic_reset_cycle": body.get("traffic_reset_cycle", "none"), "used": 0, "conns": 0}
                    if groups:
                        u["outbound_group_id"] = body.get("outbound_group_id", 0)
                    fake.users[u["id"]] = u
                    fake.next_id += 1
                    return self._reply(201, u)
                if m and int(m.group(1)) in fake.users:
                    u = fake.users[int(m.group(1))]
                    if self.command == "PUT":
                        for k, v in body.items():
                            u[k] = v
                        if "expires_at" in body and not body["expires_at"]:
                            u["expires_at"] = "0001-01-01T00:00:00Z"
                        return self._reply(200, u)
                    if self.command == "DELETE":
                        del fake.users[u["id"]]
                        return self._reply(204)
                return self._reply(404, {"error": "not found"})

            def _groups(self, g, body):
                gid = int(g.group(1)) if g.group(1) else None
                if gid is None and self.command == "GET":
                    return self._reply(200, [{"id": 0, "name": "直连", "socks5_url": ""}] + list(fake.groups.values()))
                if gid is None and self.command == "POST":
                    if any(x["name"] == body["name"] for x in fake.groups.values()):
                        return self._reply(409, {"error": "outbound group name already exists"})
                    x = {"id": fake.next_gid, "name": body["name"], "socks5_url": body["socks5_url"]}
                    fake.groups[x["id"]] = x
                    fake.next_gid += 1
                    return self._reply(201, x)
                if gid not in fake.groups:
                    return self._reply(404, {"error": "outbound group not found"})
                x = fake.groups[gid]
                if g.group(2):
                    fake.tested.append(gid)
                    if x["socks5_url"].startswith("bad"):
                        return self._reply(200, {"target": "1.1.1.1:443", "success": False, "error": "connection refused"})
                    return self._reply(200, {"target": "1.1.1.1:443", "success": True, "latency_ms": 42})
                if self.command == "PUT":
                    x.update({k: body[k] for k in ("name", "socks5_url") if k in body})
                    return self._reply(200, x)
                if self.command == "DELETE":
                    del fake.groups[gid]
                    for u in fake.users.values():
                        if u.get("outbound_group_id") == gid:
                            u["outbound_group_id"] = 0
                    return self._reply(204)
                return self._reply(405, {"error": "method not allowed"})

            do_GET = do_POST = do_PUT = do_DELETE = _handle

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d" % self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def by_name(self, name):
        return next((u for u in self.users.values() if u["username"] == name), None)

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class FakeSSManager:
    """Mimics ssmanager's UDP manager protocol."""

    def __init__(self):
        self.ports, self.traffic, self.log = {}, {}, []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.addr = "127.0.0.1:%d" % self.sock.getsockname()[1]
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while self.running:
            try:
                data, peer = self.sock.recvfrom(65535)
            except OSError:
                return
            msg = data.decode()
            cmd, _, arg = msg.partition(":")
            self.log.append(cmd)
            if cmd == "add":
                p = json.loads(arg)
                self.ports[p["server_port"]] = p
                self.traffic.setdefault(p["server_port"], 0)
                reply = "ok"
            elif cmd == "remove":
                p = json.loads(arg)
                self.ports.pop(p["server_port"], None)
                self.traffic.pop(p["server_port"], None)
                reply = "ok"
            elif cmd == "list":
                reply = json.dumps([{"server_port": p, "password": v["password"]} for p, v in self.ports.items()])
            elif cmd == "ping":
                reply = "stat: " + json.dumps({str(p): b for p, b in self.traffic.items()})
            else:
                reply = "invalid command"
            self.sock.sendto(reply.encode(), peer)

    def close(self):
        self.running = False
        self.sock.close()


class MultiTest(test_api.APITest):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.mkdtemp()

    def node(self, **kw):
        s, n, _ = self.call("POST", "/api/v1/nodes", kw)
        self.assertEqual(s, 201, n)
        return n

    def user(self, name, **kw):
        kw["username"] = name
        s, u, _ = self.call("POST", "/api/v1/users", kw)
        self.assertEqual(s, 201, u)
        return u

    def links(self, u, fmt=""):
        _, data, _ = self.call("GET", u["subscription_url"] + fmt, token=None, raw=True)
        return data.decode() if fmt else base64.b64decode(data).decode().splitlines()

    def write_agent_config(self, nodes):
        for n in nodes:  # never touch this machine's real anytls-server unit
            n.setdefault("unit", os.path.join(self.tmp, "anytls-server.service"))
        path = os.path.join(self.tmp, "agent.json")
        with open(path, "w") as f:
            json.dump({"panel": self.base, "interval": 30, "nodes": nodes}, f)
        return allinone_agent.Agent(path)

    # ------------------------------------------------------------------
    def test_node_validation(self):
        self.assertEqual(self.call("POST", "/api/v1/nodes", {"name": "x", "address": "y", "type": "vmess"})[0], 400)
        self.assertEqual(self.call("POST", "/api/v1/nodes", {"name": "x", "address": "y", "type": "anytls",
                                                              "port": "20000-30000"})[0], 400)
        self.assertEqual(self.call("POST", "/api/v1/nodes", {"name": "x", "address": "y", "type": "shadowsocks",
                                                              "ss_method": "2022-blake3-aes-256-gcm"})[0], 400)
        n = self.node(name="SS", address="y", type="shadowsocks", port="abc")  # port is ignored for ss
        self.assertEqual((n["type"], n["ss_method"]), ("shadowsocks", "aes-256-gcm"))
        # agent nodes are not polled by the panel and cannot use the hysteria auth callback
        self.assertEqual(self.call("POST", "/api/v1/nodes/%d/sync" % n["id"])[0], 400)
        self.user("zed", password="zedpass1")
        self.assertFalse(self.call("POST", "/hy2/auth/" + n["auth_token"], {"auth": "zedpass1"}, token=None)[1]["ok"])
        self.assertEqual(self.call("GET", "/hy2/node/%s/config" % n["auth_token"], token=None)[0], 404)
        _, cfg, _ = self.call("GET", "/api/v1/nodes/%d/config" % n["id"])
        self.assertEqual(json.loads(cfg["agent_config"])["nodes"][0]["token"], n["auth_token"])

    def test_ss_port_allocation(self):
        self.svc.cfg.ss_port_min, self.svc.cfg.ss_port_max = 40000, 40002
        a, b = self.user("a"), self.user("b")
        self.assertEqual((a["ss_port"], b["ss_port"]), (40000, 40001))
        self.assertEqual(self.call("POST", "/api/v1/users", {"username": "c", "ss_port": 40000})[0], 409)
        self.assertEqual(self.call("PATCH", "/api/v1/users/b", {"ss_port": 40000})[0], 409)
        self.assertEqual(self.call("PATCH", "/api/v1/users/b", {"ss_port": 0})[0], 400)
        self.assertEqual(self.user("c")["ss_port"], 40002)
        s, r, _ = self.call("POST", "/api/v1/users", {"username": "d"})
        self.assertEqual(s, 409)
        self.assertIn("no free shadowsocks port", r["error"])
        self.call("DELETE", "/api/v1/users/a")
        self.assertEqual(self.user("d")["ss_port"], 40000)

    def test_migrated_users_get_ss_port(self):
        path = os.path.join(self.tmp, "old.db")
        db = DB(path)
        db.x("INSERT INTO users(username,password,sub_token,created_at,updated_at) VALUES('old','oldpass1','s',0,0)")
        svc = Service(Config(db_path=path, admin_pass="pw"), DB(path))
        self.assertEqual(svc.db.get_user("old")["ss_port"], 40000)

    def test_mixed_subscription(self):
        self.add_node(name="HY", address="hk.example.com", sni="hk.example.com")
        self.node(name="AT", type="anytls", address="hk.example.com", port="8443", sni="hk.example.com")
        self.node(name="SS", type="shadowsocks", address="2001:db8::1", ss_method="chacha20-ietf-poly1305")
        self.node(name="off", type="anytls", address="x", port="1", enabled=False)
        u = self.user("mix", password="mix pass/1")
        links = self.links(u)
        self.assertEqual(links[0], "hysteria2://mix%20pass%2F1@hk.example.com:443/?sni=hk.example.com#HY")
        self.assertEqual(links[1], "anytls://mix%20pass%2F1@hk.example.com:8443/?sni=hk.example.com#AT")
        m = re.match(r"^ss://([A-Za-z0-9_-]+)@\[2001:db8::1\]:(\d+)#SS$", links[2])
        self.assertTrue(m, links[2])
        info = base64.urlsafe_b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4)).decode()
        self.assertEqual((info, int(m.group(2))), ("chacha20-ietf-poly1305:mix pass/1", u["ss_port"]))
        self.assertEqual(len(links), 3)
        clash = self.links(u, "?format=clash")
        self.assertIn("    type: anytls\n    server: \"hk.example.com\"\n    port: 8443\n", clash)
        self.assertIn("    type: ss\n    server: \"2001:db8::1\"\n    port: %d\n    cipher: chacha20-ietf-poly1305\n"
                      % u["ss_port"], clash)
        self.assertIn('proxies: ["HY", "AT", "SS", "DIRECT"]', clash)
        self.call("PATCH", "/api/v1/users/mix", {"enabled": False})
        self.assertEqual(self.links(u), [])

    def test_agent_report_accounting(self):
        n = self.node(name="AT", type="anytls", address="a", port="8443")
        self.user("p", traffic_multiplier=2, traffic_limit=1000)
        self.user("q")
        url = "/agent/%s/report" % n["auth_token"]
        self.assertEqual(self.call("POST", "/agent/nope/report", {}, token=None)[0], 404)
        self.assertEqual(self.call("POST", url, {"counters": []}, token=None)[0], 400)
        # first report of a node is a baseline only
        _, r, _ = self.call("POST", url, {"counters": {"p": 100, "ghost": 5}}, token=None)
        self.assertTrue(r["baseline"])
        self.assertEqual(self.call("GET", "/api/v1/users/p")[1]["used"], 0)
        self.call("POST", url, {"counters": {"p": 150, "q": 30}, "online": 3, "version": "t"}, token=None)
        p, q = self.call("GET", "/api/v1/users/p")[1], self.call("GET", "/api/v1/users/q")[1]
        self.assertEqual((p["download"], q["download"]), (100, 30))  # p: 50 * 2, q: new user counts fully
        # counter went down (server restarted): counts from zero
        self.call("POST", url, {"counters": {"p": 20}}, token=None)
        self.assertEqual(self.call("GET", "/api/v1/users/p")[1]["download"], 140)
        _, node, _ = self.call("GET", "/api/v1/nodes/%d" % n["id"])
        self.assertEqual((node["online"], node["agent_version"], node["agent_synced"]), (0, "", True))
        self.call("POST", url, {"counters": {"p": 1000}, "error": "boom"}, token=None)
        _, node, _ = self.call("GET", "/api/v1/nodes/%d" % n["id"])
        self.assertEqual(node["last_error"], "boom")
        _, st, _ = self.call("GET", "/agent/%s/state" % n["auth_token"], token=None)
        self.assertEqual({u["username"]: u["active"] for u in st["users"]}, {"p": False, "q": True})
        _, hist, _ = self.call("GET", "/api/v1/users/p/traffic")
        self.assertGreater(hist["items"][0]["download"], 0)

    def test_agent_anytls_end_to_end(self):
        fake = FakeAnyTLS()
        self.addCleanup(fake.close)
        n = self.node(name="AT", type="anytls", address="a", port="8443")
        fake.users[99] = {"id": 99, "username": "stale", "password": "x", "enabled": True, "expires_at": "",
                          "used": 7, "conns": 0}
        fake.next_id = 100
        self.user("ann", password="annpass1", traffic_limit=500)
        self.user("ben", password="benpass1")
        agent = self.write_agent_config([{"token": n["auth_token"], "type": "anytls", "api": fake.url, "api_key": "k"}])
        ok, _ = agent.run_once()
        self.assertTrue(ok)
        self.assertEqual(sorted(u["username"] for u in fake.users.values()), ["ann", "ben"])
        ann = fake.by_name("ann")
        self.assertEqual((ann["password"], ann["enabled"], ann["traffic_multiplier"]), ("annpass1", True, 1.0))
        # traffic flows; the next cycle reports it, then ann goes over limit and gets blocked
        ann["used"], fake.by_name("ben")["used"] = 600, 10
        ann["conns"] = 2
        agent.run_once()
        _, u, _ = self.call("GET", "/api/v1/users/ann")
        self.assertEqual((u["download"], u["status"]), (600, "overlimit"))
        ann = fake.by_name("ann")
        self.assertEqual((ann["enabled"], ann["expires_at"]), (False, allinone_agent.BLOCKED_UNTIL))
        self.assertEqual(self.call("GET", "/api/v1/nodes/%d" % n["id"])[1]["online"], 2)
        # reset + password change + delete propagate; a steady state makes no calls but GET
        self.call("POST", "/api/v1/users/ann/reset-traffic")
        self.call("PATCH", "/api/v1/users/ann", {"password": "annpass2"})
        self.call("DELETE", "/api/v1/users/ben")
        agent.run_once()
        ann = fake.by_name("ann")
        self.assertEqual((ann["enabled"], ann["password"], ann["expires_at"][:4]), (True, "annpass2", "0001"))
        self.assertIsNone(fake.by_name("ben"))
        fake.calls.clear()
        agent.run_once()
        self.assertEqual({c[0] for c in fake.calls}, {"GET"})
        self.assertEqual(self.call("GET", "/api/v1/users/ann")[1]["used"], 0)

    def test_agent_shadowsocks_end_to_end(self):
        fake = FakeSSManager()
        self.addCleanup(fake.close)
        n = self.node(name="SS", type="shadowsocks", address="a")
        cyd = self.user("cyd", password="cydpass1")
        dee = self.user("dee", password="deepass1", traffic_multiplier=0.5)
        fake.ports[1234] = {"server_port": 1234, "password": "manual"}
        state = os.path.join(self.tmp, "ss.json")
        agent = self.write_agent_config([{"token": n["auth_token"], "type": "shadowsocks",
                                          "manager": fake.addr, "state": state}])
        self.assertTrue(agent.run_once()[0])
        self.assertEqual(sorted(fake.ports), sorted([cyd["ss_port"], dee["ss_port"]]))
        self.assertEqual((fake.ports[cyd["ss_port"]]["password"], fake.ports[cyd["ss_port"]]["method"]),
                         ("cydpass1", "aes-256-gcm"))
        fake.traffic[cyd["ss_port"]], fake.traffic[dee["ss_port"]] = 300, 400
        agent.run_once()
        self.assertEqual(self.call("GET", "/api/v1/users/cyd")[1]["download"], 300)
        self.assertEqual(self.call("GET", "/api/v1/users/dee")[1]["download"], 200)
        # disabling removes the port; password / method change re-adds it; ssmanager restart is healed
        self.call("PATCH", "/api/v1/users/dee", {"enabled": False})
        self.call("PATCH", "/api/v1/users/cyd", {"password": "cydpass2"})
        self.call("PATCH", "/api/v1/nodes/%d" % n["id"], {"ss_method": "aes-128-gcm"})
        agent.run_once()
        self.assertEqual(list(fake.ports), [cyd["ss_port"]])
        self.assertEqual((fake.ports[cyd["ss_port"]]["password"], fake.ports[cyd["ss_port"]]["method"]),
                         ("cydpass2", "aes-128-gcm"))
        fake.ports.clear()
        fake.traffic.clear()
        fake.log.clear()
        agent.run_once()
        self.assertIn(cyd["ss_port"], fake.ports)
        fake.log.clear()
        agent.run_once()
        self.assertNotIn("add", fake.log)
        # disabling the node removes every port
        self.call("PATCH", "/api/v1/nodes/%d" % n["id"], {"enabled": False})
        agent.run_once()
        self.assertEqual(fake.ports, {})

    def test_agent_errors_reported(self):
        n = self.node(name="SS", type="shadowsocks", address="a")
        self.user("eli")
        dead = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dead.bind(("127.0.0.1", 0))  # bound but never answers
        self.addCleanup(dead.close)
        agent = self.write_agent_config([
            {"token": n["auth_token"], "type": "shadowsocks", "manager": "127.0.0.1:%d" % dead.getsockname()[1],
             "timeout": 0.2, "state": os.path.join(self.tmp, "s.json")},
            {"token": "wrong", "type": "anytls", "api": "http://127.0.0.1:1", "api_key": "k"}])
        ok, _ = agent.run_once()
        self.assertFalse(ok)
        _, node, _ = self.call("GET", "/api/v1/nodes/%d" % n["id"])
        self.assertIn("did not answer", node["last_error"])
        self.assertEqual(allinone_agent.main(["--config", agent.config_path, "--once"]), 1)

    def test_import_anytls(self):
        self.user("taken", password="takenpw1")
        items = [
            {"id": 1, "username": "amy", "password": "amypass1", "enabled": True, "traffic_limit_bytes": 1000,
             "traffic_multiplier": 1.5, "traffic_reset_cycle": "monthly", "traffic_reset_at": "2026-03-17T08:00:00Z",
             "expires_at": "2027-01-02T03:04:05.123456789Z", "usage": {"traffic_used_bytes": 300}},
            {"id": 2, "username": "张三", "password": "zhangpw1", "enabled": False, "traffic_reset_cycle": "daily",
             "expires_at": "0001-01-01T00:00:00Z", "usage": {"traffic_used_bytes": 0}},
            {"id": 3, "username": "taken", "password": "other", "usage": {}},
            {"id": 4, "username": "dup", "password": "takenpw1", "usage": {}},
            {"id": 5, "username": "bad"},
        ]
        self.assertEqual(self.call("POST", "/api/v1/import", {"source": "x", "items": []})[0], 400)
        s, r, _ = self.call("POST", "/api/v1/import", {"source": "anytls", "items": items})
        self.assertEqual((s, r["created"]), (200, ["amy", "anytls2"]))
        self.assertEqual([x["item"] for x in r["skipped"]], ["taken", "dup", "bad"])
        _, amy, _ = self.call("GET", "/api/v1/users/amy")
        self.assertEqual((amy["traffic_limit"], amy["download"], amy["traffic_multiplier"], amy["reset_day"],
                          amy["expire_at"], amy["status"]), (1000, 300, 1.5, 17, 1798859045, "active"))  # 2027-01-02T03:04:05Z
        _, z, _ = self.call("GET", "/api/v1/users/anytls2")
        self.assertEqual((z["status"], z["expire_at"]), ("disabled", 0))
        self.assertIn("daily", z["note"])
        # importing again is idempotent
        _, r, _ = self.call("POST", "/api/v1/import", {"source": "anytls", "items": items[:1]})
        self.assertEqual((r["created"], r["skipped"][0]["reason"]), ([], "exists"))

    def test_import_ssmanager(self):
        rows = [
            {"server_port": 8388, "password": "p1", "method": "aes-256-gcm", "remark": "香港用户", "enabled": 1,
             "traffic_limit_bytes": 0, "total_bytes": 999, "expires_at": None},
            {"server_port": 8389, "password": "p2", "method": "chacha20-ietf-poly1305", "remark": "bob", "enabled": 0,
             "limit_exceeded": 1, "traffic_limit_bytes": 10, "total_bytes": 20, "expires_at": "2026-01-01T00:00:00.000Z",
             "traffic_multiplier": 1.9},
            {"server_port": 8390, "password": "p3", "method": "aes-256-gcm", "remark": "off", "enabled": 0},
        ]
        self.user("bob", password="bobs-own")  # name clash -> bob-ss8389
        s, r, _ = self.call("POST", "/api/v1/import", {"source": "ssmanager", "items": rows})
        self.assertEqual(r["created"], ["ss8388", "bob-ss8389", "off"])
        self.assertEqual(r["methods"], {"aes-256-gcm": 2, "chacha20-ietf-poly1305": 1})
        _, u, _ = self.call("GET", "/api/v1/users/ss8388")
        self.assertEqual((u["ss_port"], u["download"], u["status"]), (8388, 999, "active"))
        self.assertIn("香港用户", u["note"])
        _, u, _ = self.call("GET", "/api/v1/users/bob-ss8389")
        self.assertEqual((u["ss_port"], u["status"], u["traffic_multiplier"]), (8389, "expired", 1.9))
        self.assertEqual(self.call("GET", "/api/v1/users/off")[1]["status"], "disabled")
        _, r, _ = self.call("POST", "/api/v1/import", {"source": "ssmanager", "items": rows[:2]})
        self.assertEqual([x["reason"] for x in r["skipped"]], ["exists", "exists"])

    def test_set_used_traffic(self):
        self.add_node()
        G = 1024 ** 3
        _, u, _ = self.call("POST", "/api/v1/users", {"username": "su", "traffic_limit_gb": 10, "used_gb": 2})
        self.assertEqual((u["upload"], u["download"], u["used"]), (0, 2 * G, 2 * G))
        self.call("PATCH", "/api/v1/users/su", {"upload": 100, "download": 200})
        _, u, _ = self.call("POST", "/api/v1/users/su/set-traffic", {"gb": 1.5})
        self.assertEqual((u["upload"], u["download"]), (0, int(1.5 * G)))
        _, u, _ = self.call("POST", "/api/v1/users/su/set-traffic", {"upload": 10, "download": 20})
        self.assertEqual((u["upload"], u["download"]), (10, 20))
        _, u, _ = self.call("POST", "/api/v1/users/su/set-traffic", {"download": 30})
        self.assertEqual((u["upload"], u["download"]), (10, 30))
        _, u, _ = self.call("POST", "/api/v1/users/su/set-traffic", {"add_bytes": -35})
        self.assertEqual((u["upload"], u["download"]), (5, 0))
        _, u, _ = self.call("POST", "/api/v1/users/su/set-traffic", {"add_bytes": -100})
        self.assertEqual(u["used"], 0)
        # over the limit -> overlimit and kicked; back under -> active again
        _, u, _ = self.call("POST", "/api/v1/users/su/set-traffic", {"add_gb": 11})
        self.assertEqual(u["status"], "overlimit")
        self.assertIn("su", self.fake.kicked)
        _, u, _ = self.call("PATCH", "/api/v1/users/su", {"used_gb": 3})
        self.assertEqual((u["upload"], u["download"], u["status"]), (0, 3 * G, "active"))
        _, u, _ = self.call("PATCH", "/api/v1/users/su", {"used": 7})
        self.assertEqual(u["used"], 7)
        for bad in ({}, {"gb": 1, "bytes": 2}, {"gb": 1, "add_gb": 1}, {"gb": -1}, {"bytes": -1},
                    {"gb": "x"}, {"gb": "nan"}, {"gb": "inf"}, {"upload": -1}, {"add_gb": "inf"}):
            self.assertEqual(self.call("POST", "/api/v1/users/su/set-traffic", bad)[0], 400, bad)
        self.assertEqual(self.call("PATCH", "/api/v1/users/su", {"used": 1, "upload": 1})[0], 400)
        self.assertEqual(self.call("POST", "/api/v1/users/nobody/set-traffic", {"gb": 1})[0], 404)
        _, u, _ = self.call("GET", "/api/v1/users/su")
        self.assertEqual(u["used"], 7)

    def test_outbound_groups_api(self):
        s, g, _ = self.call("POST", "/api/v1/outbound-groups", {"name": "US", "socks5_url": "127.0.0.1:1080"})
        self.assertEqual((s, g["name"], g["users"], g["status"]), (201, "US", 0, []))
        for bad in ({"name": "", "socks5_url": "1.2.3.4:1080"}, {"name": "x", "socks5_url": ""},
                    {"name": "x", "socks5_url": "1.2.3.4"}, {"name": "x", "socks5_url": "http://1.2.3.4:80"},
                    {"name": "x", "socks5_url": "1.2.3.4:99999"}, {"name": "x" * 65, "socks5_url": "a:1"}):
            self.assertEqual(self.call("POST", "/api/v1/outbound-groups", bad)[0], 400, bad)
        self.assertEqual(self.call("POST", "/api/v1/outbound-groups", {"name": "US", "socks5_url": "a:1"})[0], 409)
        _, g2, _ = self.call("POST", "/api/v1/outbound-groups", {"name": "JP", "socks5_url": "socks5://u:p@jp.example:1080"})
        self.assertEqual(self.call("PATCH", "/api/v1/outbound-groups/%d" % g2["id"], {"name": "US"})[0], 409)
        _, g2, _ = self.call("PATCH", "/api/v1/outbound-groups/%d" % g2["id"], {"note": "tokyo"})
        self.assertEqual((g2["name"], g2["note"]), ("JP", "tokyo"))
        # users reference a group; unknown ids are rejected; deleting a group moves users to direct
        u = self.user("gus", outbound_group_id=g["id"])
        self.assertEqual(u["outbound_group_id"], g["id"])
        self.assertEqual(self.call("POST", "/api/v1/users", {"username": "x1", "outbound_group_id": 999})[0], 400)
        self.assertEqual(self.call("PATCH", "/api/v1/users/gus", {"outbound_group_id": 999})[0], 400)
        self.assertEqual(self.call("PATCH", "/api/v1/users/gus", {"outbound_group_id": -1})[0], 400)
        self.assertEqual(self.call("GET", "/api/v1/outbound-groups/%d" % g["id"])[1]["users"], 1)
        _, d, _ = self.call("DELETE", "/api/v1/outbound-groups/%d" % g["id"])
        self.assertEqual(d["users_moved_to_direct"], 1)
        self.assertEqual(self.call("GET", "/api/v1/users/gus")[1]["outbound_group_id"], 0)
        self.assertEqual(self.call("GET", "/api/v1/outbound-groups/%d" % g["id"])[0], 404)
        self.assertEqual([x["name"] for x in self.call("GET", "/api/v1/outbound-groups")[1]["items"]], ["JP"])

    def test_agent_anytls_outbound_groups(self):
        fake = FakeAnyTLS(groups=True)
        self.addCleanup(fake.close)
        # a group created by hand on the server is left alone
        fake.groups[50] = {"id": 50, "name": "manual", "socks5_url": "9.9.9.9:1080"}
        fake.next_gid = 51
        n = self.node(name="AT", type="anytls", address="a", port="8443")
        _, us, _ = self.call("POST", "/api/v1/outbound-groups", {"name": "US", "socks5_url": "127.0.0.1:1080"})
        _, bad, _ = self.call("POST", "/api/v1/outbound-groups", {"name": "Dead", "socks5_url": "bad.example:1"})
        self.user("amy", password="amypass1", outbound_group_id=us["id"])
        self.user("bob", password="bobpass1")
        agent = self.write_agent_config([{"token": n["auth_token"], "type": "anytls", "api": fake.url, "api_key": "k"}])
        self.assertTrue(agent.run_once()[0])
        names = {x["name"]: x for x in fake.groups.values()}
        self.assertEqual(sorted(names), sorted(["manual", "aio-%d US" % us["id"], "aio-%d Dead" % bad["id"]]))
        self.assertEqual(fake.by_name("amy")["outbound_group_id"], names["aio-%d US" % us["id"]]["id"])
        self.assertEqual(fake.by_name("bob")["outbound_group_id"], 0)
        self.assertEqual(len(fake.tested), 2)
        # test results reach the panel with the next report
        agent.run_once()
        st = {x["name"]: x["status"] for x in self.call("GET", "/api/v1/outbound-groups")[1]["items"]}
        self.assertEqual([(x["node"], x["ok"], x["latency_ms"]) for x in st["US"]], [("AT", True, 42)])
        self.assertEqual((st["Dead"][0]["ok"], st["Dead"][0]["error"]), (False, "connection refused"))
        # steady state: no writes, no re-test within TEST_EVERY
        fake.calls.clear()
        agent.run_once()
        self.assertEqual({c[0] for c in fake.calls}, {"GET"})
        self.assertEqual(len(fake.tested), 2)
        # rename + new address -> PUT and an immediate re-test; old status is dropped in the panel
        self.call("PATCH", "/api/v1/outbound-groups/%d" % us["id"], {"name": "USA", "socks5_url": "127.0.0.1:1081"})
        self.assertEqual(self.call("GET", "/api/v1/outbound-groups/%d" % us["id"])[1]["status"], [])
        agent.run_once()
        x = fake.groups[names["aio-%d US" % us["id"]]["id"]]
        self.assertEqual((x["name"], x["socks5_url"]), ("aio-%d USA" % us["id"], "127.0.0.1:1081"))
        self.assertEqual(len(fake.tested), 3)
        # moving a user and deleting a group propagate; the hand-made group survives
        self.call("PATCH", "/api/v1/users/bob", {"outbound_group_id": bad["id"]})
        self.call("DELETE", "/api/v1/outbound-groups/%d" % us["id"])
        agent.run_once()
        self.assertEqual(sorted(x["name"] for x in fake.groups.values()), sorted(["manual", "aio-%d Dead" % bad["id"]]))
        self.assertEqual(fake.by_name("amy")["outbound_group_id"], 0)
        self.assertEqual(fake.by_name("bob")["outbound_group_id"], names["aio-%d Dead" % bad["id"]]["id"])

    def test_agent_anytls_listen_port(self):
        fake = FakeAnyTLS()
        self.addCleanup(fake.close)
        unit = os.path.join(self.tmp, "at.service")
        orig = ("[Unit]\nDescription=AnyTLS Server (managed by allinone-agent)\n[Service]\n"
                "ExecStart=/usr/local/bin/anytls-server -l 0.0.0.0:9443 -p x -api-listen 127.0.0.1:8843\n")
        with open(unit, "w") as f:
            f.write(orig)
        restarts, fw, up = [], [], [True]
        busy = set()
        patches = {"_restart": lambda drv: restarts.append(open(unit).read()) or up[0]}
        for k, v in patches.items():
            old = getattr(allinone_agent.AnyTLS, k)
            setattr(allinone_agent.AnyTLS, k, v)
            self.addCleanup(setattr, allinone_agent.AnyTLS, k, old)
        for k, v in {"open_firewall": lambda p, protos=("tcp", "udp"): fw.append((p, protos)),
                     "port_free": lambda p: p not in busy}.items():
            old = getattr(allinone_agent, k)
            setattr(allinone_agent, k, v)
            self.addCleanup(setattr, allinone_agent, k, old)
        n = self.node(name="AT", type="anytls", address="a", port="9443")
        agent = self.write_agent_config([{"token": n["auth_token"], "type": "anytls", "api": fake.url,
                                          "api_key": "k", "unit": unit}])
        node = lambda: self.call("GET", "/api/v1/nodes/%d" % n["id"])[1]
        self.assertTrue(agent.run_once()[0])
        self.assertEqual(restarts, [])
        agent.run_once()
        self.assertEqual((node()["agent_port"], node()["port_pending"]), ("9443", False))
        # port changed in the panel -> unit rewritten, firewall opened, restarted
        self.call("PATCH", "/api/v1/nodes/%d" % n["id"], {"port": "10443"})
        self.assertTrue(node()["port_pending"])
        self.assertTrue(agent.run_once()[0])
        self.assertEqual(open(unit).read(), orig.replace("0.0.0.0:9443", "0.0.0.0:10443"))
        self.assertEqual((len(restarts), fw), (1, [(10443, ("tcp",))]))
        agent.run_once()
        self.assertEqual((node()["agent_port"], node()["port_pending"]), ("10443", False))
        # busy port: nothing touched, error reported
        busy.add(11443)
        self.call("PATCH", "/api/v1/nodes/%d" % n["id"], {"port": "11443"})
        self.assertFalse(agent.run_once()[0])
        self.assertEqual(len(restarts), 1)
        agent.run_once()
        self.assertIn("already in use", node()["last_error"])
        self.assertTrue(node()["port_pending"])
        # server does not come back -> rolled back, not retried every cycle
        busy.clear()
        up[0] = False
        self.call("PATCH", "/api/v1/nodes/%d" % n["id"], {"port": "12443"})
        self.assertFalse(agent.run_once()[0])
        self.assertIn("0.0.0.0:10443", open(unit).read())
        self.assertEqual(len(restarts), 3)  # try + rollback
        agent.run_once()
        self.assertEqual(len(restarts), 3)
        self.assertIn("did not start on port 12443", node()["last_error"])
        # a unit not written by install.sh is never edited
        up[0] = True
        with open(unit, "w") as f:
            f.write(orig.replace(" (managed by allinone-agent)", ""))
        self.call("PATCH", "/api/v1/nodes/%d" % n["id"], {"port": "13443"})
        self.assertTrue(agent.run_once()[0])
        self.assertEqual(len(restarts), 3)

    def test_agent_anytls_too_old_for_groups(self):
        fake = FakeAnyTLS()  # no /api/outbound-groups
        self.addCleanup(fake.close)
        n = self.node(name="AT", type="anytls", address="a", port="8443")
        agent = self.write_agent_config([{"token": n["auth_token"], "type": "anytls", "api": fake.url, "api_key": "k"}])
        _, g, _ = self.call("POST", "/api/v1/outbound-groups", {"name": "US", "socks5_url": "127.0.0.1:1080"})
        self.user("cat", password="catpass1")
        self.assertTrue(agent.run_once()[0])  # groups exist but nobody uses them: fine
        self.call("PATCH", "/api/v1/users/cat", {"outbound_group_id": g["id"]})
        self.assertFalse(agent.run_once()[0])
        agent.run_once()
        self.assertIn("too old for outbound groups", self.call("GET", "/api/v1/nodes/%d" % n["id"])[1]["last_error"])

    def test_import_anytls_groups(self):
        self.call("POST", "/api/v1/outbound-groups", {"name": "HK", "socks5_url": "8.8.8.8:1080"})
        groups = [{"id": 0, "name": "直连", "socks5_url": ""},
                  {"id": 3, "name": "US", "socks5_url": "1.2.3.4:1080"},
                  {"id": 4, "name": "HK", "socks5_url": "8.8.8.8:1080"},       # same as the panel's -> reused
                  {"id": 5, "name": "HK", "socks5_url": "7.7.7.7:1080"},       # clash -> renamed
                  {"id": 6, "name": "aio-9 X", "socks5_url": "6.6.6.6:1080"},  # agent-managed -> skipped
                  {"id": 7, "name": "Bad", "socks5_url": "nope"}]
        items = [{"id": i, "username": n, "password": n + "pass1", "enabled": True, "outbound_group_id": gid}
                 for i, (n, gid) in enumerate([("ia", 3), ("ib", 4), ("ic", 5), ("id", 0), ("ie", 7)], 1)]
        s, r, _ = self.call("POST", "/api/v1/import", {"source": "anytls", "items": items, "outbound_groups": groups})
        self.assertEqual(s, 200, r)
        self.assertEqual(sorted(r["groups_created"]), ["HK (anytls 5)", "US"])
        byname = {g["name"]: g["id"] for g in self.call("GET", "/api/v1/outbound-groups")[1]["items"]}
        got = {n: self.call("GET", "/api/v1/users/" + n)[1]["outbound_group_id"] for n in ("ia", "ib", "ic", "id", "ie")}
        self.assertEqual(got, {"ia": byname["US"], "ib": byname["HK"], "ic": byname["HK (anytls 5)"], "id": 0, "ie": 0})
        self.assertEqual(self.call("POST", "/api/v1/import", {"source": "anytls", "items": [], "outbound_groups": {}})[0], 400)

    def test_node_traffic_multiplier(self):
        hy = self.add_node(traffic_multiplier=2)
        at = self.node(name="AT", type="anytls", address="a", port="8443", traffic_multiplier=0.5)
        self.assertEqual((hy["traffic_multiplier"], at["traffic_multiplier"]), (2.0, 0.5))
        for bad in (-1, 101, "x"):
            self.assertEqual(self.call("PATCH", "/api/v1/nodes/%d" % at["id"], {"traffic_multiplier": bad})[0], 400)
        self.assertEqual(self.node(name="d", type="shadowsocks", address="d")["traffic_multiplier"], 1.0)
        self.user("nm", traffic_multiplier=1.5)
        # hysteria2: panel-side sync -> 100 * 1.5 * 2, 1000 * 1.5 * 2
        self.fake.traffic = {"nm": {"tx": 100, "rx": 1000}}
        self.call("POST", "/api/v1/sync")
        _, u, _ = self.call("GET", "/api/v1/users/nm")
        self.assertEqual((u["upload"], u["download"]), (300, 3000))
        # anytls: agent report (first report is a baseline) -> 400 * 1.5 * 0.5
        url = "/agent/%s/report" % at["auth_token"]
        self.call("POST", url, {"counters": {"nm": 0}}, token=None)
        self.call("POST", url, {"counters": {"nm": 400}}, token=None)
        self.assertEqual(self.call("GET", "/api/v1/users/nm")[1]["download"], 3300)
        # 0 = this node is free
        self.call("PATCH", "/api/v1/nodes/%d" % at["id"], {"traffic_multiplier": 0})
        self.call("POST", url, {"counters": {"nm": 900}}, token=None)
        self.assertEqual(self.call("GET", "/api/v1/users/nm")[1]["download"], 3300)

    def test_node_multiplier_migration(self):
        """An existing database (installed before node multipliers) is upgraded in place."""
        import sqlite3
        path = os.path.join(self.tmp, "pre.db")
        c = sqlite3.connect(path)
        c.execute("CREATE TABLE nodes (id INTEGER PRIMARY KEY, name TEXT NOT NULL, address TEXT NOT NULL, "
                  "port TEXT NOT NULL DEFAULT '443', auth_token TEXT NOT NULL, created_at INTEGER NOT NULL)")
        c.execute("INSERT INTO nodes(name,address,auth_token,created_at) VALUES('a','b','t',0)")
        c.commit()
        c.close()
        self.assertEqual(DB(path).get_node(1)["traffic_multiplier"], 1.0)

    def test_agent_type_mismatch(self):
        fake = FakeAnyTLS()
        self.addCleanup(fake.close)
        n = self.node(name="SS", type="shadowsocks", address="a")
        agent = self.write_agent_config([{"token": n["auth_token"], "type": "anytls", "api": fake.url, "api_key": "k"}])
        self.assertFalse(agent.run_once()[0])
        self.assertEqual(fake.users, {})


# Don't run the inherited hysteria tests a second time.
for _name in [k for k in vars(test_api.APITest) if k.startswith("test_")]:
    setattr(MultiTest, _name, None)

if __name__ == "__main__":
    unittest.main()
