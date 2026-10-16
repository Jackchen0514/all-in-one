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
    """Mimics anytls-server's /api/users admin API."""

    def __init__(self, key="k"):
        self.users, self.next_id, self.calls = {}, 1, []
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
                if self.path == "/api/users" and self.command == "GET":
                    return self._reply(200, [dict(u, usage={"traffic_used_bytes": u["used"], "active_conns": u["conns"]})
                                             for u in fake.users.values()])
                if self.path == "/api/users" and self.command == "POST":
                    u = {"id": fake.next_id, "username": body["username"], "password": body["password"],
                         "enabled": body.get("enabled", True), "expires_at": body.get("expires_at") or "0001-01-01T00:00:00Z",
                         "traffic_limit_bytes": body.get("traffic_limit_bytes", 0),
                         "traffic_multiplier": body.get("traffic_multiplier", 0),
                         "traffic_reset_cycle": body.get("traffic_reset_cycle", "none"), "used": 0, "conns": 0}
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
