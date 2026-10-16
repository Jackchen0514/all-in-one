import base64
import datetime
import json
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from allinone.config import Config
from allinone.db import DB
from allinone.server import make_server
from allinone.service import GB, Service


class FakeHy2:
    """Mimics the hysteria2 trafficStats API."""

    def __init__(self, secret="s3cret"):
        self.secret = secret
        self.traffic = {}
        self.online = {}
        self.kicked = []
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, obj):
                data = json.dumps(obj).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if self.headers.get("Authorization") != fake.secret:
                    self.send_response(401)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path.startswith("/traffic"):
                    data = fake.traffic
                    if "clear=1" in self.path:
                        fake.traffic = {}
                    return self._reply(data)
                if self.path == "/online":
                    return self._reply(fake.online)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                fake.kicked.extend(body)
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d" % self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class APITest(unittest.TestCase):
    def setUp(self):
        self.cfg = Config(db_path=":memory:", admin_pass="pw", api_token="tok")
        self.svc = Service(self.cfg, DB(":memory:"))
        self.srv = make_server(self.svc, "127.0.0.1", 0)
        self.base = "http://127.0.0.1:%d" % self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.fake = FakeHy2()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.fake.close()

    def call(self, method, path, body=None, token="tok", raw=False, headers=None):
        req = urllib.request.Request(self.base + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None)
        if token:
            req.add_header("Authorization", "Bearer " + token)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req) as r:
                data = r.read()
                return r.status, (data if raw else json.loads(data)), r.headers
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read()), e.headers

    def add_node(self, **kw):
        body = {"name": "n1", "address": "1.2.3.4", "port": "443", "api_url": self.fake.url,
                "api_secret": "s3cret"}
        body.update(kw)
        s, n, _ = self.call("POST", "/api/v1/nodes", body)
        self.assertEqual(s, 201)
        return n

    # ------------------------------------------------------------------
    def test_auth_required(self):
        self.assertEqual(self.call("GET", "/api/v1/users", token=None)[0], 401)
        self.assertEqual(self.call("GET", "/api/v1/users", token="nope")[0], 401)
        s, r, _ = self.call("POST", "/api/v1/login", {"username": "admin", "password": "pw"}, token=None)
        self.assertEqual(s, 200)
        self.assertEqual(self.call("GET", "/api/v1/users", token=r["token"])[0], 200)
        self.assertEqual(self.call("POST", "/api/v1/login", {"username": "admin", "password": "x"}, token=None)[0], 401)

    def test_version(self):
        from allinone import __version__
        self.assertEqual(self.call("GET", "/api/v1/version", token=None)[0], 401)
        s, r, _ = self.call("GET", "/api/v1/version")
        self.assertEqual((s, r["version"]), (200, __version__))
        self.assertIn("commit", r)

    def test_user_crud_and_validation(self):
        s, u, _ = self.call("POST", "/api/v1/users", {"username": "bob", "traffic_limit_gb": 10, "expire_days": 30})
        self.assertEqual(s, 201)
        self.assertEqual(u["traffic_limit"], 10 * GB)
        self.assertAlmostEqual(u["expire_at"], time.time() + 30 * 86400, delta=5)
        self.assertEqual(u["status"], "active")
        self.assertGreaterEqual(len(u["password"]), 12)
        self.assertEqual(self.call("POST", "/api/v1/users", {"username": "bob"})[0], 409)
        self.assertEqual(self.call("POST", "/api/v1/users", {"username": "bad name!"})[0], 400)
        self.assertEqual(self.call("POST", "/api/v1/users", {"username": "x", "reset_day": 40})[0], 400)
        s, u, _ = self.call("PATCH", "/api/v1/users/bob", {"enabled": False, "note": "hi"})
        self.assertEqual((u["status"], u["note"]), ("disabled", "hi"))
        s, r, _ = self.call("GET", "/api/v1/users?status=disabled")
        self.assertEqual(r["total"], 1)
        self.assertEqual(self.call("DELETE", "/api/v1/users/bob")[0], 200)
        self.assertEqual(self.call("GET", "/api/v1/users/bob")[0], 404)

    def test_extend(self):
        self.call("POST", "/api/v1/users", {"username": "c"})
        _, u, _ = self.call("POST", "/api/v1/users/c/extend", {"days": 10})
        self.assertAlmostEqual(u["expire_at"], time.time() + 10 * 86400, delta=5)
        _, u, _ = self.call("POST", "/api/v1/users/c/extend", {"days": 5})
        self.assertAlmostEqual(u["expire_at"], time.time() + 15 * 86400, delta=5)
        _, u, _ = self.call("POST", "/api/v1/users/c/extend", {"days": -20})
        self.assertEqual(u["status"], "expired")
        # extending an expired user counts from now
        _, u, _ = self.call("POST", "/api/v1/users/c/extend", {"days": 1})
        self.assertAlmostEqual(u["expire_at"], time.time() + 86400, delta=5)
        self.assertEqual(u["status"], "active")

    def test_hy2_auth_callback(self):
        n = self.add_node()
        _, u, _ = self.call("POST", "/api/v1/users", {"username": "dan", "password": "danpass1"})
        url = "/hy2/auth/" + n["auth_token"]
        self.assertEqual(self.call("POST", url, {"auth": "danpass1"}, token=None)[1], {"ok": True, "id": "dan"})
        self.assertFalse(self.call("POST", url, {"auth": "wrong"}, token=None)[1]["ok"])
        self.assertFalse(self.call("POST", "/hy2/auth/bad", {"auth": "danpass1"}, token=None)[1]["ok"])
        self.call("PATCH", "/api/v1/users/dan", {"traffic_limit": 100, "upload": 100})
        self.assertFalse(self.call("POST", url, {"auth": "danpass1"}, token=None)[1]["ok"])
        self.call("POST", "/api/v1/users/dan/reset-traffic")
        self.assertTrue(self.call("POST", url, {"auth": "danpass1"}, token=None)[1]["ok"])
        self.call("PATCH", "/api/v1/nodes/%d" % n["id"], {"enabled": False})
        self.assertFalse(self.call("POST", url, {"auth": "danpass1"}, token=None)[1]["ok"])

    def test_sync_accounts_and_kicks(self):
        self.add_node()
        self.call("POST", "/api/v1/users", {"username": "eve", "traffic_limit": 1000})
        self.call("POST", "/api/v1/users", {"username": "fay"})
        self.fake.traffic = {"eve": {"tx": 300, "rx": 800}, "fay": {"tx": 5, "rx": 7}, "ghost": {"tx": 1, "rx": 1}}
        self.fake.online = {"eve": 1, "fay": 2, "ghost": 1}
        s, r, _ = self.call("POST", "/api/v1/sync")
        self.assertEqual(s, 200)
        self.assertEqual(sorted(self.fake.kicked), ["eve", "ghost"])
        _, eve, _ = self.call("GET", "/api/v1/users/eve")
        self.assertEqual((eve["upload"], eve["download"], eve["status"]), (300, 800, "overlimit"))
        _, fay, _ = self.call("GET", "/api/v1/users/fay")
        self.assertEqual((fay["upload"], fay["download"]), (5, 7))
        self.assertEqual(self.fake.traffic, {})  # cleared on the node
        _, nodes, _ = self.call("GET", "/api/v1/nodes")
        self.assertEqual(nodes["items"][0]["online"], 2)
        _, hist, _ = self.call("GET", "/api/v1/users/eve/traffic")
        self.assertEqual(hist["items"][0]["download"], 800)
        # add traffic brings eve back
        _, eve, _ = self.call("POST", "/api/v1/users/eve/add-traffic", {"bytes": 1000})
        self.assertEqual(eve["status"], "active")

    def test_traffic_multiplier(self):
        self.add_node()
        _, u, _ = self.call("POST", "/api/v1/users", {"username": "x2", "traffic_multiplier": 2})
        self.assertEqual(u["traffic_multiplier"], 2.0)
        _, u, _ = self.call("POST", "/api/v1/users", {"username": "def"})
        self.assertEqual(u["traffic_multiplier"], 1.0)
        self.call("POST", "/api/v1/users", {"username": "free", "traffic_multiplier": 0})
        self.call("POST", "/api/v1/users", {"username": "half"})
        _, u, _ = self.call("PATCH", "/api/v1/users/half", {"traffic_multiplier": 0.5})
        self.assertEqual(u["traffic_multiplier"], 0.5)
        for bad in (-1, 101, "abc"):
            self.assertEqual(self.call("PATCH", "/api/v1/users/half", {"traffic_multiplier": bad})[0], 400)
        self.fake.traffic = {n: {"tx": 100, "rx": 1001} for n in ("x2", "def", "free", "half")}
        self.call("POST", "/api/v1/sync")
        got = {n: (u["upload"], u["download"]) for n in ("x2", "def", "free", "half")
               for u in [self.call("GET", "/api/v1/users/" + n)[1]]}
        self.assertEqual(got, {"x2": (200, 2002), "def": (100, 1001), "free": (0, 0), "half": (50, 500)})
        _, hist, _ = self.call("GET", "/api/v1/users/x2/traffic")
        self.assertEqual(hist["items"][0]["download"], 2002)

    def test_sync_error_recorded(self):
        self.add_node(api_secret="wrong")
        _, r, _ = self.call("POST", "/api/v1/sync")
        self.assertIn("error", list(r.values())[0])
        _, nodes, _ = self.call("GET", "/api/v1/nodes")
        self.assertIn("401", nodes["items"][0]["last_error"])

    def test_disable_kicks(self):
        self.add_node()
        self.call("POST", "/api/v1/users", {"username": "kim"})
        self.call("PATCH", "/api/v1/users/kim", {"enabled": False})
        self.assertEqual(self.fake.kicked, ["kim"])

    def test_subscription(self):
        self.add_node(name="HK", address="hk.example.com", port="20000-30000", sni="hk.example.com",
                      obfs_password="ob")
        _, u, _ = self.call("POST", "/api/v1/users", {"username": "lee", "password": "leepass1",
                                                      "traffic_limit_gb": 1})
        sub = u["subscription_url"]
        s, data, h = self.call("GET", sub, token=None, raw=True)
        links = base64.b64decode(data).decode().splitlines()
        self.assertEqual(links, ["hysteria2://leepass1@hk.example.com:20000-30000/"
                                 "?sni=hk.example.com&obfs=salamander&obfs-password=ob#HK"])
        self.assertIn("total=%d" % GB, h["Subscription-Userinfo"])
        _, clash, _ = self.call("GET", sub + "?format=clash", token=None, raw=True)
        clash = clash.decode()
        self.assertIn("port: 20000", clash)
        self.assertIn('ports: "20000-30000"', clash)
        self.assertIn("obfs: salamander", clash)
        self.assertEqual(self.call("GET", "/sub/nope", token=None)[0], 404)
        # regenerate invalidates old sub url
        self.call("POST", "/api/v1/users/lee/regenerate", {})
        self.assertEqual(self.call("GET", sub, token=None)[0], 404)

    def test_port_hopping(self):
        for bad in ("abc", "30000-20000", "0-10", "20000-70000", "1-2-3"):
            self.assertEqual(self.call("POST", "/api/v1/nodes", {"name": "x", "address": "y", "hop_ports": bad})[0],
                             400, bad)
        self.assertEqual(self.call("POST", "/api/v1/nodes", {"name": "x", "address": "y", "hop_interval": 1})[0], 400)
        n = self.add_node(name="JP", address="jp.example.com", port="443", hop_ports="20000:30000, 40000-40100",
                          hop_interval=20)
        self.assertEqual((n["hop_ports"], n["hop_interval"]), ("20000-30000,40000-40100", 20))
        _, u, _ = self.call("POST", "/api/v1/users", {"username": "hop", "password": "hoppass1"})
        _, data, _ = self.call("GET", u["subscription_url"], token=None, raw=True)
        self.assertEqual(base64.b64decode(data).decode(),
                         "hysteria2://hoppass1@jp.example.com:443/?mport=20000-30000%2C40000-40100#JP")
        _, clash, _ = self.call("GET", u["subscription_url"] + "?format=clash", token=None, raw=True)
        clash = clash.decode()
        self.assertIn("port: 443\n", clash)
        self.assertIn('ports: "20000-30000/40000-40100"', clash)
        self.assertIn("hop-interval: 20", clash)
        # agent sync status includes hop ports
        url = "/hy2/node/%s/config" % n["auth_token"]
        _, r, _ = self.call("GET", url + "?port=443&obfs=&hop=", token=None)
        self.assertEqual(r["hop_ports"], "20000-30000,40000-40100")
        self.assertFalse(self.call("GET", "/api/v1/nodes/%d" % n["id"])[1]["agent_synced"])
        self.call("GET", url + "?port=443&obfs=&hop=20000-30000,40000-40100", token=None)
        self.assertTrue(self.call("GET", "/api/v1/nodes/%d" % n["id"])[1]["agent_synced"])
        # turning hopping off
        _, n, _ = self.call("PATCH", "/api/v1/nodes/%d" % n["id"], {"hop_ports": ""})
        self.assertEqual(n["hop_ports"], "")
        _, data, _ = self.call("GET", u["subscription_url"], token=None, raw=True)
        self.assertNotIn("mport", base64.b64decode(data).decode())

    def test_node_config(self):
        n = self.add_node(obfs_password="ob")
        _, r, _ = self.call("GET", "/api/v1/nodes/%d/config" % n["id"])
        self.assertIn("/hy2/auth/" + n["auth_token"], r["yaml"])
        self.assertIn("secret: s3cret", r["yaml"])
        self.assertIn("password: ob", r["yaml"])
        self.assertEqual(self.call("POST", "/api/v1/nodes", {"name": "x", "address": "y", "port": "abc"})[0], 400)

    def test_node_agent_config(self):
        n = self.add_node(port="8443", obfs_password="ob")
        self.assertFalse(n["agent_synced"])
        url = "/hy2/node/%s/config" % n["auth_token"]
        s, r, _ = self.call("GET", url + "?port=443&obfs=", token=None)
        self.assertEqual(r, {"listen_port": 8443, "port": "8443", "obfs_password": "ob", "hop_ports": ""})
        _, n, _ = self.call("GET", "/api/v1/nodes/%d" % n["id"])
        self.assertEqual((n["agent_port"], n["agent_synced"]), ("443", False))
        self.assertNotIn("agent_obfs", n)
        self.call("GET", url + "?port=8443&obfs=ob", token=None)
        _, n, _ = self.call("GET", "/api/v1/nodes/%d" % n["id"])
        self.assertTrue(n["agent_synced"])
        self.call("PATCH", "/api/v1/nodes/%d" % n["id"], {"port": "20000-30000"})
        self.assertEqual(self.call("GET", url, token=None)[1]["listen_port"], 20000)
        self.assertEqual(self.call("GET", "/hy2/node/bad/config", token=None)[0], 404)

    def test_migrate_old_db(self):
        import os, sqlite3, tempfile
        path = os.path.join(tempfile.mkdtemp(), "old.db")
        c = sqlite3.connect(path)
        c.execute("CREATE TABLE nodes (id INTEGER PRIMARY KEY, name TEXT NOT NULL, address TEXT NOT NULL, "
                  "port TEXT NOT NULL DEFAULT '443', auth_token TEXT NOT NULL, created_at INTEGER NOT NULL)")
        c.execute("INSERT INTO nodes(name,address,auth_token,created_at) VALUES('a','b','t',0)")
        c.commit()
        c.close()
        c = sqlite3.connect(path)
        c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, "
                  "password TEXT NOT NULL, sub_token TEXT NOT NULL, created_at INTEGER NOT NULL, "
                  "updated_at INTEGER NOT NULL)")
        c.execute("INSERT INTO users(username,password,sub_token,created_at,updated_at) VALUES('u','p','s',0,0)")
        c.commit()
        c.close()
        db = DB(path)
        n = db.get_node(1)
        self.assertEqual((n["agent_seen_at"], n["agent_port"], n["agent_obfs"]), (0, "", ""))
        self.assertEqual(db.get_user("u")["traffic_multiplier"], 1.0)

    def test_auto_reset(self):
        self.call("POST", "/api/v1/users", {"username": "mo", "reset_day": 5})
        self.svc.db.update_user("mo", {"upload": 50, "download": 50,
                                       "last_reset_at": int(datetime.datetime(2026, 1, 1).timestamp())})
        self.assertEqual(self.svc.auto_reset(datetime.datetime(2026, 1, 4, 12)), [])
        self.assertEqual(self.svc.auto_reset(datetime.datetime(2026, 1, 5, 0, 1)), ["mo"])
        self.assertEqual(self.svc.db.get_user("mo")["upload"], 0)
        self.svc.db.update_user("mo", {"upload": 9, "last_reset_at": int(datetime.datetime(2026, 1, 5, 0, 1).timestamp())})
        self.assertEqual(self.svc.auto_reset(datetime.datetime(2026, 2, 1)), [])
        self.assertEqual(self.svc.auto_reset(datetime.datetime(2026, 2, 6)), ["mo"])


if __name__ == "__main__":
    unittest.main()
