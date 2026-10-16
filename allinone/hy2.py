"""Client for the Hysteria2 server Traffic Stats API.

See https://v2.hysteria.network/docs/advanced/Traffic-Stats-API/
  GET  /traffic[?clear=1] -> {"<id>": {"tx": n, "rx": n}}   tx = client upload, rx = client download
  GET  /online            -> {"<id>": <connection count>}
  POST /kick              <- ["<id>", ...]
"""
import json
import urllib.error
import urllib.request

TIMEOUT = 10


class NodeAPIError(Exception):
    pass


def _call(node, method, path, body=None):
    if not node.get("api_url"):
        raise NodeAPIError("node has no api_url configured")
    url = node["api_url"].rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if node.get("api_secret"):
        req.add_header("Authorization", node["api_secret"])
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        raise NodeAPIError("HTTP %d from %s" % (e.code, url))
    except Exception as e:  # network errors, timeouts
        raise NodeAPIError("%s: %s" % (url, e))
    if not raw.strip():
        return None
    try:
        return json.loads(raw)
    except ValueError:
        raise NodeAPIError("invalid JSON from %s" % url)


def fetch_traffic(node, clear=True):
    return _call(node, "GET", "/traffic?clear=1" if clear else "/traffic") or {}


def fetch_online(node):
    return _call(node, "GET", "/online") or {}


def kick(node, ids):
    if ids:
        _call(node, "POST", "/kick", list(ids))
