"""Runtime configuration, read from environment variables (prefix AIO_; the old HY2M_ prefix
of hysteria-manager is still accepted so an existing .env keeps working)."""
import os
from dataclasses import dataclass


def _env(name, default):
    for prefix in ("AIO_", "HY2M_"):
        v = os.environ.get(prefix + name)
        if v is not None:
            return v
    return default


@dataclass
class Config:
    listen_host: str = "0.0.0.0"
    listen_port: int = 8080
    db_path: str = "data/allinone.db"
    admin_user: str = "admin"
    admin_pass: str = ""  # empty => generated on first start and stored in DB
    api_token: str = ""  # static token for machine-to-machine API calls; empty => disabled
    public_url: str = ""  # e.g. https://panel.example.com, used to build subscription URLs
    sync_interval: int = 60  # seconds between hysteria2 traffic sync rounds
    session_ttl: int = 7 * 86400
    tls_cert: str = ""  # serve HTTPS directly when both cert and key are set
    tls_key: str = ""
    ss_port_min: int = 40000  # per-user shadowsocks ports are assigned from this range
    ss_port_max: int = 49999

    @classmethod
    def from_env(cls) -> "Config":
        c = cls()
        c.listen_host = _env("HOST", c.listen_host)
        c.listen_port = int(_env("PORT", c.listen_port))
        c.db_path = _env("DB", c.db_path)
        c.admin_user = _env("ADMIN_USER", c.admin_user)
        c.admin_pass = _env("ADMIN_PASS", c.admin_pass)
        c.api_token = _env("API_TOKEN", c.api_token)
        c.public_url = _env("PUBLIC_URL", c.public_url).rstrip("/")
        c.sync_interval = max(5, int(_env("SYNC_INTERVAL", c.sync_interval)))
        c.session_ttl = int(_env("SESSION_TTL", c.session_ttl))
        c.tls_cert = _env("TLS_CERT", c.tls_cert)
        c.tls_key = _env("TLS_KEY", c.tls_key)
        rng = _env("SS_PORT_RANGE", "%d-%d" % (c.ss_port_min, c.ss_port_max))
        lo, _, hi = rng.partition("-")
        c.ss_port_min, c.ss_port_max = int(lo), int(hi or lo)
        if not 1 <= c.ss_port_min <= c.ss_port_max <= 65535:
            raise ValueError("AIO_SS_PORT_RANGE must look like 40000-49999")
        return c
