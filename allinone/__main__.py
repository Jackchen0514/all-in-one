import logging
import threading

from .config import Config
from .db import DB
from .server import make_server
from .service import Service


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = Config.from_env()
    svc = Service(cfg, DB(cfg.db_path))
    threading.Thread(target=svc.run_loop, name="sync", daemon=True).start()
    srv = make_server(svc, cfg.listen_host, cfg.listen_port, cfg.tls_cert, cfg.tls_key)
    logging.info("allinone listening on %s://%s:%d (admin user: %s)", "https" if srv.tls else "http",
                 cfg.listen_host, cfg.listen_port, cfg.admin_user)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        svc.stop()
        srv.server_close()


if __name__ == "__main__":
    main()
