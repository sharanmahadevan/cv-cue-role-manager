"""Run the app: `cv-cue-role-manager` (reads .env locally, environment/Fly secrets in production)."""

from __future__ import annotations

import logging
import os


def main() -> None:
    import uvicorn

    from .config import Settings, load_dotenv
    from .web.app import create_app

    load_dotenv()
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = Settings.from_env()
    if not cfg.allowed_emails and not cfg.dev_login:
        logging.warning("ALLOWED_EMAILS is empty: nobody can sign in.")
    port = int(os.environ.get("PORT", "8080"))
    host = os.environ.get("HOST", "0.0.0.0" if os.environ.get("FLY_APP_NAME") else "127.0.0.1")
    uvicorn.run(create_app(cfg), host=host, port=port, proxy_headers=True, forwarded_allow_ips="*")


if __name__ == "__main__":
    main()
