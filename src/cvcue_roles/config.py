"""Settings, read from environment variables (Fly secrets in production, .env locally)."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def load_dotenv(path: str = ".env") -> None:
    """Minimal .env loader for local runs. Existing environment variables win."""
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


@dataclass
class Settings:
    # CV-CUE connection (one CV-CUE account per deployment)
    base_url: str = ""
    key_id: str = ""
    key_value: str = ""
    cid: str = ""
    verify_ssl: bool = True
    root_location: int = 0
    mock: bool = False

    # App
    public_url: str = "http://localhost:8080"
    db_path: str = "role-manager.db"
    session_secret: str = field(default_factory=lambda: secrets.token_urlsafe(32))

    # Sign-in
    google_client_id: str = ""
    google_client_secret: str = ""
    allowed_emails: tuple[str, ...] = ()
    dev_login: bool = False

    @property
    def google_enabled(self) -> bool:
        return bool(self.google_client_id and self.google_client_secret)

    @property
    def cvcue_configured(self) -> bool:
        return self.mock or bool(self.base_url and self.key_id and self.key_value)

    def email_allowed(self, email: str) -> bool:
        """Allow exact addresses ("a@b.com") or whole domains ("@b.com")."""
        email = (email or "").strip().lower()
        if not email:
            return False
        for entry in self.allowed_emails:
            if entry.startswith("@") and email.endswith(entry):
                return True
            if email == entry:
                return True
        return False

    @classmethod
    def from_env(cls) -> Settings:
        e = os.environ.get
        on_fly = bool(e("FLY_APP_NAME"))
        dev_login = _bool(e("DEV_LOGIN")) and not on_fly  # never on Fly
        allowed = tuple(x.strip().lower() for x in (e("ALLOWED_EMAILS") or "").split(",") if x.strip())
        return cls(
            base_url=(e("CVCUE_BASE_URL") or "").rstrip("/"),
            key_id=e("CVCUE_KEY_ID") or "",
            key_value=e("CVCUE_KEY_VALUE") or "",
            cid=e("CVCUE_CID") or "",
            verify_ssl=_bool(e("CVCUE_VERIFY_SSL"), True),
            root_location=int(e("CVCUE_ROOT_LOCATION") or 0),
            mock=_bool(e("CVCUE_MOCK")) and not on_fly,
            public_url=(e("PUBLIC_URL") or (f"https://{e('FLY_APP_NAME')}.fly.dev" if on_fly
                                             else f"http://localhost:{e('PORT') or 8080}")).rstrip("/"),
            db_path=e("DB_PATH") or "role-manager.db",
            session_secret=e("SESSION_SECRET") or secrets.token_urlsafe(32),
            google_client_id=e("GOOGLE_CLIENT_ID") or "",
            google_client_secret=e("GOOGLE_CLIENT_SECRET") or "",
            allowed_emails=allowed,
            dev_login=dev_login,
        )
