# CV-CUE role manager

A small web app for managing firewall rules on Arista CV-CUE **role profiles** (Network profiles → Roles)
from shared, versioned **rule sets**.

CV-CUE stores firewall rules inside each role profile, so the same rules get copied by hand and drift
apart. This app keeps one ordered rule set, links role profiles to it, and pushes every published
change to all of them. It reads each one back afterwards to confirm the update.

## How it works

- **Rule set**: an ordered list of Layer 3-4 firewall rules plus a default rule, kept in this app.
  Edits go into a draft; **publishing** creates a new version and pushes it.
- **Link**: a role profile is linked to a rule set by the tag `ruleset:<name>` in its CV-CUE
  description. The tag lives in CV-CUE, so it's visible in the CV-CUE UI and the link survives if
  this app's database is lost.
- **Sync status** for each linked role profile:
  - *In sync*: its rules match the latest published version.
  - *Update pending*: its rules match an older version.
  - *Edited in CV-CUE*: someone changed the rules in CV-CUE; they match no published version.
    You can apply the published version again, or copy the edited rules into the draft.
- **Every write** reads the current role profile, replaces only its firewall rules (and, when linking,
  its description tag), sends the whole role profile back, then reads it again to verify.
  VLAN, traffic control, and web quarantine settings are kept.
- A publish is refused if the rule set or any linked role profile changed after you opened the review
  page, so what you reviewed is what gets applied.

Not managed yet: application firewall rules and per-user traffic control (they're shown as they are in CV-CUE).

## Run locally

```bash
python3.12 -m venv .venv312 && .venv312/bin/pip install ".[dev]"
cp .env.example .env          # demo mode with sample data and developer sign-in
.venv312/bin/cv-cue-role-manager
```

Open http://localhost:8080. To use a real CV-CUE, set `CVCUE_MOCK=false` and fill in
`CVCUE_BASE_URL`, `CVCUE_KEY_ID`, and `CVCUE_KEY_VALUE` in `.env`.

Tests: `.venv312/bin/ruff check src tests && .venv312/bin/python -m pytest -q`

## Deploy to Fly.io

One-time setup:

```bash
fly apps create cv-cue-role-manager
fly volumes create rolemgr_data --region sjc --size 1 --app cv-cue-role-manager
fly secrets set --app cv-cue-role-manager \
  CVCUE_BASE_URL=https://<server>.srv.wifi.arista.com/wifi/api \
  CVCUE_KEY_ID=KEY-... CVCUE_KEY_VALUE=... \
  SESSION_SECRET=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))') \
  GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=... \
  ALLOWED_EMAILS=you@example.com
fly deploy
```

Google sign-in needs an OAuth web client with the redirect URI
`https://cv-cue-role-manager.fly.dev/auth/google/callback`. Only addresses (or `@domains`) in
`ALLOWED_EMAILS` can sign in. Demo mode and developer sign-in are always off on Fly.

After that, every push to `main` that passes CI deploys automatically once the repository has a
`FLY_API_TOKEN` secret (`fly tokens create deploy --app cv-cue-role-manager`).

The SQLite database is on the `rolemgr_data` volume; keep the app at one machine.

## Relationship to cv-cue-mcp

This is a separate app with its own repository, deploy, and API key. It doesn't depend on the
[cv-cue-mcp](https://github.com/sharanmahadevan/cv-cue-mcp) server. The rule set JSON it exports is
compatible with the `sync.py` script, and it can import those files.
