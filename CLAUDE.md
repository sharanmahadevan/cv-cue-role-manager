# CV-CUE role manager — working notes for Claude

Starlette app (no build step, server-rendered HTML in `src/cvcue_roles/web/pages.py`) that manages
firewall rules on CV-CUE role profiles from versioned rule sets. Separate from `../cv-cue-mcp`.

- Check before committing: `.venv312/bin/ruff check src tests` and `.venv312/bin/python -m pytest -q`.
- Local demo: `.env` with `CVCUE_MOCK=true` and `DEV_LOGIN=true`, then `.venv312/bin/cv-cue-role-manager`.
- Editable installs don't work under Desktop (hidden `.pth` files); reinstall with `.venv312/bin/pip install .`.
- Use CV-CUE terms in the UI: role profile, firewall rules, location. "Rule set" is this app's own object.
- Never commit `.env` or `*.db`.

CV-CUE API facts the code relies on (verified against a live server):
- `GET /deviceconfiguration/roleprofiles?locationid=0&fetchSubTreeTemplates=true` lists role profiles.
- `PUT /deviceconfiguration/roleprofiles` with the full role body replaces `firewallProfile`;
  rules without `oid` are accepted, other fields are kept when echoed back.
- `orderId` is renumbered 1-based on create but kept as sent on update: compare by relative order
  (`rules.from_role` sorts and drops ids).
- Codes: direction 0 any/1 in/2 out; protocol 0 any/1 TCP/2 UDP/N+3 other; action 1 allow/2 block.
- Bandwidth limits (`trafficControl{Upload,Download}Limit`) are stored in Kbps (1 Mbps = 1024 Kbps);
  `*LimitUnit` (0 Kbps, 1 Mbps) only picks the CV-CUE display unit. Convert in `roleform.to_kbps/from_kbps`.
