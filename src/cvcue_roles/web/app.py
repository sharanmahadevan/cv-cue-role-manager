"""Starlette app: sign-in, pages, and form handlers."""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
from contextlib import asynccontextmanager
from urllib.parse import quote, urlencode

import httpx
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from .. import roleform as F
from .. import rules as R
from ..client import CvcueClient, CvcueError
from ..config import Settings
from ..mock import MockCvcue, seed_store
from ..service import Portal, StalePlan
from ..store import Store
from . import pages as P

log = logging.getLogger(__name__)

GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO = "https://openidconnect.googleapis.com/v1/userinfo"
CSP = ("default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; "
       "form-action 'self' https://accounts.google.com; frame-ancestors 'none'")


def create_app(cfg: Settings, api=None) -> Starlette:
    store = Store(cfg.db_path)
    if api is None:
        if cfg.mock:
            api = MockCvcue()
        elif cfg.cvcue_configured:
            api = CvcueClient(cfg.base_url, cfg.key_id, cfg.key_value, cfg.cid, cfg.verify_ssl)
    if cfg.mock:
        seed_store(store)
    portal = Portal(api, store, cfg.root_location) if api is not None else None

    # ------------------------------------------------------------ helpers
    def html(body: str, status: int = 200) -> HTMLResponse:
        return HTMLResponse(body, status, headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY",
                                                   "Content-Security-Policy": CSP, "Referrer-Policy": "same-origin"})

    def user_of(request: Request) -> str | None:
        email = request.session.get("email")
        if email and (cfg.email_allowed(email) or request.session.get("dev")):
            return email
        return None

    def csrf(request: Request) -> str:
        if "csrf" not in request.session:
            request.session["csrf"] = secrets.token_urlsafe(24)
        return request.session["csrf"]

    def flash(request: Request, kind: str, text: str) -> None:
        request.session["flash"] = [kind, text]

    def page(request: Request, title: str, body: str, nav: str = "", status: int = 200) -> HTMLResponse:
        fl = request.session.pop("flash", None)
        mode = "Mock CV-CUE (demo data)" if cfg.mock else (api.base_url if api is not None else "")
        return html(P.layout(title, body, user_of(request), nav, fl, csrf(request), mode), status)

    def protected(handler):
        async def wrapper(request: Request) -> Response:
            if not user_of(request):
                return RedirectResponse(f"/login?next={quote(request.url.path)}", 303)
            if request.method == "POST":
                form = await request.form()
                if not secrets.compare_digest(str(form.get("csrf", "")), request.session.get("csrf", "")):
                    return page(request, "Expired", P.message("This form expired. Go back, reload, and try again."),
                                status=400)
            if portal is None:
                return page(request, "Setup needed", P.setup_needed(), status=503)
            try:
                return await handler(request)
            except CvcueError as exc:
                log.warning("CV-CUE error: %s", exc)
                return page(request, "CV-CUE error", P.cvcue_error(exc), status=502)
        return wrapper

    async def db(fn, *args):
        return await asyncio.to_thread(fn, *args)

    def loc_param(request: Request, form=None):
        raw = (form or {}).get("loc") if form is not None else request.query_params.get("loc")
        try:
            return int(raw)
        except (TypeError, ValueError):
            return raw

    # ------------------------------------------------------------ auth
    async def login(request: Request) -> Response:
        if user_of(request):
            return RedirectResponse("/roles", 303)
        return page(request, "Sign in", P.login(cfg.google_enabled, cfg.dev_login, _safe_next(
            request.query_params.get("next")), request.query_params.get("error")))

    async def google_start(request: Request) -> Response:
        if not cfg.google_enabled:
            return RedirectResponse("/login?error=Google+sign-in+isn't+set+up", 303)
        st = secrets.token_urlsafe(24)
        request.session["g_state"] = st
        request.session["next"] = _safe_next(request.query_params.get("next"))
        q = urlencode({"client_id": cfg.google_client_id, "redirect_uri": f"{cfg.public_url}/auth/google/callback",
                       "response_type": "code", "scope": "openid email profile", "state": st,
                       "prompt": "select_account"})
        return RedirectResponse(f"{GOOGLE_AUTH}?{q}", 303)

    async def google_callback(request: Request) -> Response:
        p = request.query_params
        st = request.session.pop("g_state", None)
        if not st or not secrets.compare_digest(p.get("state", ""), st):
            return RedirectResponse("/login?error=Sign-in+expired.+Try+again.", 303)
        if p.get("error") or not p.get("code"):
            return RedirectResponse("/login?error=Google+sign-in+was+cancelled", 303)
        try:
            async with httpx.AsyncClient(timeout=15) as h:
                tok = (await h.post(GOOGLE_TOKEN, data={
                    "code": p["code"], "client_id": cfg.google_client_id, "client_secret": cfg.google_client_secret,
                    "redirect_uri": f"{cfg.public_url}/auth/google/callback", "grant_type": "authorization_code",
                })).raise_for_status().json()
                info = (await h.get(GOOGLE_USERINFO, headers={"Authorization": f"Bearer {tok['access_token']}"})
                        ).raise_for_status().json()
        except Exception as exc:  # noqa: BLE001
            log.warning("Google sign-in failed: %s", exc)
            return RedirectResponse("/login?error=Google+sign-in+failed", 303)
        email = (info.get("email") or "").lower()
        if not info.get("email_verified") or not cfg.email_allowed(email):
            log.info("Sign-in refused for %s", email)
            return RedirectResponse("/login?error=That+account+isn't+allowed+to+use+this+app", 303)
        nxt = _safe_next(request.session.get("next"))
        request.session.clear()
        request.session["email"] = email
        return RedirectResponse(nxt, 303)

    async def dev_login(request: Request) -> Response:
        if not cfg.dev_login:
            return Response(status_code=404)
        form = await request.form()
        request.session.clear()
        request.session["email"] = str(form.get("email") or "dev@localhost")[:120]
        request.session["dev"] = True
        return RedirectResponse(_safe_next(str(form.get("next") or "")), 303)

    async def logout(request: Request) -> Response:
        request.session.clear()
        return RedirectResponse("/login", 303)

    # ------------------------------------------------------------ role profiles
    async def roles_page(request: Request) -> Response:
        rows = await portal.role_rows()
        sets = await db(store.list_rulesets)
        return page(request, "Roles", P.roles(rows, sets), "roles")

    async def read_form(request: Request) -> dict:
        """Form fields as a dict; `rulesets` (repeated, ordered) as a list."""
        form = await request.form()
        data = {k: v for k, v in form.items() if k != "rulesets"}
        data["rulesets"] = [str(v) for v in form.getlist("rulesets")]
        return data

    async def role_page(request: Request) -> Response:
        tid = int(request.path_params["tid"])
        loc = loc_param(request)
        role, current = await portal.role_content(tid, loc)
        locs = await portal.locations()
        sets = await db(store.list_rulesets)
        versions = {s["name"]: await db(store.versions, s["name"]) for s in sets}
        applied = await db(store.applied_fingerprints)
        row = portal.classify(role, locs.get(loc, f"Location {loc}"), versions, applied.get(tid))
        target = None
        if row.rulesets and not row.missing:
            target, _ = await portal.latest_contents(row.rulesets)
        changes = R.diff(R.from_role(role), target) if target and row.status != "in_sync" else []
        return page(request, role["templateName"], P.role_detail(row, current, sets, target, changes), "roles")

    async def link_review(request: Request) -> Response:
        tid = int(request.path_params["tid"])
        loc = loc_param(request)
        names = []
        for n in request.query_params.getlist("rulesets") + request.query_params.getlist("ruleset"):
            if n and n not in names:
                names.append(n)
        content, missing = await portal.latest_contents(names)
        if not names or missing:
            flash(request, "error", f"Publish {', '.join(missing) or 'a rule set'} before linking role profiles to it.")
            return RedirectResponse(f"/roles/{tid}?loc={loc}", 303)
        role = await portal.get_role(tid, loc)
        changes = R.diff(R.from_role(role), content)
        return page(request, "Link role profile", P.link_review(role, loc, names, content, changes), "roles")

    async def role_action(request: Request) -> Response:
        tid = int(request.path_params["tid"])
        action = request.path_params["action"]
        form = await read_form(request)
        loc = loc_param(request, form)
        user = user_of(request)
        try:
            if action == "link":
                run_id = await portal.link(tid, loc, form["rulesets"] or [str(form.get("ruleset", ""))], user)
            elif action == "revert":
                run_id = await portal.revert(tid, loc, user)
            elif action == "unlink":
                run_id = await portal.unlink(tid, loc, user)
            elif action == "adopt":
                role, current = await portal.role_content(tid, loc)
                tags = R.tags_of(role)
                if len(tags) != 1:
                    raise ValueError("Copying rules into a draft works only for a role profile with one rule set.")
                rs = await db(store.get_ruleset, tags[0])
                if rs is None:
                    raise ValueError("This role profile isn't linked to a rule set in this app.")
                await db(store.save_draft, rs["name"], current, user)
                flash(request, "ok", f"Copied {role['templateName']}'s rules into the {rs['name']} draft. "
                                     "Review and publish to apply them everywhere.")
                return RedirectResponse(f"/rulesets/{rs['name']}", 303)
            else:
                return Response(status_code=404)
        except ValueError as exc:
            flash(request, "error", str(exc))
            return RedirectResponse(f"/roles/{tid}?loc={loc}", 303)
        return RedirectResponse(f"/runs/{run_id}", 303)

    # ------------------------------------------------------------ create / edit / delete role profiles
    async def role_pick(request: Request) -> Response:
        """Toolbar buttons on the roles list: route the selected radio button to edit or delete."""
        sel = request.query_params.get("sel", "")
        tid, _, loc = sel.partition(":")
        if not tid.isdigit():
            flash(request, "error", "Select a role profile first.")
            return RedirectResponse("/roles", 303)
        verb = "edit" if request.url.path.endswith("/edit") else "delete"
        return RedirectResponse(f"/roles/{tid}/{verb}?loc={quote(loc)}", 303)

    async def _form_context(exclude_tid: int | None = None):
        roles, sets, locs = await asyncio.gather(portal.raw_roles(), db(store.list_rulesets),
                                                 portal.folder_locations())
        names = {(r.get("templateName") or "").lower() for r in roles if r.get("templateId") != exclude_tid}
        published = {s["name"] for s in sets if s["latest"]}
        return names, published, sets, locs

    def _start_new_ruleset(request: Request, back: str, f: dict) -> Response:
        """Park the role form and go create a rule set; the form comes back with it in the list."""
        values = {k: v for k, v in f.items() if k not in ("csrf", "name")}
        request.session["role_draft"] = {"back": back, "values": values, "ruleset": None,
                                         "label": f.get("profile_name") or "new role profile"}
        return RedirectResponse("/rulesets/new", 303)

    def _resume(request: Request, f: dict, published: set[str]) -> tuple[dict, list[str]]:
        draft = request.session.pop("role_draft", None)
        if not draft:
            return f, []
        f = {**f, **draft["values"]}
        notes = []
        name = draft.get("ruleset")
        sets_ = [n for n in f.get("rulesets") or []]
        if name and name in published:
            sets_ = [name if n == F.NEW_RULESET else n for n in sets_] if F.NEW_RULESET in sets_ else sets_ + [name]
            f["fw_on"] = "1"
        else:
            sets_ = [n for n in sets_ if n != F.NEW_RULESET]
            if name:
                notes.append(f"Rule set {name} isn't published yet. Publish it to add it here.")
        f["rulesets"] = list(dict.fromkeys(sets_))
        return f, notes

    async def role_new(request: Request) -> Response:
        names, published, sets, locs = await _form_context()
        if request.method == "GET":
            roles = await portal.raw_roles()
            used = [(r.get("createdAtLocationId") or {}).get("id") for r in roles]
            common = max(set(used), key=used.count) if used else None
            loc = common if common in locs else next(iter(locs), "")
            f, notes = (_resume(request, F.new_fields(str(loc)), published) if request.query_params.get("resume")
                        else (F.new_fields(str(loc)), []))
            return page(request, "Add role profile", P.role_form("create", f, notes, locs, sets), "roles")
        form = await read_form(request)
        f, errors = F.parse(form, existing_names=names, published=published, creating=True, locations=locs)
        if errors:
            return page(request, "Add role profile", P.role_form("create", f, errors, locs, sets), "roles", 400)
        if F.NEW_RULESET in f["rulesets"]:
            return _start_new_ruleset(request, "/roles/new?resume=1", f)
        try:
            run_id = await portal.create_role(f, user_of(request))
        except ValueError as exc:
            return page(request, "Add role profile", P.role_form("create", f, [str(exc)], locs, sets), "roles", 400)
        return RedirectResponse(f"/runs/{run_id}", 303)

    async def role_edit(request: Request) -> Response:
        tid = int(request.path_params["tid"])
        form = await read_form(request) if request.method == "POST" else {}
        loc = loc_param(request, form if request.method == "POST" else None)
        role = await portal.get_role(tid, loc)
        current = R.tags_of(role)
        names, published, sets, locs = await _form_context(exclude_tid=tid)
        all_locs = await portal.locations()
        title = f"Edit {role.get('templateName')}"

        def render(f, errors, status=200):
            f["orig_name"] = role.get("templateName")
            return page(request, title, P.role_form("edit", f, errors, all_locs, sets, current, tid, loc, role),
                        "roles", status)

        if request.method == "GET":
            f = F.fields_from_role(role)
            notes = []
            if request.query_params.get("resume"):
                f, notes = _resume(request, f, published)
            return render(f, notes)
        f, errors = F.parse(form, existing_names=names, published=published, current_rulesets=current,
                            creating=False, keep_allowed=bool(role.get("firewallEnabled")))
        if errors:
            return render(f, errors, 400)
        if F.NEW_RULESET in f["rulesets"]:
            return _start_new_ruleset(request, f"/roles/{tid}/edit?loc={loc}&resume=1", f)
        try:
            run_id = await portal.update_role(tid, loc, f, user_of(request))
        except ValueError as exc:
            return render(f, [str(exc)], 400)
        return RedirectResponse(f"/runs/{run_id}", 303)

    async def role_delete(request: Request) -> Response:
        tid = int(request.path_params["tid"])
        form = dict(await request.form()) if request.method == "POST" else None
        loc = loc_param(request, form)
        if request.method == "POST":
            try:
                run_id = await portal.delete_role(tid, loc, user_of(request))
            except ValueError as exc:
                flash(request, "error", str(exc))
                return RedirectResponse(f"/roles/{tid}?loc={loc}", 303)
            return RedirectResponse(f"/runs/{run_id}", 303)
        role = await portal.get_role(tid, loc)
        locs = await portal.locations()
        row = portal.classify(role, locs.get(loc, f"Location {loc}"), {})
        refs = await portal.references(tid, loc)
        return page(request, f"Delete {role.get('templateName')}", P.role_delete(row, refs), "roles")

    # ------------------------------------------------------------ rule sets
    async def rulesets_page(request: Request) -> Response:
        sets = await db(store.list_rulesets)
        rows = await portal.role_rows()
        usage = {s["name"]: [r for r in rows if s["name"] in r.rulesets] for s in sets}
        unmanaged = [r for r in rows if r.status == "unmanaged" and r.role.get("firewallEnabled")]
        return page(request, "Rule sets", P.rulesets(sets, usage, unmanaged), "rulesets")

    async def ruleset_create(request: Request) -> Response:
        form = await request.form()
        name = str(form.get("name", "")).strip()
        desc = str(form.get("description", "")).strip()[:200]
        back = "/rulesets/new" if form.get("for_role") else "/rulesets"
        if not R.NAME_RE.match(name):
            flash(request, "error", "Use 1-48 letters, numbers, dots, dashes, or underscores for the name.")
            return RedirectResponse(back, 303)
        if await db(store.get_ruleset, name):
            flash(request, "error", f"A rule set named {name} already exists.")
            return RedirectResponse(back, 303)
        content = R.empty_content()
        source = str(form.get("source", ""))
        if source.startswith("role:"):
            _, tid, loc = source.split(":", 2)
            _, content = await portal.role_content(int(tid), int(loc) if loc.lstrip("-").isdigit() else loc)
        await db(store.create_ruleset, name, desc, content, user_of(request))
        draft = request.session.get("role_draft")
        if draft and form.get("for_role"):
            draft["ruleset"] = name
            request.session["role_draft"] = draft
        flash(request, "ok", f"Created {name}. Add rules, then review and publish.")
        return RedirectResponse(f"/rulesets/{name}", 303)

    async def ruleset_new(request: Request) -> Response:
        rows = await portal.role_rows()
        sources = [r for r in rows if r.role.get("firewallEnabled")]
        return page(request, "New rule set", P.ruleset_new(request.session.get("role_draft"), sources), "rulesets")

    def role_draft_for(request: Request, name: str) -> dict | None:
        draft = request.session.get("role_draft")
        return draft if draft and draft.get("ruleset") == name else None

    async def ruleset_page(request: Request) -> Response:
        name = request.path_params["name"]
        rs = await db(store.get_ruleset, name)
        rows = [r for r in await portal.role_rows() if name in r.rulesets]
        if rs is None:
            if R.NAME_RE.match(name):
                return page(request, name, P.ruleset_missing(name, rows), "rulesets")
            return page(request, "Not found", P.message("That rule set doesn't exist."), "rulesets", 404)
        edit = request.query_params.get("edit")
        edit_i = int(edit) if edit and edit.isdigit() and int(edit) < len(rs["draft"]["rules"]) else None
        return page(request, name, P.ruleset_editor(rs, rows, edit_i, request.session.pop("form_errors", None),
                                                          role_draft_for(request, name)),
                    "rulesets")

    async def ruleset_edit(request: Request) -> Response:
        name = request.path_params["name"]
        rs = await db(store.get_ruleset, name)
        if rs is None:
            return Response(status_code=404)
        form = dict(await request.form())
        op = form.get("op", "")
        draft = rs["draft"]
        rules = draft["rules"]
        i = int(form["i"]) if str(form.get("i", "")).isdigit() else None
        if i is not None and i >= len(rules):
            i = None
        user = user_of(request)
        back = f"/rulesets/{name}"
        if op in ("add", "update"):
            rule, errors = R.rule_from_form(form)
            if errors:
                request.session["form_errors"] = {"errors": errors, "values": {k: str(v) for k, v in form.items()
                                                                                if k != "csrf"}}
                again = f"?edit={i}" if op == "update" and i is not None else ""
                return RedirectResponse(f"{back}{again}#rule-form", 303)
            if op == "update" and i is not None:
                old = rules[i]
                rule["mark"], rule["dscp"] = old["mark"], old["dscp"]
                rules[i] = rule
            else:
                rules.append(rule)
        elif op == "delete" and i is not None:
            rules.pop(i)
        elif op == "up" and i:
            rules[i - 1], rules[i] = rules[i], rules[i - 1]
        elif op == "down" and i is not None and i < len(rules) - 1:
            rules[i + 1], rules[i] = rules[i], rules[i + 1]
        elif op == "default":
            draft["default_action"] = 1 if form.get("default_action") == "1" else 2
        elif op == "describe":
            await db(store.save_draft, name, draft, user, str(form.get("description", "")).strip()[:200])
            return RedirectResponse(back, 303)
        elif op == "discard":
            if rs["published"] is None:
                draft = R.empty_content()
            else:
                draft = rs["published"]
            flash(request, "ok", "Draft changes discarded.")
        elif op == "import":
            try:
                draft = R.content_from_import(json.loads(str(form.get("json", ""))))
            except (ValueError, TypeError) as exc:
                flash(request, "error", f"Couldn't read that JSON: {exc}")
                return RedirectResponse(back, 303)
            flash(request, "ok", "Imported into the draft. Review and publish to apply.")
        await db(store.save_draft, name, draft, user)
        return RedirectResponse(back, 303)

    async def ruleset_review(request: Request) -> Response:
        name = request.path_params["name"]
        try:
            plan = await portal.plan(name)
        except KeyError:
            return page(request, "Not found", P.message("That rule set doesn't exist."), "rulesets", 404)
        return page(request, f"Review {name}", P.review(plan, role_draft_for(request, name)), "rulesets")

    async def ruleset_publish(request: Request) -> Response:
        name = request.path_params["name"]
        form = await request.form()
        try:
            run_id = await portal.publish(name, str(form.get("token", "")), user_of(request))
        except StalePlan as exc:
            flash(request, "error", f"{exc} Check the changes again before publishing.")
            return RedirectResponse(f"/rulesets/{name}/review", 303)
        return RedirectResponse(f"/runs/{run_id}", 303)

    async def ruleset_history(request: Request) -> Response:
        name = request.path_params["name"]
        rs = await db(store.get_ruleset, name)
        if rs is None:
            return page(request, "Not found", P.message("That rule set doesn't exist."), "rulesets", 404)
        versions = await db(store.versions, name)
        runs = await db(store.recent_runs, 50, name)
        return page(request, f"{name} history", P.history(rs, versions, runs), "rulesets")

    async def ruleset_restore(request: Request) -> Response:
        name = request.path_params["name"]
        form = await request.form()
        v = await db(store.get_version, name, int(form.get("version", 0)))
        if v is None:
            return Response(status_code=404)
        await db(store.save_draft, name, v["content"], user_of(request))
        flash(request, "ok", f"Loaded v{v['version']} into the draft. Review and publish to roll back.")
        return RedirectResponse(f"/rulesets/{name}", 303)

    async def ruleset_delete(request: Request) -> Response:
        name = request.path_params["name"]
        linked = [r for r in await portal.role_rows() if name in r.rulesets]
        if linked:
            flash(request, "error", f"Unlink the {len(linked)} role profile(s) using {name} before deleting it.")
            return RedirectResponse(f"/rulesets/{name}", 303)
        await db(store.delete_ruleset, name)
        flash(request, "ok", f"Deleted {name}.")
        return RedirectResponse("/rulesets", 303)

    async def ruleset_export(request: Request) -> Response:
        name = request.path_params["name"]
        rs = await db(store.get_ruleset, name)
        if rs is None:
            return Response(status_code=404)
        which = request.query_params.get("which", "published")
        content = rs["published"] if which == "published" and rs["published"] else rs["draft"]
        return JSONResponse({"name": name, "description": rs["description"], **content,
                             "firewallProfile": R.to_firewall_profile(content)},
                            headers={"Content-Disposition": f'attachment; filename="{name}.json"'})

    # ------------------------------------------------------------ activity
    async def activity_page(request: Request) -> Response:
        return page(request, "Activity", P.activity(await db(store.recent_runs, 100)), "activity")

    async def run_page(request: Request) -> Response:
        run = await db(store.get_run, int(request.path_params["rid"]))
        if run is None:
            return page(request, "Not found", P.message("That run doesn't exist."), "activity", 404)
        return page(request, f"Run {run['id']}", P.run(run, role_draft_for(request, run["ruleset"])), "activity")

    async def healthz(_: Request) -> Response:
        return JSONResponse({"ok": True})

    async def home(_: Request) -> Response:
        return RedirectResponse("/roles", 303)

    @asynccontextmanager
    async def lifespan(_app):
        yield
        if api is not None:
            await api.aclose()

    routes = [
        Route("/", home), Route("/healthz", healthz),
        Route("/login", login), Route("/auth/google", google_start), Route("/auth/google/callback", google_callback),
        Route("/auth/dev", dev_login, methods=["POST"]), Route("/logout", logout, methods=["POST"]),
        Route("/roles", protected(roles_page)),
        Route("/roles/new", protected(role_new), methods=["GET", "POST"]),
        Route("/roles/edit", protected(role_pick)),
        Route("/roles/delete", protected(role_pick)),
        Route("/roles/{tid:int}", protected(role_page)),
        Route("/roles/{tid:int}/edit", protected(role_edit), methods=["GET", "POST"]),
        Route("/roles/{tid:int}/delete", protected(role_delete), methods=["GET", "POST"]),
        Route("/roles/{tid:int}/link", protected(link_review)),
        Route("/roles/{tid:int}/{action}", protected(role_action), methods=["POST"]),
        Route("/rulesets", protected(rulesets_page)),
        Route("/rulesets", protected(ruleset_create), methods=["POST"]),
        Route("/rulesets/new", protected(ruleset_new)),
        Route("/rulesets/{name}", protected(ruleset_page)),
        Route("/rulesets/{name}/edit", protected(ruleset_edit), methods=["POST"]),
        Route("/rulesets/{name}/review", protected(ruleset_review)),
        Route("/rulesets/{name}/publish", protected(ruleset_publish), methods=["POST"]),
        Route("/rulesets/{name}/history", protected(ruleset_history)),
        Route("/rulesets/{name}/restore", protected(ruleset_restore), methods=["POST"]),
        Route("/rulesets/{name}/delete", protected(ruleset_delete), methods=["POST"]),
        Route("/rulesets/{name}/export", protected(ruleset_export)),
        Route("/activity", protected(activity_page)),
        Route("/runs/{rid:int}", protected(run_page)),
    ]
    https = cfg.public_url.startswith("https://")
    middleware = [Middleware(SessionMiddleware, secret_key=cfg.session_secret, session_cookie="rm_session",
                             same_site="lax", https_only=https, max_age=12 * 3600)]
    app = Starlette(routes=routes, middleware=middleware, lifespan=lifespan)
    app.state.portal, app.state.store, app.state.api = portal, store, api
    return app


def _safe_next(value: str | None) -> str:
    if value and value.startswith("/") and not value.startswith("//"):
        return value
    return "/roles"
