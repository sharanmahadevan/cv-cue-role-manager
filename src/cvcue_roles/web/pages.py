"""HTML pages (server-rendered, no build step). Terms follow CV-CUE: role profiles, firewall rules, locations."""

from __future__ import annotations

import datetime as dt
from html import escape

from .. import rules as R

CSRF = '<input type="hidden" name="csrf" value="__CSRF__">'

STATUS = {
    "in_sync": ("ok", "In sync · v{v}"),
    "behind": ("pend", "Update pending · on v{v}"),
    "drifted": ("warn", "Edited in CV-CUE"),
    "not_published": ("muted", "Rule set not published"),
    "unknown_ruleset": ("warn", "Unknown rule set"),
    "multiple_tags": ("warn", "More than one rule set tag"),
    "unmanaged": ("none", "Not managed"),
}

CSS = """
:root{--bg:#f7f7f5;--surface:#fff;--text:#1f1f1d;--muted:#6b6a65;--faint:#9a9890;--border:rgba(0,0,0,.12);
--accent:#1f6fd1;--accent-bg:#e6f0fb;--ok:#2f6d12;--ok-bg:#e9f3dd;--warn:#7a4a06;--warn-bg:#faeed9;
--bad:#a32d2d;--bad-bg:#fcebeb;--neutral:#f0efea;--primary:#1f1f1d;--on-primary:#fff;--new:rgba(31,111,209,.07)}
@media (prefers-color-scheme:dark){:root{--bg:#191917;--surface:#22221f;--text:#ecebe6;--muted:#a6a49c;--faint:#77756e;
--border:rgba(255,255,255,.12);--accent:#7fb2ef;--accent-bg:#14304f;--ok:#a7d77a;--ok-bg:#24360f;--warn:#f2c06b;
--warn-bg:#40290a;--bad:#f09595;--bad-bg:#4a1717;--neutral:#2c2c29;--primary:#ecebe6;--on-primary:#1a1a18;--new:rgba(127,178,239,.08)}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
header{display:flex;align-items:center;gap:20px;padding:12px 24px;border-bottom:1px solid var(--border);background:var(--surface);flex-wrap:wrap}
header .brand{font-weight:600}header nav{display:flex;gap:4px}header nav a{padding:6px 10px;border-radius:8px;color:var(--muted)}
header nav a.on{background:var(--neutral);color:var(--text)}header .sp{flex:1}header .who{color:var(--muted);font-size:13px}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:22px;font-weight:600;margin:0 0 4px}h2{font-size:16px;font-weight:600;margin:0 0 10px}
.sub{color:var(--muted);margin:0 0 18px}.crumb{color:var(--muted);font-size:13px;margin-bottom:6px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px 20px;margin-bottom:16px}
.tw{overflow-x:auto}table{width:100%;border-collapse:collapse}th,td{padding:8px 8px;border-bottom:1px solid var(--border);text-align:left;vertical-align:middle}
th{color:var(--muted);font-weight:500;font-size:12px}tr.new td{background:var(--new)}td.n{color:var(--faint);width:32px}
.pill{display:inline-block;font-size:12px;padding:2px 9px;border-radius:999px;white-space:nowrap}
.ok{background:var(--ok-bg);color:var(--ok)}.warn{background:var(--warn-bg);color:var(--warn)}.pend{background:var(--accent-bg);color:var(--accent)}
.muted{background:var(--neutral);color:var(--muted)}.none{color:var(--faint)}.bad{background:var(--bad-bg);color:var(--bad)}
button,.btn{font:inherit;font-size:13px;padding:6px 12px;border-radius:8px;border:1px solid var(--border);background:var(--surface);color:var(--text);cursor:pointer;display:inline-block}
button:hover,.btn:hover{background:var(--neutral);text-decoration:none}.primary{background:var(--primary);color:var(--on-primary);border-color:var(--primary)}
.primary:hover{background:var(--primary);opacity:.9}.danger{color:var(--bad)}.small{padding:3px 8px;font-size:12px}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.inline{display:inline}
input,select,textarea{font:inherit;padding:6px 8px;border-radius:8px;border:1px solid var(--border);background:var(--surface);color:var(--text)}
label{display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.stat{background:var(--neutral);border-radius:8px;padding:10px 12px}.stat .l{font-size:12px;color:var(--muted)}
.diff{font:12px/1.8 ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--neutral);border-radius:8px;padding:10px 12px;margin:6px 0 0;white-space:pre-wrap}
.plus{color:var(--ok)}.minus{color:var(--bad)}.tilde{color:var(--warn)}
.flash{padding:10px 14px;border-radius:8px;margin-bottom:16px}.errors{color:var(--bad);margin:0 0 8px;padding-left:18px}
details summary{cursor:pointer;color:var(--accent)}.mono{font-family:ui-monospace,Menlo,monospace;font-size:12px}
tr.pick{cursor:pointer}tr.pick:hover td{background:var(--neutral)}tr.sel td{background:var(--accent-bg)}
input[type=radio]{accent-color:var(--accent);width:16px;height:16px;padding:0}fieldset label{margin:0}
.danger-fill{background:var(--bad);border-color:var(--bad);color:#fff}.danger-fill:hover{background:var(--bad)}
.tag{font-size:11px;background:var(--neutral);color:var(--muted);padding:1px 7px;border-radius:6px}
"""


def esc(v) -> str:
    return escape("" if v is None else str(v), quote=True)


def ts(t) -> str:
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if t else ""


def layout(title: str, body: str, user: str | None, nav: str, flash, csrf: str, mode: str) -> str:
    links = "".join(f'<a href="{h}" class="{"on" if nav == k else ""}">{t}</a>'
                    for k, h, t in (("roles", "/roles", "Role profiles"), ("rulesets", "/rulesets", "Rule sets"),
                                    ("activity", "/activity", "Activity")))
    who = (f'<span class="who">{esc(mode)}</span><span class="who">{esc(user)}</span>'
           f'<form method="post" action="/logout" class="inline">{CSRF}<button class="small">Sign out</button></form>'
           if user else "")
    fl = ""
    if flash:
        kind, text = flash
        fl = f'<div class="flash {"ok" if kind == "ok" else "bad"}">{esc(text)}</div>'
    page = (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" '
            f'content="width=device-width,initial-scale=1"><title>{esc(title)} · CV-CUE role manager</title>'
            f'<style>{CSS}</style></head><body><header><span class="brand">CV-CUE role manager</span>'
            f'{"<nav>" + links + "</nav>" if user else ""}<span class="sp"></span>{who}</header>'
            f'<main>{fl}{body}</main></body></html>')
    return page.replace("__CSRF__", esc(csrf))


def message(text: str) -> str:
    return f'<div class="card"><p>{esc(text)}</p></div>'


def setup_needed() -> str:
    return ('<div class="card"><h2>CV-CUE isn\'t connected</h2><p>Set <span class="mono">CVCUE_BASE_URL</span>, '
            '<span class="mono">CVCUE_KEY_ID</span>, and <span class="mono">CVCUE_KEY_VALUE</span>, then restart. '
            'On Fly, use <span class="mono">fly secrets set</span>.</p></div>')


def cvcue_error(exc) -> str:
    return (f'<div class="card"><h2>CV-CUE didn\'t accept that request</h2><p>{esc(exc)}</p>'
            '<p class="sub">Nothing else was changed. Reload to see the current state.</p></div>')


def login(google: bool, dev: bool, nxt: str, error: str | None) -> str:
    err = f'<div class="flash bad">{esc(error)}</div>' if error else ""
    parts = [f'<div class="card" style="max-width:420px;margin:40px auto">{err}<h1>Sign in</h1>'
             '<p class="sub">Manage firewall rules on CV-CUE role profiles from shared rule sets.</p>']
    if google:
        parts.append(f'<a class="btn primary" href="/auth/google?next={esc(nxt)}">Sign in with Google</a>')
    if dev:
        parts.append(f'<form method="post" action="/auth/dev" style="margin-top:16px" class="row">'
                     f'<input type="hidden" name="next" value="{esc(nxt)}">'
                     '<input name="email" value="dev@localhost" aria-label="Email"><button>Developer sign-in</button></form>'
                     '<p class="sub" style="margin-top:8px">Developer sign-in is for local use and is off on Fly.</p>')
    if not google and not dev:
        parts.append('<p>Sign-in isn\'t configured. Set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and ALLOWED_EMAILS.</p>')
    return "".join(parts) + "</div>"


def status_pill(row) -> str:
    cls, label = STATUS[row.status]
    return f'<span class="pill {cls}">{esc(label.format(v=row.version))}</span>'


def role_link(row) -> str:
    return f'<a href="/roles/{row.template_id}?loc={esc(row.location_id)}">{esc(row.role.get("templateName"))}</a>'


# ------------------------------------------------------------ role profiles
def vlan_label(role: dict) -> str:
    if not role.get("vlanEnabled"):
        return "From SSID"
    return esc(role.get("vlanId")) if role.get("vlanId") else "Untagged"


def ruleset_link(name: str | None) -> str:
    return f'<a href="/rulesets/{esc(name)}">{esc(name)}</a>' if name else '<span class="none">None</span>'


def roles(rows, sets) -> str:
    pending = [s for s in sets if s["has_changes"]]
    banner = "".join(f'<div class="flash pend"><b>{esc(s["name"])}</b> has unpublished changes. '
                     f'<a href="/rulesets/{esc(s["name"])}/review">Review and publish</a></div>' for s in pending)
    trs = []
    for r in rows:
        role = r.role
        rid = f"sel-{r.template_id}"
        trs.append(f'<tr class="pick"><td class="n"><input type="radio" name="sel" id="{rid}" '
                   f'value="{r.template_id}:{esc(r.location_id)}" aria-label="Select {esc(role.get("templateName"))}"></td>'
                   f'<td>{role_link(r)}</td><td>{esc(r.location)}</td><td>{ruleset_link(r.ruleset)}</td>'
                   f'<td>{vlan_label(role)}</td><td>{"On" if role.get("firewallEnabled") else "Off"}</td>'
                   f'<td>{status_pill(r)}</td></tr>')
    managed = sum(1 for r in rows if r.ruleset)
    toolbar = ('<div class="row" style="margin-bottom:10px"><a class="btn primary" href="/roles/new">Add role profile</a>'
               '<button formaction="/roles/edit">Edit</button><button formaction="/roles/delete" class="danger">Delete</button>'
               '<span class="sub" style="margin:0" id="selhint">Select a role profile to edit or delete it.</span></div>')
    script = ('<script>document.querySelectorAll("tr.pick").forEach(function(tr){tr.addEventListener("click",function(e){'
              'if(e.target.closest("a,button,input"))return;var r=tr.querySelector("input[type=radio]");r.checked=true;'
              'r.dispatchEvent(new Event("change",{bubbles:true}));});});document.getElementById("rolesForm")'
              '.addEventListener("change",function(){var c=document.querySelector("input[name=sel]:checked");'
              'document.querySelectorAll("tr.pick").forEach(function(tr){tr.classList.toggle("sel",tr.contains(c));});'
              'document.getElementById("selhint").textContent=c?"Selected: "+c.closest("tr").querySelector("a").textContent:"";});'
              '</script>')
    return (f'<h1>Network profiles · Roles</h1><p class="sub">{len(rows)} role profiles, {managed} linked to a rule set. '
            'Link a role profile to a rule set to manage its firewall rules from here.</p>' + banner +
            '<form method="get" id="rolesForm" class="card tw">' + toolbar +
            '<table><tr><th></th><th>Role profile</th><th>Location</th><th>Firewall rule set</th>'
            '<th>VLAN</th><th>Firewall</th><th>Sync status</th></tr>' + "".join(trs) + "</table></form>" + script)


def role_form(mode: str, f: dict, errors: list[str], locations: dict, sets: list[dict], current_ruleset: str = "",
              tid: int | None = None, loc=None) -> str:
    v = f.get
    creating = mode == "create"
    errs = "".join(f"<li>{esc(e)}</li>" for e in errors)
    published = [s for s in sets if s["latest"]]

    def sel(field, value, default=""):
        return "selected" if (v(field) or default) == value else ""

    rs_opts = ['<option value="">None (manage firewall rules in CV-CUE)</option>']
    names = {s["name"] for s in published}
    for s in published:
        rs_opts.append(f'<option value="{esc(s["name"])}" {sel("ruleset", s["name"])}>{esc(s["name"])} (v{s["latest"]})</option>')
    if current_ruleset and current_ruleset not in names:
        rs_opts.append(f'<option value="{esc(current_ruleset)}" {sel("ruleset", current_ruleset)}>'
                       f'{esc(current_ruleset)} (keep tag; not set up in this app)</option>')
    loc_field = ""
    if creating:
        opts = "".join(f'<option value="{k}" {sel("location", str(k))}>{esc(p)}</option>' for k, p in locations.items())
        loc_field = f'<label>Location<select name="location" required>{opts}</select></label>'
    else:
        loc_field = f'<label>Location<input value="{esc(locations.get(loc, loc))}" disabled></label>'
    unit = lambda key: (f'<select name="{key}_unit" aria-label="Unit"><option value="1" {sel(key + "_unit", "1")}>Mbps</option>'  # noqa: E731
                        f'<option value="0" {sel(key + "_unit", "0", "1")}>Kbps</option></select>')
    action = "/roles/new" if creating else f"/roles/{tid}/edit"
    crumb = ("Add role profile" if creating else
             f'<a href="/roles/{tid}?loc={esc(loc)}">{esc(f.get("orig_name") or v("name"))}</a> / Edit')
    rs_note = ("Choosing a rule set applies its latest published version and tags the role profile. "
               "Choosing None removes the tag and leaves the current firewall rules as they are.")
    return (f'<div class="crumb"><a href="/roles">Role profiles</a> / {crumb}</div>'
            f'<h1>{"Add role profile" if creating else "Edit role profile"}</h1>'
            '<p class="sub">Saved straight to CV-CUE, then read back to check.</p>'
            + (f'<ul class="errors flash bad">{errs}</ul>' if errs else "") +
            f'<form method="post" action="{action}" class="card">{CSRF}'
            + ("" if creating else f'<input type="hidden" name="loc" value="{esc(loc)}">') +
            '<div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(260px,1fr))">'
            f'<label>Role name<input name="name" value="{esc(v("name"))}" required maxlength="64" placeholder="Staff"></label>'
            f'{loc_field}'
            f'<label style="grid-column:1/-1">Description<input name="description" value="{esc(v("description"))}" maxlength="200" '
            'placeholder="Who gets this role"></label>'
            '<label>VLAN<select name="vlan_mode">'
            f'<option value="ssid" {sel("vlan_mode", "ssid", "ssid")}>Use the SSID\'s VLAN</option>'
            f'<option value="untagged" {sel("vlan_mode", "untagged")}>Untagged</option>'
            f'<option value="id" {sel("vlan_mode", "id")}>VLAN ID</option></select></label>'
            f'<label>VLAN ID<input name="vlan_id" value="{esc(v("vlan_id"))}" inputmode="numeric" placeholder="20"></label>'
            f'<label style="grid-column:1/-1">Firewall rule set<select name="ruleset">{"".join(rs_opts)}</select>'
            f'<span>{rs_note}</span></label>'
            '<fieldset style="grid-column:1/-1;border:1px solid var(--border);border-radius:8px;padding:10px 12px">'
            '<legend style="font-size:12px;color:var(--muted)">Per-user traffic control</legend>'
            f'<label style="flex-direction:row;align-items:center;gap:8px;color:var(--text)"><input type="checkbox" name="tc_enabled" '
            f'value="1" {"checked" if v("tc_enabled") else ""}> Limit each client\'s bandwidth</label>'
            '<div class="row" style="margin-top:8px">'
            f'<label>Download<span class="row"><input name="down" value="{esc(v("down"))}" size="7" inputmode="numeric">{unit("down")}</span></label>'
            f'<label>Upload<span class="row"><input name="up" value="{esc(v("up"))}" size="7" inputmode="numeric">{unit("up")}</span></label>'
            '</div></fieldset></div>'
            f'<div class="row" style="margin-top:16px"><button class="primary">{"Create role profile" if creating else "Save changes"}</button>'
            f'<a class="btn" href="{"/roles" if creating else f"/roles/{tid}?loc={esc(loc)}"}">Cancel</a></div></form>')


def role_delete(row, refs: list[str]) -> str:
    role = row.role
    tid, loc = row.template_id, row.location_id
    name = esc(role.get("templateName"))
    if refs:
        body = (f'<p>{name} can\'t be deleted while these profiles use it: <b>{esc(", ".join(refs))}</b>. '
                'Remove it from them in CV-CUE first.</p>'
                f'<a class="btn" href="/roles/{tid}?loc={esc(loc)}">Back</a>')
    else:
        body = (f'<p>This permanently deletes the role profile <b>{name}</b> from CV-CUE at {esc(row.location)}. '
                'It can\'t be undone here; you\'d have to create it again.</p>'
                + (f'<p class="sub">It\'s linked to {esc(row.ruleset)}; the rule set itself is kept.</p>' if row.ruleset else "")
                + f'<form method="post" action="/roles/{tid}/delete" class="row">{CSRF}'
                f'<input type="hidden" name="loc" value="{esc(loc)}"><button class="primary danger-fill">Delete {name}</button>'
                f'<a class="btn" href="/roles/{tid}?loc={esc(loc)}">Cancel</a></form>')
    return (f'<div class="crumb"><a href="/roles">Role profiles</a> / <a href="/roles/{tid}?loc={esc(loc)}">{name}</a> / Delete</div>'
            f'<h1>Delete {name}?</h1><div class="card">{body}</div>')


def ruleset_missing(name: str, linked) -> str:
    sources = "".join(f'<option value="role:{r.template_id}:{esc(r.location_id)}">Copy current rules from '
                      f'{esc(r.role["templateName"])}</option>' for r in linked if r.role.get("firewallEnabled"))
    used = ", ".join(role_link(r) for r in linked) or "none"
    return (f'<div class="crumb"><a href="/rulesets">Rule sets</a> / {esc(name)}</div>'
            f'<h1>{esc(name)} isn\'t set up in this app yet</h1>'
            f'<p class="sub">These role profiles are tagged <span class="mono">ruleset:{esc(name)}</span> in CV-CUE: {used}. '
            'Create the rule set here to manage them. Starting from a linked role profile\'s current rules means '
            'publishing it changes nothing on CV-CUE.</p>'
            f'<form method="post" action="/rulesets" class="card row" style="align-items:flex-end">{CSRF}'
            f'<input type="hidden" name="name" value="{esc(name)}">'
            f'<label>Start from<select name="source">{sources}<option value="">Empty</option></select></label>'
            f'<label style="flex:1;min-width:220px">Description<input name="description" placeholder="What this rule set allows"></label>'
            f'<button class="primary">Create {esc(name)}</button></form>')


def rules_table(content: dict, compare: dict | None = None, editable: bool = False, name: str = "",
                edit_i: int | None = None) -> str:
    c = R.normalize(content)
    known = {R.describe(r) for r in (compare or {}).get("rules", [])} if compare is not None else None
    trs = []
    for i, r in enumerate(c["rules"]):
        new = known is not None and R.describe(r) not in known
        tools = ""
        if editable:
            def btn(op, label, extra=""):
                return (f'<form method="post" action="/rulesets/{esc(name)}/edit" class="inline">{CSRF}'
                        f'<input type="hidden" name="op" value="{op}"><input type="hidden" name="i" value="{i}">'
                        f'<button class="small {extra}" aria-label="{esc(label)} rule {i + 1}">{label}</button></form>')
            tools = (f'<td class="row" style="flex-wrap:nowrap"><a class="btn small" href="?edit={i}#rule-form">Edit</a>'
                     + (btn("up", "↑") if i else "") + (btn("down", "↓") if i < len(c["rules"]) - 1 else "")
                     + btn("delete", "Delete", "danger") + "</td>")
        mark = ' <span class="pill pend">Changed</span>' if new else ""
        extra = f' <span class="tag">dscp {r["dscp"]}</span>' if r["dscp"] or r["mark"] != R.MARK_DEFAULT else ""
        trs.append(f'<tr class="{"new" if new else ""}{" editing" if edit_i == i else ""}"><td class="n">{i + 1}</td>'
                   f'<td>{esc(r["name"])}{mark}{extra}</td><td>{R.DIRECTIONS[r["direction"]]}</td>'
                   f'<td>{R.protocol_label(r["protocol"])}</td><td>{esc(r["port"]) or "Any"}</td>'
                   f'<td>{esc(r["host"]) or "Any"}</td><td>{R.ACTIONS[r["action"]]}</td>{tools}</tr>')
    if editable:
        default_cell = (f'<form method="post" action="/rulesets/{esc(name)}/edit" class="row">{CSRF}'
                        '<input type="hidden" name="op" value="default"><select name="default_action" aria-label="Default rule action">'
                        f'<option value="2" {"selected" if c["default_action"] == 2 else ""}>Block</option>'
                        f'<option value="1" {"selected" if c["default_action"] == 1 else ""}>Allow</option>'
                        '</select><button class="small">Set</button></form>')
    else:
        default_cell = R.ACTIONS[c["default_action"]]
    changed_default = compare is not None and compare.get("default_action") != c["default_action"]
    trs.append(f'<tr class="{"new" if changed_default else ""}"><td class="n">·</td><td style="color:var(--muted)">Default rule</td>'
               f'<td>Any</td><td>Any</td><td>Any</td><td>Any</td><td>{default_cell}</td>{"<td></td>" if editable else ""}</tr>')
    head = ("<tr><th></th><th>Rule name</th><th>Direction</th><th>Protocol</th><th>Port</th><th>Hostname</th>"
            f'<th>Action</th>{"<th></th>" if editable else ""}</tr>')
    return f'<div class="tw"><table>{head}{"".join(trs)}</table></div>'


def role_detail(row, current, sets, latest, changes) -> str:
    role = row.role
    tid, loc = row.template_id, row.location_id
    hidden = f'{CSRF}<input type="hidden" name="loc" value="{esc(loc)}">'
    rs_link = ruleset_link(row.ruleset)
    info = (f'<div class="grid" style="margin-bottom:16px">'
            f'<div class="stat"><div class="l">Location</div>{esc(row.location)}</div>'
            f'<div class="stat"><div class="l">VLAN</div>{vlan_label(role)}</div>'
            f'<div class="stat"><div class="l">Firewall</div>{"On" if role.get("firewallEnabled") else "Off"}</div>'
            f'<div class="stat"><div class="l">Firewall rule set</div>'
            f'{rs_link}</div>'
            f'<div class="stat"><div class="l">Sync status</div>{status_pill(row)}</div></div>')
    published = [s for s in sets if s["latest"]]
    link_form = ""
    if published:
        opts = "".join(f'<option value="{esc(s["name"])}" {"selected" if s["name"] == row.ruleset else ""}>'
                       f'{esc(s["name"])} (v{s["latest"]})</option>' for s in published)
        link_form = (f'<form method="get" action="/roles/{tid}/link" class="row"><input type="hidden" name="loc" value="{esc(loc)}">'
                     f'<select name="ruleset" aria-label="Rule set">{opts}</select>'
                     f'<button>{"Change rule set" if row.ruleset else "Link to rule set"}</button></form>')
    actions = []
    if row.status in ("drifted", "behind") and latest:
        lines = "".join(_diff_line(k, t) for k, t in changes)
        what = ("Someone changed this role profile's firewall rules in CV-CUE. They no longer match any published version."
                if row.status == "drifted" else f"This role profile still has v{row.version}.")
        actions.append(f'<div class="card"><h2>Out of sync with {esc(row.ruleset)} v{latest["version"]}</h2><p>{what}</p>'
                       f'<p class="sub">Changes needed to match v{latest["version"]}:</p><div class="diff">{lines}</div>'
                       f'<div class="row" style="margin-top:12px"><form method="post" action="/roles/{tid}/revert" class="inline">{hidden}'
                       f'<button class="primary">Apply v{latest["version"]} to this role profile</button></form>'
                       + (f'<form method="post" action="/roles/{tid}/adopt" class="inline">{hidden}'
                          f'<button>Copy these rules into the {esc(row.ruleset)} draft</button></form>'
                          if row.status == "drifted" else "") + "</div></div>")
    manage = []
    if link_form:
        manage.append(link_form)
    if row.ruleset:
        manage.append(f'<form method="post" action="/roles/{tid}/unlink" class="inline">{hidden}'
                      '<button class="danger">Unlink (keep current rules)</button></form>')
    if role.get("firewallEnabled") and not row.ruleset:
        manage.append(f'<form method="post" action="/rulesets" class="row">{CSRF}'
                      f'<input type="hidden" name="source" value="role:{tid}:{esc(loc)}">'
                      f'<input name="name" placeholder="new-rule-set-name" aria-label="New rule set name" required>'
                      '<button>Create rule set from these rules</button></form>')
    if not published and not row.ruleset:
        manage.append('<p class="sub">Publish a rule set first, then link this role profile to it.</p>')
    head_buttons = (f'<div class="row"><a class="btn primary" href="/roles/{tid}/edit?loc={esc(loc)}">Edit role profile</a>'
                    f'<a class="btn danger" href="/roles/{tid}/delete?loc={esc(loc)}">Delete</a></div>')
    return (f'<div class="crumb"><a href="/roles">Role profiles</a> / {esc(role.get("templateName"))}</div>'
            f'<div class="row" style="justify-content:space-between"><h1>{esc(role.get("templateName"))}</h1>{head_buttons}</div>'
            f'<p class="sub">{esc(role.get("description")) or "No description"}</p>'
            + info + "".join(actions) +
            f'<div class="card"><h2>Firewall rules on CV-CUE</h2>'
            f'{rules_table(current) if role.get("firewallEnabled") else "<p>Firewall is off for this role profile.</p>"}</div>'
            f'<div class="card"><h2>Manage</h2><div class="row" style="gap:16px">{"".join(manage)}</div>'
            '<p class="sub" style="margin:12px 0 0">Linking writes <span class="mono">ruleset:&lt;name&gt;</span> into the role '
            'profile\'s CV-CUE description and applies the rule set\'s latest published version. VLAN, traffic control, '
            'and web quarantine settings stay as they are.</p></div>')


def link_review(role, loc, name, version, changes) -> str:
    tid = role["templateId"]
    lines = "".join(_diff_line(k, t) for k, t in changes) or "No firewall changes; only the description tag is added."
    return (f'<div class="crumb"><a href="/roles">Role profiles</a> / <a href="/roles/{tid}?loc={esc(loc)}">'
            f'{esc(role["templateName"])}</a> / Link</div><h1>Link {esc(role["templateName"])} to {esc(name)}</h1>'
            f'<p class="sub">This applies {esc(name)} v{version["version"]} and tags the role profile so later '
            'publishes update it too.</p>'
            f'<div class="card"><h2>Changes on CV-CUE</h2><div class="diff">{lines}</div>'
            f'<div class="diff">~ description: "{esc(role.get("description") or "")}" → '
            f'"{esc(R.set_tag(role.get("description"), name))}"</div>'
            f'<form method="post" action="/roles/{tid}/link" class="row" style="margin-top:12px">{CSRF}'
            f'<input type="hidden" name="loc" value="{esc(loc)}"><input type="hidden" name="ruleset" value="{esc(name)}">'
            f'<button class="primary">Link and apply v{version["version"]}</button>'
            f'<a class="btn" href="/roles/{tid}?loc={esc(loc)}">Cancel</a></form></div>')


def _out_pill(out: int) -> str:
    return f' <span class="pill warn">{out} out of sync</span>' if out else ""


def _diff_line(kind: str, text: str) -> str:
    cls = {"+": "plus", "-": "minus"}.get(kind, "tilde")
    return f'<div class="{cls}">{esc(kind)} {esc(text)}</div>'


# ------------------------------------------------------------ rule sets
def rulesets(sets, usage, unmanaged) -> str:
    trs = []
    for s in sets:
        used = usage.get(s["name"], [])
        out = sum(1 for r in used if r.status != "in_sync")
        state = ('<span class="pill pend">Unpublished changes</span>' if s["has_changes"] and s["latest"]
                 else '<span class="pill muted">Not published</span>' if not s["latest"]
                 else '<span class="pill ok">Published</span>')
        trs.append(f'<tr><td><a href="/rulesets/{esc(s["name"])}">{esc(s["name"])}</a></td><td>{esc(s["description"])}</td>'
                   f'<td>{len(s["draft"]["rules"])}</td><td>{"v" + str(s["latest"]) if s["latest"] else "-"}</td>'
                   f'<td>{state}</td><td>{len(used)}{_out_pill(out)}</td></tr>')
    table = ('<div class="card tw"><table><tr><th>Rule set</th><th>Description</th><th>Rules</th><th>Published</th>'
             '<th>Status</th><th>Role profiles</th></tr>' + "".join(trs) + "</table></div>") if sets else \
        '<div class="card"><p>Create your first rule set below. You can start empty or copy the rules from an existing role profile.</p></div>'
    sources = "".join(f'<option value="role:{r.template_id}:{esc(r.location_id)}">Copy from {esc(r.role["templateName"])}</option>'
                      for r in unmanaged)
    return ('<h1>Firewall rule sets</h1><p class="sub">A rule set is an ordered list of firewall rules kept in this app. '
            'Publishing it writes the rules into every role profile linked to it.</p>' + table +
            f'<div class="card"><h2>New rule set</h2><form method="post" action="/rulesets" class="row" style="align-items:flex-end">{CSRF}'
            '<label>Name<input name="name" placeholder="guest-web" required pattern="[A-Za-z0-9_.\\-]{1,48}"></label>'
            '<label style="flex:1;min-width:200px">Description<input name="description" placeholder="Web access for guest devices"></label>'
            f'<label>Start from<select name="source"><option value="">Empty</option>{sources}</select></label>'
            '<button class="primary">Create</button></form></div>')


def ruleset_editor(rs, rows, edit_i, form_errors) -> str:
    name = rs["name"]
    draft = rs["draft"]
    out = sum(1 for r in rows if r.status != "in_sync")
    status = ('<span class="pill pend">Draft · unpublished changes</span>' if rs["has_changes"] and rs["latest"]
              else '<span class="pill muted">Draft · never published</span>' if not rs["latest"]
              else f'<span class="pill ok">v{rs["latest"]} published</span>')
    used = ", ".join(role_link(r) for r in rows) or "No role profiles yet"
    review_cls = "primary" if rs["has_changes"] or out else ""
    head = (f'<div class="crumb"><a href="/rulesets">Rule sets</a> / {esc(name)}</div>'
            f'<div class="row" style="justify-content:space-between"><div><h1>{esc(name)} <span class="tag">Firewall rule set</span></h1></div>'
            f'<div class="row"><a class="btn {review_cls}" href="/rulesets/{esc(name)}/review">Review and publish</a>'
            f'<a class="btn" href="/rulesets/{esc(name)}/history">Version history</a>'
            f'<a class="btn" href="/rulesets/{esc(name)}/export">Export JSON</a></div></div>'
            f'<form method="post" action="/rulesets/{esc(name)}/edit" class="row" style="margin:6px 0 14px">{CSRF}'
            f'<input type="hidden" name="op" value="describe"><input name="description" value="{esc(rs["description"])}" '
            'placeholder="Description" aria-label="Description" style="min-width:320px"><button class="small">Save description</button></form>'
            f'<div class="grid" style="margin-bottom:16px"><div class="stat"><div class="l">Status</div>{status}</div>'
            f'<div class="stat"><div class="l">Applied to</div>{len(rows)} role profile(s)'
            f'{_out_pill(out)}</div>'
            f'<div class="stat" style="grid-column:span 2"><div class="l">Role profiles</div>{used}</div></div>')
    compare = rs["published"] if rs["latest"] else None
    table = (f'<div class="card"><div class="row" style="justify-content:space-between"><h2>Firewall rules (Layer 3-4)</h2>'
             '<span class="sub" style="margin:0">Evaluated top to bottom; the default rule applies last.</span></div>'
             f'{rules_table(draft, compare, True, name, edit_i)}'
             + (f'<form method="post" action="/rulesets/{esc(name)}/edit" style="margin-top:10px">{CSRF}'
                '<input type="hidden" name="op" value="discard"><button class="small">Discard draft changes</button></form>'
                if rs["has_changes"] and rs["latest"] else "") + "</div>")
    return head + table + rule_form(name, draft, edit_i, form_errors) + (
        f'<div class="card"><details><summary>Import rules from JSON</summary><p class="sub">Paste a file exported from this '
        'app, or a rule set file used with sync.py. It replaces the draft; nothing reaches CV-CUE until you publish.</p>'
        f'<form method="post" action="/rulesets/{esc(name)}/edit">{CSRF}<input type="hidden" name="op" value="import">'
        '<textarea name="json" rows="6" style="width:100%" class="mono" aria-label="Rule set JSON"></textarea>'
        '<button style="margin-top:8px">Import into draft</button></form></details></div>'
        + (f'<div class="card"><form method="post" action="/rulesets/{esc(name)}/delete">{CSRF}'
           f'<button class="danger">Delete {esc(name)}</button></form></div>' if not rows else ""))


def rule_form(name, draft, edit_i, form_errors) -> str:
    values = {}
    if form_errors:
        values = form_errors.get("values", {})
    elif edit_i is not None:
        r = draft["rules"][edit_i]
        values = {"name": r["name"], "direction": str(r["direction"]), "port": r["port"], "host": r["host"],
                  "action": str(r["action"]),
                  "protocol": str(r["protocol"]) if r["protocol"] in (0, 1, 2) else "other",
                  "protocol_number": str(r["protocol"] - 3) if r["protocol"] > 2 else ""}
    v = values.get
    op = "update" if edit_i is not None else "add"
    errs = "".join(f"<li>{esc(e)}</li>" for e in (form_errors or {}).get("errors", []))

    def opt(field, value, label, default=""):
        return f'<option value="{value}" {"selected" if (v(field) or default) == value else ""}>{label}</option>'

    title = f"Edit rule {edit_i + 1}" if edit_i is not None else "Add a rule"
    return (f'<div class="card" id="rule-form"><h2>{title}</h2>' + (f'<ul class="errors">{errs}</ul>' if errs else "") +
            f'<form method="post" action="/rulesets/{esc(name)}/edit" class="row" style="align-items:flex-end">{CSRF}'
            f'<input type="hidden" name="op" value="{op}">'
            + (f'<input type="hidden" name="i" value="{edit_i}">' if edit_i is not None else "") +
            f'<label>Rule name<input name="name" value="{esc(v("name"))}" placeholder="Allow-HTTPS" required></label>'
            '<label>Direction<select name="direction">' + opt("direction", "2", "Out", "2") + opt("direction", "1", "In") +
            opt("direction", "0", "Any") + "</select></label>"
            '<label>Protocol<select name="protocol">' + opt("protocol", "1", "TCP", "1") + opt("protocol", "2", "UDP") +
            opt("protocol", "0", "Any") + opt("protocol", "other", "Other IP protocol") + "</select></label>"
            f'<label>Protocol no.<input name="protocol_number" value="{esc(v("protocol_number"))}" size="4" placeholder="47"></label>'
            f'<label>Port<input name="port" value="{esc(v("port"))}" size="9" placeholder="443"></label>'
            f'<label>Hostname<input name="host" value="{esc(v("host"))}" placeholder="Any"></label>'
            '<label>Action<select name="action">' + opt("action", "1", "Allow", "1") + opt("action", "2", "Block") +
            "</select></label>"
            f'<button class="primary">{"Save rule" if edit_i is not None else "Add rule"}</button>'
            + (f'<a class="btn" href="/rulesets/{esc(name)}">Cancel</a>' if edit_i is not None else "") +
            '</form><p class="sub" style="margin:10px 0 0">Changes go into the draft. Nothing reaches CV-CUE until you review and publish. '
            'Protocol no. is used only with "Other IP protocol"; leave port empty for any port.</p></div>')


def review(plan) -> str:
    name = plan.ruleset["name"]
    upd = plan.to_update
    locs = len({i.row.location for i in upd})
    if plan.new_version:
        what = f'This publishes v{(plan.ruleset["latest"] or 0) + 1} of {esc(name)}'
    else:
        what = f'This re-applies v{plan.ruleset["latest"]} of {esc(name)}' if plan.ruleset["latest"] else ""
    if not plan.items and plan.new_version:
        summary = f"{what}. No role profiles are linked yet, so nothing on CV-CUE changes."
    elif not upd and not plan.new_version:
        summary = f"Everything is published and all {len(plan.items)} linked role profile(s) are in sync. Nothing to do."
    else:
        summary = (f"{what} and updates {len(upd)} of {len(plan.items)} linked role profile(s) in {locs} location(s). "
                   "VLAN, traffic control, and web quarantine settings stay as they are.")
    blocks = []
    for item in plan.items:
        body = ("".join(_diff_line(k, t) for k, t in item.changes) if item.changes
                else '<div style="color:var(--muted)">Already matches. Not updated.</div>')
        blocks.append(f'<div style="margin-bottom:12px"><div>{role_link(item.row)} '
                      f'<span style="color:var(--muted)">· {esc(item.row.location)}</span> {status_pill(item.row)}</div>'
                      f'<div class="diff">{body}</div></div>')
    can = plan.new_version or upd
    button = (f'<form method="post" action="/rulesets/{esc(name)}/publish" class="row">{CSRF}'
              f'<input type="hidden" name="token" value="{esc(plan.token)}">'
              f'<button class="primary">{"Publish" if plan.new_version else "Apply"}'
              f'{f" to {len(upd)} role profile(s)" if upd else ""}</button>'
              f'<a class="btn" href="/rulesets/{esc(name)}">Back to editor</a></form>' if can else
              f'<a class="btn" href="/rulesets/{esc(name)}">Back to editor</a>')
    rules = rules_table(plan.target, plan.ruleset["published"])
    return (f'<div class="crumb"><a href="/rulesets">Rule sets</a> / <a href="/rulesets/{esc(name)}">{esc(name)}</a> / Review</div>'
            f'<h1>Review and publish</h1><p class="sub">{summary}</p>'
            f'<div class="card"><h2>Rules to publish</h2>{rules}</div>'
            f'<div class="card"><h2>Changes per role profile</h2>{"".join(blocks) or "<p>No linked role profiles.</p>"}{button}</div>')


def history(rs, versions, runs) -> str:
    name = rs["name"]
    vs = []
    for v in versions:
        vs.append(f'<tr><td>v{v["version"]}</td><td>{ts(v["published_at"])}</td><td>{esc(v["published_by"])}</td>'
                  f'<td>{len(v["content"]["rules"])}</td><td><details><summary>Show rules</summary>{rules_table(v["content"])}</details></td>'
                  f'<td><form method="post" action="/rulesets/{esc(name)}/restore">{CSRF}'
                  f'<input type="hidden" name="version" value="{v["version"]}"><button class="small">Load into draft</button></form></td></tr>')
    return (f'<div class="crumb"><a href="/rulesets">Rule sets</a> / <a href="/rulesets/{esc(name)}">{esc(name)}</a> / History</div>'
            f'<h1>{esc(name)} version history</h1><p class="sub">To roll back, load an older version into the draft, then review and publish it.</p>'
            '<div class="card tw"><table><tr><th>Version</th><th>Published</th><th>By</th><th>Rules</th><th></th><th></th></tr>'
            + ("".join(vs) or '<tr><td colspan="6">Not published yet.</td></tr>') + "</table></div>"
            + f'<div class="card"><h2>Activity</h2>{runs_table(runs)}</div>')


def runs_table(runs) -> str:
    if not runs:
        return "<p>No activity yet.</p>"
    trs = []
    for r in runs:
        res = (f'<span class="pill ok">{r["ok_count"]} ok</span>' if r["ok_count"] else "") + \
              (f' <span class="pill bad">{r["fail_count"]} failed</span>' if r["fail_count"] else "")
        trs.append(f'<tr><td><a href="/runs/{r["id"]}">#{r["id"]}</a></td><td>{ts(r["started_at"])}</td><td>{esc(r["kind"])}</td>'
                   f'<td>{esc(r["ruleset"])}</td><td>{esc(r["summary"])}</td><td>{res}</td><td>{esc(r["started_by"])}</td></tr>')
    return ('<div class="tw"><table><tr><th>Run</th><th>When</th><th>Action</th><th>Rule set</th><th>Summary</th>'
            '<th>Result</th><th>By</th></tr>' + "".join(trs) + "</table></div>")


def activity(runs) -> str:
    return ('<h1>Activity</h1><p class="sub">Every change this app made on CV-CUE, newest first.</p>'
            f'<div class="card">{runs_table(runs)}</div>')


def run(r) -> str:
    done, fail = '<span class="pill ok">Done</span>', '<span class="pill bad">Failed</span>'
    trs = "".join(f'<tr><td><a href="/roles/{x["template_id"]}?loc={esc(x["location_id"])}">{esc(x["role_name"])}</a></td>'
                  f'<td>{done if x["ok"] else fail}</td><td>{esc(x["message"])}</td></tr>' for x in r["results"])
    failed = any(not x["ok"] for x in r["results"])
    hint = ('<p class="sub">Failed role profiles weren\'t changed or didn\'t verify. Open the rule set\'s review page to '
            'retry; it only updates role profiles that are still out of sync.</p>' if failed else "")
    return (f'<div class="crumb"><a href="/activity">Activity</a> / Run #{r["id"]}</div>'
            f'<h1>{esc(r["kind"].capitalize())} · {esc(r["ruleset"])}</h1>'
            f'<p class="sub">{esc(r["summary"])} · {ts(r["started_at"])} · {esc(r["started_by"])}</p>{hint}'
            '<div class="card tw"><table><tr><th>Role profile</th><th>Result</th><th>Details</th></tr>'
            + (trs or '<tr><td colspan="3">No role profiles needed an update.</td></tr>') + "</table></div>"
            + f'<a class="btn" href="/rulesets/{esc(r["ruleset"])}">Open {esc(r["ruleset"])}</a>')
