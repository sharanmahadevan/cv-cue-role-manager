"""HTML pages (server-rendered, no build step). Terms follow CV-CUE: role profiles, firewall rules, locations."""

from __future__ import annotations

import datetime as dt
from html import escape

from .. import rules as R

CSRF = '<input type="hidden" name="csrf" value="__CSRF__">'

STATUS = {
    "in_sync": ("ok", "In sync"),
    "behind": ("pend", "Update pending"),
    "drifted": ("warn", "Edited in CV-CUE"),
    "not_published": ("muted", "Waiting for {m} to be published"),
    "unknown_ruleset": ("warn", "Unknown rule set: {m}"),
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
.req{color:var(--bad);margin-left:2px}.opt{flex-direction:row;align-items:center;gap:8px;color:var(--text);font-size:14px}
.opt.big{font-size:16px;font-weight:600}.dashed{border:1px dashed var(--border);border-radius:8px;padding:16px;display:flex;align-items:center}
[hidden]{display:none!important}
@media (max-width:640px){main .grid{grid-template-columns:1fr!important}main .grid>label,main .grid>div{grid-area:auto!important;grid-column:auto!important}
header{padding:10px 16px}main{padding:16px 12px 48px}}
tr.dup td{opacity:.45}tr.dup td:nth-child(2){text-decoration:line-through}.rs-note{font-size:12px;margin-left:6px;display:inline-block}
tr.dup .rs-note{text-decoration:none;color:var(--muted)}tr.conflict td{background:var(--warn-bg)}tr.conflict .rs-note{color:var(--warn)}
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
    text = label.format(m=", ".join(row.missing))
    title = ""
    if row.status == "in_sync" and row.versions:
        text += " · " + " + ".join(f"v{row.versions[n]}" for n in row.rulesets)
        title = ", ".join(f"{n} v{row.versions[n]}" for n in row.rulesets)
    elif row.status == "behind" and row.version:
        text += f" · on v{row.version}"
    return f'<span class="pill {cls}" title="{esc(title)}">{esc(text)}</span>'


def role_link(row) -> str:
    return f'<a href="/roles/{row.template_id}?loc={esc(row.location_id)}">{esc(row.role.get("templateName"))}</a>'


# ------------------------------------------------------------ role profiles
def vlan_label(role: dict) -> str:
    if not role.get("vlanEnabled"):
        return "From SSID"
    return esc(role.get("vlanId")) if role.get("vlanId") else "Untagged"


def ruleset_link(name: str | None) -> str:
    return f'<a href="/rulesets/{esc(name)}">{esc(name)}</a>' if name else '<span class="none">None</span>'


def ruleset_links(names: list[str]) -> str:
    """Linked rule sets in the order they apply."""
    if not names:
        return '<span class="none">None</span>'
    return '<span class="none"> + </span>'.join(ruleset_link(n) for n in names)


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
                   f'<td>{role_link(r)}</td><td>{esc(r.location)}</td><td>{ruleset_links(r.rulesets)}</td>'
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
            '<table><tr><th></th><th>Role profile</th><th>Location</th><th>Firewall rule sets</th>'
            '<th>VLAN</th><th>Firewall</th><th>Sync status</th></tr>' + "".join(trs) + "</table></form>" + script)


def role_form(mode: str, f: dict, errors: list[str], locations: dict, sets: list[dict], current_rulesets=None,
              tid: int | None = None, loc=None, role: dict | None = None) -> str:
    """Add/edit role profile, laid out like the CV-CUE role editor."""
    v = f.get
    creating = mode == "create"
    role = role or {}
    errs = "".join(f"<li>{esc(e)}</li>" for e in errors)

    def checked(field):
        return "checked" if v(field) else ""

    def sel(field, value, default=""):
        return "selected" if (v(field) or default) == value else ""

    def radio(field, value, label, default=""):
        on = "checked" if (v(field) or default) == value else ""
        return (f'<label class="opt"><input type="radio" name="{field}" value="{value}" {on}> {label}</label>')

    # --- rule sets: an ordered list, combined in that order
    current_rulesets = current_rulesets or []
    names = {s["name"] for s in sets}
    keep_ok = not creating and role.get("firewallEnabled")

    def rs_select(selected: str) -> str:
        opts = ['<option value="">Select a rule set</option>']
        for s in sets:
            if s["latest"]:
                on = "selected" if s["name"] == selected else ""
                opts.append(f'<option value="{esc(s["name"])}" {on}>{esc(s["name"])} '
                            f'(v{s["latest"]}, {len(s["published"]["rules"])} rules)</option>')
            else:
                opts.append(f'<option value="{esc(s["name"])}" disabled>{esc(s["name"])} (not published yet)</option>')
        for n in current_rulesets:
            if n not in names:
                on = "selected" if n == selected else ""
                opts.append(f'<option value="{esc(n)}" {on}>{esc(n)} (keep tag; not set up in this app)</option>')
        on = "selected" if selected == "__new__" else ""
        opts.append(f'<option value="__new__" {on}>+ Create new rule set…</option>')
        return ('<div class="rs-row row" style="margin-bottom:8px"><span class="rs-n sub" style="margin:0;min-width:18px"></span>'
                f'<select name="rulesets" aria-label="Rule set" style="max-width:440px;flex:1">{"".join(opts)}</select>'
                '<button type="button" class="small rs-up" aria-label="Move up">↑</button>'
                '<button type="button" class="small rs-down" aria-label="Move down">↓</button>'
                '<button type="button" class="small danger rs-del">Remove</button></div>')

    chosen = [n for n in (v("rulesets") or []) if n]
    rs_rows = "".join(rs_select(n) for n in chosen) + rs_select("")
    previews = "".join(
        f'<div class="rs-preview" data-rs="{esc(s["name"])}" data-default="{s["published"]["default_action"]}" hidden>'
        f'<div class="row" style="justify-content:space-between;margin:12px 0 6px">'
        f'<span><b>{esc(s["name"])}</b> <span class="sub" style="margin:0">v{s["latest"]}'
        f'{" · " + esc(s["description"]) if s["description"] else ""}</span></span>'
        f'<a class="btn small" href="/rulesets/{esc(s["name"])}" target="_blank" rel="noopener">Edit rule set</a></div>'
        f'{rules_table(s["published"], show_default=False, annotate=True)}</div>' for s in sets if s["latest"])
    keep_hint = ("Leave the list empty to keep this role profile's current rules without a rule set."
                 if keep_ok else "")

    # --- location
    if creating:
        opts = "".join(f'<option value="{k}" {sel("location", str(k))}>{esc(p)}</option>' for k, p in locations.items())
        loc_field = f'<label><span>Location<span class="req">*</span></span><select name="location" required>{opts}</select></label>'
    else:
        loc_field = f'<label>Location<input value="{esc(locations.get(loc, loc))}" disabled></label>'

    def limit(key, label):
        return (f'<div><label class="opt"><input type="checkbox" name="{key}_on" value="1" {checked(key + "_on")}> '
                f'Limit the maximum {label} bandwidth per user to</label><div class="row" style="margin-top:6px">'
                f'<input name="{key}" value="{esc(v(key))}" size="7" inputmode="numeric" aria-label="{label} limit">'
                f'<span>Mbps</span><span class="sub" style="margin:0">[1 - 1024]</span></div></div>')

    app_fw = ("On in CV-CUE (kept as is)" if role.get("applicationFirewallEnabled") else "Off") if not creating else "Off"
    redirect = (role.get("redirection") or {}).get("webQuarantineEnabled") or (role.get("redirection") or {}).get(
        "dynamicRedirectionEnabled")
    action = "/roles/new" if creating else f"/roles/{tid}/edit"
    crumb = ("Add role profile" if creating else
             f'<a href="/roles/{tid}?loc={esc(loc)}">{esc(v("orig_name") or v("profile_name"))}</a> / Edit')
    cancel = "/roles" if creating else f"/roles/{tid}?loc={esc(loc)}"
    script = ('<script>(function(){var f=document.getElementById("roleForm");var list=f.querySelector("#rsList");'
              'function sync(){var t=(f.querySelector("input[name=vlan_type]:checked")||{}).value||"id";'
              'f.querySelectorAll("[data-vlan]").forEach(function(e){e.hidden=e.dataset.vlan!==t;});'
              'f.querySelector("#vlanBody").style.opacity=f.querySelector("input[name=vlan_on]").checked?1:.45;'
              'var fon=f.querySelector("input[name=fw_on]").checked;f.querySelector("#fwBody").style.opacity=fon?1:.45;'
              'var rows=list.querySelectorAll(".rs-row"),vals=[],isNew=false,n=0;'
              'rows.forEach(function(r,i){var v=r.querySelector("select").value;r.querySelector(".rs-n").textContent=v?(++n)+".":"";'
              'r.querySelector(".rs-up").hidden=i===0;r.querySelector(".rs-down").hidden=i===rows.length-1;'
              'if(v==="__new__")isNew=true;else if(v&&vals.indexOf(v)<0)vals.push(v);});'
              'var box=f.querySelector("#rsPreviews"),block=false,shown=0;'
              'box.querySelectorAll(".rs-preview").forEach(function(p){p.hidden=true;});'
              'vals.forEach(function(v){var p=box.querySelector(\'.rs-preview[data-rs="\'+CSS.escape(v)+\'"]\');'
              'if(p){box.appendChild(p);p.hidden=false;shown++;if(p.dataset.default==="2")block=true;}});'
              'function rng(p){if(!p)return null;var x=p.split("-");return[+x[0],+(x[1]||x[0])];}'
              'function covers(a,b){var A=a.split("|"),B=b.split("|");if(A[0]!=="0"&&A[0]!==B[0])return false;'
              'if(A[1]!=="0"&&A[1]!==B[1])return false;if(A[2]){var ar=rng(A[2]),br=rng(B[2]);'
              'if(!br||br[0]<ar[0]||br[1]>ar[1])return false;}if(A[3]&&A[3]!==B[3])return false;return true;}'
              'var kept=[],dups=0,confl=0;box.querySelectorAll(".rs-preview").forEach(function(p){'
              'p.querySelectorAll("tr[data-key]").forEach(function(tr){tr.classList.remove("dup","conflict");'
              'var note=tr.querySelector(".rs-note");note.textContent="";if(p.hidden)return;var e=null;'
              'for(var i=0;i<kept.length;i++){if(kept[i].set!==p.dataset.rs&&covers(kept[i].key,tr.dataset.key)){e=kept[i];break;}}'
              'if(e){if(e.eff===tr.dataset.eff){tr.classList.add("dup");dups++;'
              'note.textContent=" Left out: "+e.name+" in "+e.set+" already matches this traffic";return;}'
              'tr.classList.add("conflict");confl++;note.textContent=" Never applies: "+e.name+" in "+e.set+" matches first";}'
              'kept.push({set:p.dataset.rs,key:tr.dataset.key,eff:tr.dataset.eff,name:tr.dataset.name});});});'
              'var sm=f.querySelector("#rsDupSummary");sm.hidden=!(dups||confl);'
              'sm.textContent=(dups?dups+" duplicate rule"+(dups>1?"s":"")+" left out":"")+(dups&&confl?"; ":"")+'
              '(confl?confl+" rule"+(confl>1?"s":"")+" never appl"+(confl>1?"y":"ies")+" (marked below)":"")+".";'
              'var d=f.querySelector("#rsDefault");d.hidden=!shown;d.textContent="Then the default rule: "+(block?"Block":"Allow")+'
              '(shown>1?(block?" (at least one rule set blocks by default)":" (every rule set allows by default)"):"")+".";'
              'f.querySelector("#newHint").hidden=!isNew;var b=f.querySelector("#saveBtn");'
              'b.textContent=isNew&&fon?"Continue to create rule set":b.dataset.label;}'
              'f.addEventListener("change",sync);'
              'f.querySelector("#rsAdd").addEventListener("click",function(){list.appendChild('
              'document.getElementById("rsTpl").content.firstElementChild.cloneNode(true));sync();});'
              'list.addEventListener("click",function(e){var r=e.target.closest(".rs-row");if(!r)return;'
              'if(e.target.classList.contains("rs-del")){if(list.querySelectorAll(".rs-row").length>1)r.remove();'
              'else r.querySelector("select").value="";}'
              'else if(e.target.classList.contains("rs-up")&&r.previousElementSibling)list.insertBefore(r,r.previousElementSibling);'
              'else if(e.target.classList.contains("rs-down")&&r.nextElementSibling)list.insertBefore(r.nextElementSibling,r);'
              'else return;sync();});sync();})();</script>')
    save = "Create role profile" if creating else "Save changes"
    return (f'<div class="crumb"><a href="/roles">Role profiles</a> / {crumb}</div>'
            f'<h1>{"Add role profile" if creating else "Edit role profile"}</h1>'
            '<p class="sub">Saved straight to CV-CUE, then read back to check.</p>'
            + (f'<ul class="errors flash bad">{errs}</ul>' if errs else "") +
            f'<form method="post" action="{action}" id="roleForm">{CSRF}'
            + ("" if creating else f'<input type="hidden" name="loc" value="{esc(loc)}">') +
            # --- names
            '<div class="card"><div class="grid" style="grid-template-columns:minmax(0,1fr) minmax(0,1fr)">'
            '<div style="display:flex;flex-direction:column;gap:12px">'
            f'<label><span>Role name<span class="req">*</span></span><input name="role_name" value="{esc(v("role_name"))}" required maxlength="64" '
            'placeholder="Enter role name"></label>'
            f'<label><span>Profile name<span class="req">*</span></span><input name="profile_name" value="{esc(v("profile_name"))}" required '
            'maxlength="64" placeholder="Enter profile name"></label>'
            f'{loc_field}'
            f'<label>Description<input name="description" value="{esc(v("description"))}" maxlength="200" placeholder="Optional"></label>'
            '</div><div class="dashed"><label class="opt"><input type="checkbox" name="inherit" value="1" '
            f'{checked("inherit")}> Use SSID settings in absence of role-specific settings</label></div></div></div>'
            # --- VLAN
            '<h2 style="margin:20px 0 10px">Role-specific settings</h2>'
            '<div class="card"><div class="row" style="justify-content:space-between">'
            f'<label class="opt big"><input type="checkbox" name="vlan_on" value="1" {checked("vlan_on")}> VLAN</label>'
            '<span class="sub" style="margin:0;font-style:italic">Not applied to SSIDs configured with NAT and role-based control settings.</span></div>'
            '<div id="vlanBody"><div class="row" style="gap:20px;margin:10px 0">'
            + radio("vlan_type", "id", "VLAN ID", "id") + radio("vlan_type", "name", "VLAN name") + radio("vlan_type", "pool", "VLAN pool") +
            '</div>'
            f'<div data-vlan="id" class="row"><input name="vlan_id" value="{esc(v("vlan_id"))}" size="6" inputmode="numeric" '
            'aria-label="VLAN ID"><span class="sub" style="margin:0">[0 - 4094] · 0 means untagged</span></div>'
            f'<div data-vlan="name" class="row"><input name="vlan_name" value="{esc(v("vlan_name"))}" aria-label="VLAN name" '
            'placeholder="Staff-VLAN"></div>'
            f'<div data-vlan="pool" class="row"><input name="vlan_pool" value="{esc(v("vlan_pool"))}" aria-label="VLAN pool" '
            'placeholder="1,2,6-23"><span class="sub" style="margin:0">Clients are spread across these VLANs</span></div></div></div>'
            # --- Firewall
            '<div class="card"><h2>Firewall</h2>'
            f'<label class="opt"><input type="checkbox" name="fw_on" value="1" {checked("fw_on")}> Layer 3-4 firewall rules</label>'
            '<div id="fwBody" style="margin-top:10px">'
            '<div class="l" style="font-size:12px;color:var(--muted);margin-bottom:6px">Firewall rule sets, applied in this order</div>'
            f'<div id="rsList">{rs_rows}</div><template id="rsTpl">{rs_select("")}</template>'
            '<button type="button" class="small" id="rsAdd">+ Add another rule set</button>'
            '<p class="sub" id="newHint" style="margin:8px 0 0" hidden>You\'ll create the rule set next, then come back here with it '
            'added. What you\'ve entered on this page is kept.</p>'
            '<p class="flash pend" id="rsDupSummary" style="margin:10px 0 0" hidden></p>'
            f'<div id="rsPreviews">{previews}</div>'
            '<p class="sub" id="rsDefault" style="margin:10px 0 0" hidden></p>'
            '<p class="sub" style="margin:10px 0 0">Rules from each rule set are applied one after another, in this order, '
            'followed by one default rule: Block if any rule set blocks by default. Publishing any of them updates this '
            f'role profile. {keep_hint} <a href="/rulesets">Manage rule sets</a></p></div>'
            f'<p class="sub" style="margin:14px 0 0">Application firewall rules: {app_fw}. Manage them in CV-CUE.</p></div>'
            # --- Bandwidth
            '<div class="card"><h2>User bandwidth control</h2><div class="grid" style="grid-template-columns:minmax(0,1fr) minmax(0,1fr)">'
            + limit("up", "upload") + limit("down", "download") + '</div></div>'
            f'<div class="card"><h2>Redirection</h2><p class="sub" style="margin:0">{"On" if redirect else "Off"} in CV-CUE. '
            'Redirection settings aren\'t changed by this app.</p></div>'
            f'<div class="row" style="justify-content:flex-end"><a class="btn" href="{cancel}">Cancel</a>'
            f'<button class="primary" id="saveBtn" data-label="{save}">{save}</button></div></form>' + script)


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
                + (f'<p class="sub">It\'s linked to {esc(" + ".join(row.rulesets))}; the rule sets themselves are kept.</p>' if row.rulesets else "")
                + f'<form method="post" action="/roles/{tid}/delete" class="row">{CSRF}'
                f'<input type="hidden" name="loc" value="{esc(loc)}"><button class="primary danger-fill">Delete {name}</button>'
                f'<a class="btn" href="/roles/{tid}?loc={esc(loc)}">Cancel</a></form>')
    return (f'<div class="crumb"><a href="/roles">Role profiles</a> / <a href="/roles/{tid}?loc={esc(loc)}">{name}</a> / Delete</div>'
            f'<h1>Delete {name}?</h1><div class="card">{body}</div>')


def draft_banner(draft: dict | None, published: bool) -> str:
    """Reminder shown while a rule set is being made for a role profile form that's waiting."""
    if not draft:
        return ""
    who = esc(draft.get("label") or "the role profile")
    back = esc(draft["back"])
    if published:
        return (f'<div class="flash ok row" style="justify-content:space-between">'
                f'<span>Published. Continue with <b>{who}</b>; the rule set will be selected.</span>'
                f'<a class="btn primary" href="{back}">Return to role profile</a></div>')
    return (f'<div class="flash pend row" style="justify-content:space-between">'
            f'<span>Creating this rule set for <b>{who}</b>. Add rules, then review and publish; '
            'a rule set must be published before a role profile can use it.</span>'
            f'<a class="btn" href="{back}">Return to role profile</a></div>')


def ruleset_new(draft: dict | None, sources) -> str:
    opts = "".join(f'<option value="role:{r.template_id}:{esc(r.location_id)}">Copy rules from '
                   f'{esc(r.role["templateName"])}</option>' for r in sources)
    banner = ""
    if draft:
        banner = (f'<div class="flash pend">Creating a rule set for <b>{esc(draft.get("label"))}</b>. '
                  'After you publish it, you\'ll return to the role profile form with it selected.</div>')
    back = esc(draft["back"]) if draft else "/rulesets"
    return ('<div class="crumb"><a href="/rulesets">Rule sets</a> / New</div><h1>New firewall rule set</h1>'
            '<p class="sub">Name it, then add rules on the next page.</p>' + banner +
            f'<form method="post" action="/rulesets" class="card">{CSRF}'
            + ('<input type="hidden" name="for_role" value="1">' if draft else "") +
            '<div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(240px,1fr))">'
            '<label><span>Name<span class="req">*</span></span><input name="name" placeholder="guest-web" required '
            'pattern="[A-Za-z0-9_.\\-]{1,48}" autofocus></label>'
            '<label>Description<input name="description" placeholder="Web access for guest devices"></label>'
            f'<label>Start from<select name="source"><option value="">Empty</option>{opts}</select></label></div>'
            f'<div class="row" style="margin-top:14px"><button class="primary">Create and add rules</button>'
            f'<a class="btn" href="{back}">Cancel</a></div></form>')


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
                edit_i: int | None = None, show_default: bool = True, annotate: bool = False) -> str:
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
        data = ""
        if annotate:   # lets the role form's preview spot duplicates across rule sets
            d, p_, port, host = R.match_key(r)
            data = (f' data-key="{d}|{p_}|{esc(port)}|{esc(host)}" data-eff="{r["action"]}|{esc(r["mark"])}|{r["dscp"]}" '
                    f'data-act="{r["action"]}" data-name="{esc(r["name"])}"')
        note = '<span class="rs-note"></span>' if annotate else ""
        trs.append(f'<tr class="{"new" if new else ""}{" editing" if edit_i == i else ""}"{data}><td class="n">{i + 1}</td>'
                   f'<td>{esc(r["name"])}{mark}{extra}{note}</td><td>{R.DIRECTIONS[r["direction"]]}</td>'
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
    if show_default:
        changed_default = compare is not None and compare.get("default_action") != c["default_action"]
        trs.append(f'<tr class="{"new" if changed_default else ""}"><td class="n">·</td><td style="color:var(--muted)">Default rule</td>'
                   f'<td>Any</td><td>Any</td><td>Any</td><td>Any</td><td>{default_cell}</td>{"<td></td>" if editable else ""}</tr>')
    head = ("<tr><th></th><th>Rule name</th><th>Direction</th><th>Protocol</th><th>Port</th><th>Hostname</th>"
            f'<th>Action</th>{"<th></th>" if editable else ""}</tr>')
    return f'<div class="tw"><table>{head}{"".join(trs)}</table></div>'


def role_detail(row, current, sets, target, changes, notes=None) -> str:
    role = row.role
    tid, loc = row.template_id, row.location_id
    hidden = f'{CSRF}<input type="hidden" name="loc" value="{esc(loc)}">'
    names = row.rulesets
    label_html = " + ".join(esc(n) for n in names)
    info = (f'<div class="grid" style="margin-bottom:16px">'
            f'<div class="stat"><div class="l">Location</div>{esc(row.location)}</div>'
            f'<div class="stat"><div class="l">VLAN</div>{vlan_label(role)}</div>'
            f'<div class="stat"><div class="l">Firewall</div>{"On" if role.get("firewallEnabled") else "Off"}</div>'
            f'<div class="stat"><div class="l">Firewall rule sets</div>{ruleset_links(names)}</div>'
            f'<div class="stat"><div class="l">Sync status</div>{status_pill(row)}</div></div>')
    published = [s for s in sets if s["latest"]]
    actions = []
    if row.status in ("drifted", "behind") and target:
        lines = "".join(_diff_line(k, t) for k, t in changes)
        what = ("Someone changed this role profile's firewall rules in CV-CUE. They no longer match the published rule sets."
                if row.status == "drifted" else "A newer version of a linked rule set hasn't been applied to this role profile.")
        actions.append(f'<div class="card"><h2>Out of sync with {label_html}</h2><p>{what}</p>'
                       f'<p class="sub">Changes needed to match the latest published versions:</p><div class="diff">{lines}</div>'
                       f'<div class="row" style="margin-top:12px"><form method="post" action="/roles/{tid}/revert" class="inline">{hidden}'
                       '<button class="primary">Apply the latest rule sets to this role profile</button></form>'
                       + (f'<form method="post" action="/roles/{tid}/adopt" class="inline">{hidden}'
                          f'<button>Copy these rules into the {esc(names[0])} draft</button></form>'
                          if row.status == "drifted" and len(names) == 1 else "") + "</div></div>")
    manage = []
    addable = [s for s in published if s["name"] not in names]
    if addable:
        keep = "".join(f'<input type="hidden" name="rulesets" value="{esc(n)}">' for n in names)
        opts = "".join(f'<option value="{esc(s["name"])}">{esc(s["name"])} (v{s["latest"]})</option>' for s in addable)
        manage.append(f'<form method="get" action="/roles/{tid}/link" class="row"><input type="hidden" name="loc" value="{esc(loc)}">'
                      f'{keep}<select name="rulesets" aria-label="Rule set to add">{opts}</select>'
                      f'<button>{"Add rule set" if names else "Link to rule set"}</button></form>')
    if names:
        manage.append(f'<a class="btn" href="/roles/{tid}/edit?loc={esc(loc)}#fwBody">Reorder or remove rule sets</a>')
        manage.append(f'<form method="post" action="/roles/{tid}/unlink" class="inline">{hidden}'
                      f'<button class="danger">Unlink {"all rule sets" if len(names) > 1 else "rule set"} (keep current rules)</button></form>')
    if role.get("firewallEnabled") and not names:
        manage.append(f'<form method="post" action="/rulesets" class="row">{CSRF}'
                      f'<input type="hidden" name="source" value="role:{tid}:{esc(loc)}">'
                      f'<input name="name" placeholder="new-rule-set-name" aria-label="New rule set name" required>'
                      '<button>Create rule set from these rules</button></form>')
    if not published and not names:
        manage.append('<p class="sub">Publish a rule set first, then link this role profile to it.</p>')
    head_buttons = (f'<div class="row"><a class="btn primary" href="/roles/{tid}/edit?loc={esc(loc)}">Edit role profile</a>'
                    f'<a class="btn danger" href="/roles/{tid}/delete?loc={esc(loc)}">Delete</a></div>')
    return (f'<div class="crumb"><a href="/roles">Role profiles</a> / {esc(role.get("templateName"))}</div>'
            f'<div class="row" style="justify-content:space-between"><h1>{esc(role.get("templateName"))}</h1>{head_buttons}</div>'
            f'<p class="sub">{esc(role.get("description")) or "No description"}</p>'
            + info + "".join(actions) +
            (f'<div class="card"><h2>Combining {label_html}</h2>{combine_notes(notes)}</div>' if notes else "") +
            f'<div class="card"><h2>Firewall rules on CV-CUE</h2>'
            f'{rules_table(current) if role.get("firewallEnabled") else "<p>Firewall is off for this role profile.</p>"}</div>'
            f'<div class="card"><h2>Manage</h2><div class="row" style="gap:16px">{"".join(manage)}</div>'
            '<p class="sub" style="margin:12px 0 0">Each linked rule set is a <span class="mono">ruleset:&lt;name&gt;</span> tag in '
            'the role profile\'s CV-CUE description. Their rules are applied in order, then one default rule (Block if any '
            'rule set blocks by default). VLAN, traffic control, and web quarantine settings stay as they are.</p></div>')


def link_review(role, loc, names, content, changes, notes=None) -> str:
    tid = role["templateId"]
    label_html = " + ".join(esc(n) for n in names)
    lines = "".join(_diff_line(k, t) for k, t in changes) or "No firewall changes; only the description tags change."
    keep = "".join(f'<input type="hidden" name="rulesets" value="{esc(n)}">' for n in names)
    return (f'<div class="crumb"><a href="/roles">Role profiles</a> / <a href="/roles/{tid}?loc={esc(loc)}">'
            f'{esc(role["templateName"])}</a> / Link</div><h1>Link {esc(role["templateName"])} to {label_html}</h1>'
            '<p class="sub">This applies the latest published version of each rule set, in this order, and tags the role '
            'profile so later publishes update it too.</p>'
            f'<div class="card"><h2>Changes on CV-CUE</h2>{combine_notes(notes or [])}<div class="diff">{lines}</div>'
            f'<div class="diff">~ description: "{esc(role.get("description") or "")}" → '
            f'"{esc(R.set_tags(role.get("description"), names))}"</div>'
            f'<form method="post" action="/roles/{tid}/link" class="row" style="margin-top:12px">{CSRF}'
            f'<input type="hidden" name="loc" value="{esc(loc)}">{keep}'
            '<button class="primary">Link and apply</button>'
            f'<a class="btn" href="/roles/{tid}?loc={esc(loc)}">Cancel</a></form></div>')


def combine_notes(notes: list[str]) -> str:
    """Duplicates left out and rules that never apply, from combining rule sets."""
    if not notes:
        return ""
    items = "".join(f"<li>{esc(n)}</li>" for n in notes)
    return (f'<div class="flash pend" style="margin:8px 0 0"><b>Combining these rule sets</b>'
            f'<ul style="margin:6px 0 0;padding-left:18px">{items}</ul></div>')


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
    return ('<div class="row" style="justify-content:space-between"><h1>Firewall rule sets</h1>'
            '<a class="btn primary" href="/rulesets/new">New rule set</a></div><p class="sub">A rule set is an ordered list of firewall rules kept in this app. '
            'Publishing it writes the rules into every role profile linked to it.</p>' + table +
            f'<div class="card"><h2>New rule set</h2><form method="post" action="/rulesets" class="row" style="align-items:flex-end">{CSRF}'
            '<label>Name<input name="name" placeholder="guest-web" required pattern="[A-Za-z0-9_.\\-]{1,48}"></label>'
            '<label style="flex:1;min-width:200px">Description<input name="description" placeholder="Web access for guest devices"></label>'
            f'<label>Start from<select name="source"><option value="">Empty</option>{sources}</select></label>'
            '<button class="primary">Create</button></form></div>')


def ruleset_editor(rs, rows, edit_i, form_errors, role_draft=None) -> str:
    name = rs["name"]
    draft = rs["draft"]
    out = sum(1 for r in rows if r.status != "in_sync")
    status = ('<span class="pill pend">Draft · unpublished changes</span>' if rs["has_changes"] and rs["latest"]
              else '<span class="pill muted">Draft · never published</span>' if not rs["latest"]
              else f'<span class="pill ok">v{rs["latest"]} published</span>')
    used = ", ".join(role_link(r) for r in rows) or "No role profiles yet"
    review_cls = "primary" if rs["has_changes"] or out else ""
    head = (draft_banner(role_draft, bool(rs["latest"]) and not rs["has_changes"]) +
            f'<div class="crumb"><a href="/rulesets">Rule sets</a> / {esc(name)}</div>'
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
    issues = R.issues_in(draft)
    issue_html = ("<div class=\"flash pend\"><b>Check these rules</b><ul style=\"margin:6px 0 0;padding-left:18px\">"
                  + "".join(f"<li>{esc(t)}</li>" for t in issues) + "</ul></div>") if issues else ""
    table = (f'<div class="card"><div class="row" style="justify-content:space-between"><h2>Firewall rules (Layer 3-4)</h2>'
             '<span class="sub" style="margin:0">Evaluated top to bottom; the default rule applies last.</span></div>'
             f'{issue_html}{rules_table(draft, compare, True, name, edit_i)}'
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
    """Add/edit one rule, laid out like CV-CUE: the fields shown depend on the protocol.

    Any: name, IP/hostname, action, protocol. Other: plus protocol number [0-254].
    TCP/UDP: plus port [0-65535] and direction.
    """
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
    script = ('<script>(function(){var f=document.getElementById("ruleForm");if(!f)return;'
              'function sync(){var p=f.querySelector("select[name=protocol]").value;'
              'var k=p==="1"||p==="2"?"tcpudp":p==="other"?"other":"any";'
              'f.querySelectorAll("[data-show]").forEach(function(e){var on=e.dataset.show.split(" ").indexOf(k)>=0;'
              'e.hidden=!on;e.querySelectorAll("input,select").forEach(function(i){i.disabled=!on;});});'
              'f.querySelector("input[name=protocol_number]").required=k==="other";}'
              'f.querySelector("select[name=protocol]").addEventListener("change",sync);sync();})();</script>')
    return (f'<div class="card" id="rule-form"><h2>{title}</h2>' + (f'<ul class="errors">{errs}</ul>' if errs else "") +
            f'<form method="post" action="/rulesets/{esc(name)}/edit" id="ruleForm">{CSRF}'
            f'<input type="hidden" name="op" value="{op}">'
            + (f'<input type="hidden" name="i" value="{edit_i}">' if edit_i is not None else "") +
            '<div class="grid" style="grid-template-columns:repeat(3,minmax(0,1fr));align-items:start">'
            f'<label style="grid-area:1/1"><span>Rule name<span class="req">*</span></span><input name="name" value="{esc(v("name"))}" '
            'placeholder="Allow-HTTPS" required maxlength="64"></label>'
            f'<label style="grid-area:1/2">IP/Hostname<input name="host" value="{esc(v("host"))}" placeholder="*"></label>'
            f'<label data-show="tcpudp" style="grid-area:1/3">Port<span class="row" style="flex-wrap:nowrap"><input name="port" value="{esc(v("port"))}" '
            'placeholder="*" style="flex:1;min-width:0"><span class="sub" style="margin:0;white-space:nowrap">[0-65535]</span></span></label>'
            '<label style="grid-area:2/1">Action<select name="action">' + opt("action", "1", "Allow", "1") + opt("action", "2", "Block") + "</select></label>"
            '<label style="grid-area:2/2">Protocol<select name="protocol">' + opt("protocol", "1", "TCP", "1") + opt("protocol", "2", "UDP") +
            opt("protocol", "0", "Any") + opt("protocol", "other", "Other") + "</select></label>"
            '<label data-show="tcpudp" style="grid-area:2/3">Direction<select name="direction">' + opt("direction", "2", "Outgoing", "2") +
            opt("direction", "1", "Incoming") + opt("direction", "0", "Any") + "</select></label>"
            f'<label data-show="other" style="grid-area:2/3"><span>Protocol number<span class="req">*</span></span><span class="row" style="flex-wrap:nowrap">'
            f'<input name="protocol_number" value="{esc(v("protocol_number"))}" inputmode="numeric" placeholder="47" '
            'style="flex:1;min-width:0"><span class="sub" style="margin:0;white-space:nowrap">[0-254]</span></span></label>'
            '</div><div class="row" style="margin-top:14px">'
            f'<button class="primary">{"Save rule" if edit_i is not None else "Add rule"}</button>'
            + (f'<a class="btn" href="/rulesets/{esc(name)}">Cancel</a>' if edit_i is not None else "") +
            '</div></form><p class="sub" style="margin:10px 0 0">Changes go into the draft. Nothing reaches CV-CUE until you '
            'review and publish. Leave IP/Hostname or Port empty (or *) for any.</p></div>' + script)


def review(plan, draft=None) -> str:
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
        if item.blocked:
            body = f'<div class="tilde">{esc(item.blocked)}. Not updated.</div>'
        elif item.changes:
            body = "".join(_diff_line(k, t) for k, t in item.changes)
        else:
            body = '<div style="color:var(--muted)">Already matches. Not updated.</div>'
        others = [n for n in item.row.rulesets if n != name]
        combined = (f'<span class="sub" style="margin:0"> · combined with {", ".join(esc(n) for n in others)}</span>'
                    if others else "")
        blocks.append(f'<div style="margin-bottom:12px"><div>{role_link(item.row)} '
                      f'<span style="color:var(--muted)">· {esc(item.row.location)}</span> {status_pill(item.row)}{combined}</div>'
                      f'<div class="diff">{body}</div>{combine_notes(item.notes)}</div>')
    can = plan.new_version or upd
    button = (f'<form method="post" action="/rulesets/{esc(name)}/publish" class="row">{CSRF}'
              f'<input type="hidden" name="token" value="{esc(plan.token)}">'
              f'<button class="primary">{"Publish" if plan.new_version else "Apply"}'
              f'{f" to {len(upd)} role profile(s)" if upd else ""}</button>'
              f'<a class="btn" href="/rulesets/{esc(name)}">Back to editor</a></form>' if can else
              f'<a class="btn" href="/rulesets/{esc(name)}">Back to editor</a>')
    rules = rules_table(plan.target, plan.ruleset["published"])
    return (draft_banner(draft, False) +
            f'<div class="crumb"><a href="/rulesets">Rule sets</a> / <a href="/rulesets/{esc(name)}">{esc(name)}</a> / Review</div>'
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


def run(r, draft=None) -> str:
    kind = r["kind"]
    results = r["results"]
    has_set = r["ruleset"] not in ("", "-") and " + " not in r["ruleset"]
    done, fail = '<span class="pill ok">Done</span>', '<span class="pill bad">Failed</span>'

    def role_cell(x) -> str:
        name = esc(x["role_name"])
        if kind == "delete" and x["ok"]:
            return f'{name} <span class="tag">Deleted</span>'
        if not x["template_id"]:
            return name                      # never created, nothing to open
        return f'<a href="/roles/{x["template_id"]}?loc={esc(x["location_id"])}">{name}</a>'

    trs = "".join(f'<tr><td>{role_cell(x)}</td><td>{done if x["ok"] else fail}</td><td>{esc(x["message"])}</td></tr>'
                  for x in results)
    failed = any(not x["ok"] for x in results)
    if failed and kind == "publish":
        hint = ('<p class="sub">Failed role profiles weren\'t changed or didn\'t verify. Open the rule set\'s review page '
                'to retry; it only updates role profiles that are still out of sync.</p>')
    elif failed:
        hint = '<p class="sub">Check the role profile in CV-CUE before trying again.</p>'
    else:
        hint = ""
    single = results[0] if len(results) == 1 else None
    subject = single["role_name"] if single and kind != "publish" else r["ruleset"]
    buttons = ['<a class="btn primary" href="/roles">Back to role profiles</a>']
    if single and single["template_id"] and kind != "delete" and (single["ok"] or kind != "create"):
        buttons.append(f'<a class="btn" href="/roles/{single["template_id"]}?loc={esc(single["location_id"])}">'
                       f'Open {esc(single["role_name"])}</a>')
    if has_set and kind != "delete":
        buttons.append(f'<a class="btn" href="/rulesets/{esc(r["ruleset"])}">Open rule set {esc(r["ruleset"])}</a>')
    buttons.append('<a class="btn" href="/activity">All activity</a>')
    banner = draft_banner(draft, True) if draft and kind == "publish" and not failed else ""
    return (banner + f'<div class="crumb"><a href="/activity">Activity</a> / Run #{r["id"]}</div>'
            f'<h1>{esc(kind.capitalize())} · {esc(subject)}</h1>'
            f'<p class="sub">{esc(r["summary"])} · {ts(r["started_at"])} · {esc(r["started_by"])}</p>{hint}'
            '<div class="card tw"><table><tr><th>Role profile</th><th>Result</th><th>Details</th></tr>'
            + (trs or '<tr><td colspan="3">No role profiles needed an update.</td></tr>') + "</table></div>"
            + f'<div class="row">{"".join(buttons)}</div>')
