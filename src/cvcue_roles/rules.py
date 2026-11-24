"""
Firewall rule model and conversion to/from CV-CUE role profile `firewallProfile` entries.

A rule set's content is {"rules": [rule, ...], "default_action": 1|2}, where each rule is
{"name", "direction", "protocol", "port", "host", "action", "mark", "dscp"} using CV-CUE's codes:

  direction: 0 any, 1 in, 2 out
  protocol:  0 any, 1 TCP, 2 UDP, any other IP protocol number N is stored as N + 3
  action:    1 allow, 2 block

Rule order is evaluation order. CV-CUE renumbers `orderId` on create (0-based in, 1-based out)
but keeps it as sent on update, so comparisons use the relative order only.
"""

from __future__ import annotations

import difflib
import json
import re
from typing import Any

DIRECTIONS = {0: "Any", 1: "In", 2: "Out"}
ACTIONS = {1: "Allow", 2: "Block"}
MARK_DEFAULT = "TO_WIRELESS"
TAG_RE = re.compile(r"\bruleset:([A-Za-z0-9_.-]+)")
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,48}$")
_PORT_RE = re.compile(r"^\d{1,5}(-\d{1,5})?$")
_HOST_RE = re.compile(r"^[A-Za-z0-9.:/_-]{1,253}$")


def protocol_label(p: int) -> str:
    return {0: "Any", 1: "TCP", 2: "UDP"}.get(p, f"IP {p - 3}")


def empty_content() -> dict:
    return {"rules": [], "default_action": 2}


def new_rule(name: str = "", direction: int = 2, protocol: int = 1, port: str = "", host: str = "",
             action: int = 1) -> dict:
    return {"name": name, "direction": direction, "protocol": protocol, "port": port, "host": host,
            "action": action, "mark": MARK_DEFAULT, "dscp": 0}


def _norm_rule(r: dict) -> dict:
    return {
        "name": str(r.get("name") or ""),
        "direction": int(r.get("direction") or 0),
        "protocol": int(r.get("protocol") or 0),
        "port": "" if r.get("port") is None else str(r.get("port")),
        "host": str(r.get("host") or ""),
        "action": int(r.get("action") or 1),
        "mark": str(r.get("mark") or MARK_DEFAULT),
        "dscp": int(r.get("dscp") or 0),
    }


def normalize(content: dict | None) -> dict:
    content = content or empty_content()
    return {"rules": [_norm_rule(r) for r in content.get("rules") or []],
            "default_action": int(content.get("default_action") or 2)}


def fingerprint(content: dict | None) -> str:
    """Stable string used to compare two rule sets."""
    return json.dumps(normalize(content), sort_keys=True, separators=(",", ":"))


# ------------------------------------------------------------ CV-CUE mapping
def from_role(role: dict) -> dict | None:
    """Rule set content currently configured on a role profile, or None if its firewall is off."""
    if not role.get("firewallEnabled"):
        return None
    profile = role.get("firewallProfile") or []
    default = next((x for x in profile if x.get("defaultRule")), None)
    ordered = sorted((x for x in profile if not x.get("defaultRule")), key=lambda x: x.get("orderId") or 0)
    return normalize({
        "rules": [{"name": x.get("name"), "direction": x.get("direction"), "protocol": x.get("protocol"),
                   "port": x.get("port"), "host": x.get("hostName"), "action": x.get("action"),
                   "mark": x.get("markDirection"), "dscp": x.get("dscpValue")} for x in ordered],
        "default_action": (default or {}).get("action") or 2,
    })


def to_firewall_profile(content: dict) -> list[dict]:
    """The `firewallProfile` list to send in a role profile PUT/POST."""
    c = normalize(content)
    out = [{"name": r["name"], "orderId": i, "direction": r["direction"], "protocol": r["protocol"],
            "port": r["port"], "hostName": r["host"], "action": r["action"], "markDirection": r["mark"],
            "dscpValue": r["dscp"], "defaultRule": False} for i, r in enumerate(c["rules"])]
    out.append({"name": "", "orderId": -1, "direction": 0, "protocol": 0, "port": "", "hostName": "",
                "action": c["default_action"], "markDirection": MARK_DEFAULT, "dscpValue": 0, "defaultRule": True})
    return out


def apply_to_role(role: dict, content: dict) -> dict:
    """Copy of a role profile with its firewall replaced by `content`; every other setting kept."""
    body = json.loads(json.dumps(role))
    body["firewallEnabled"] = True
    body["firewallProfile"] = to_firewall_profile(content)
    return body


# ------------------------------------------------------------ tags
def tags_of(role: dict) -> list[str]:
    """Linked rule set names, in the order they're applied (duplicates dropped)."""
    out: list[str] = []
    for name in TAG_RE.findall(role.get("description") or ""):
        if name not in out:
            out.append(name)
    return out


def set_tags(description: str | None, names: list[str] | None) -> str:
    """Description with its ruleset tags replaced by `names`, in order (all removed when empty)."""
    text = TAG_RE.sub("", description or "").strip()
    text = re.sub(r"\s{2,}", " ", text)
    for name in names or []:
        text = f"{text} ruleset:{name}".strip()
    return text


def set_tag(description: str | None, name: str | None) -> str:
    """Description linked to a single rule set (or none)."""
    return set_tags(description, [name] if name else [])


def match_key(r: dict) -> tuple:
    """The traffic a rule matches: (direction, protocol, port, host). Empty/0 means any."""
    r = _norm_rule(r)
    return (r["direction"], r["protocol"], r["port"], r["host"].lower())


def _port_range(port: str) -> tuple[int, int] | None:
    if not port:
        return None
    lo, _, hi = port.partition("-")
    return int(lo), int(hi or lo)


def covers(a: dict, b: dict) -> bool:
    """True if rule `a` matches all the traffic rule `b` matches (so `b` after `a` can never match first).

    A field set to Any in `a` covers every value; a port range covers the ports inside it.
    """
    (ad, ap, aport, ah), (bd, bp, bport, bh) = match_key(a), match_key(b)
    if ad and ad != bd:
        return False
    if ap and ap != bp:
        return False
    if aport:
        ar, br = _port_range(aport), _port_range(bport)
        if br is None or not (ar[0] <= br[0] and br[1] <= ar[1]):
            return False
    if ah and ah != bh:
        return False
    return True


def _effect(r: dict) -> tuple:
    r = _norm_rule(r)
    return (r["action"], r["mark"], r["dscp"])


def combine(named: list[tuple[str, dict]]) -> tuple[dict, list[dict], list[dict]]:
    """Combine rule sets in order: their rules one after another, then one default rule.

    Returns (content, skipped, conflicts), comparing each rule with the rules kept from earlier
    rule sets (the first match wins in CV-CUE):
    - skipped: an earlier rule set already has a rule covering all of this rule's traffic with the
      same action. This rule would never apply and removing it changes nothing, so it's left out.
    - conflicts: an earlier rule set has a rule covering this rule's traffic with a different action
      (or DSCP marking). It's kept, but never applies, because the earlier rule matches first.
    Rules inside one rule set are kept as written (see `issues_in`).
    The default rule blocks if any of the rule sets blocks by default, so adding a rule set never
    opens up traffic that another one denies.
    """
    if not named:
        return empty_content(), [], []
    kept: list[tuple[dict, str]] = []
    skipped: list[dict] = []
    conflicts: list[dict] = []
    defaults = []
    for set_name, content in named:
        c = normalize(content)
        defaults.append(c["default_action"])
        for r in c["rules"]:
            earlier = next(((e, es) for e, es in kept if es != set_name and covers(e, r)), None)
            if earlier:
                note = {"rule": r, "set": set_name, "by": earlier[0], "by_set": earlier[1],
                        "exact": match_key(earlier[0]) == match_key(r)}
                if _effect(earlier[0]) == _effect(r):
                    skipped.append(note)
                    continue
                conflicts.append(note)          # different action or marking: kept, but never applies
            kept.append((r, set_name))
    return {"rules": [r for r, _ in kept], "default_action": 2 if 2 in defaults else 1}, skipped, conflicts


def compose(contents: list[dict]) -> dict:
    """Combined content only (see `combine`); rule sets are told apart by position."""
    return combine([(f"#{i}", c) for i, c in enumerate(contents)])[0]


def note_text(note: dict, kind: str) -> str:
    r, by = _norm_rule(note["rule"]), _norm_rule(note["by"])
    how = "the same traffic" if note.get("exact", True) else "all of its traffic"
    if kind == "skipped":
        return (f'{r["name"]} in {note["set"]} left out: {by["name"]} in {note["by_set"]} already matches '
                f'{how} with the same action')
    return (f'{r["name"]} in {note["set"]} never applies: {by["name"]} in {note["by_set"]} matches '
            f'{how} first ({ACTIONS[by["action"]].lower()})')


def issues_in(content: dict) -> list[str]:
    """Rules inside one rule set that can never apply because an earlier rule covers them."""
    out = []
    rules = normalize(content)["rules"]
    for i, r in enumerate(rules):
        j = next((j for j in range(i) if covers(rules[j], r)), None)
        if j is None:
            continue
        earlier = rules[j]
        same = match_key(earlier) == match_key(r)
        if _effect(earlier) == _effect(r):
            what = "duplicates" if same else "is already covered by"
            out.append(f'Rule {i + 1} ({r["name"]}) {what} rule {j + 1} ({earlier["name"]}).')
        else:
            how = "the same traffic" if same else "all of its traffic"
            out.append(f'Rule {i + 1} ({r["name"]}) never applies: rule {j + 1} ({earlier["name"]}) matches '
                       f'{how} first.')
    return out


# ------------------------------------------------------------ display and diff
def describe(r: dict) -> str:
    r = _norm_rule(r)
    parts = [r["name"] or "(unnamed)", DIRECTIONS.get(r["direction"], "?").lower(),
             protocol_label(r["protocol"]).lower(), f"port {r['port'] or 'any'}",
             f"host {r['host'] or 'any'}", "→ " + ACTIONS.get(r["action"], "?").lower()]
    if r["mark"] != MARK_DEFAULT or r["dscp"]:
        parts.append(f"(dscp {r['dscp']} {r['mark'].lower()})")
    return " ".join(parts)


def diff(have: dict | None, want: dict) -> list[tuple[str, str]]:
    """Ordered list of ("+"/"-"/"~", text) changes needed to turn `have` into `want`."""
    out: list[tuple[str, str]] = []
    if have is None:
        out.append(("~", "firewall: off → on"))
        have_rules, have_default = [], None
    else:
        h = normalize(have)
        have_rules, have_default = h["rules"], h["default_action"]
    w = normalize(want)
    a = [describe(r) for r in have_rules]
    b = [describe(r) for r in w["rules"]]
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(a=a, b=b, autojunk=False).get_opcodes():
        if op == "equal":
            continue
        out += [("-", f"#{i + 1} {a[i]}") for i in range(i1, i2)]
        out += [("+", f"#{j + 1} {b[j]}") for j in range(j1, j2)]
    if have_default != w["default_action"]:
        old = ACTIONS.get(have_default, "none").lower() if have_default else "none"
        out.append(("~", f"default rule: {old} → {ACTIONS[w['default_action']].lower()}"))
    return out


# ------------------------------------------------------------ form validation
def rule_from_form(form: dict) -> tuple[dict | None, list[str]]:
    """Validate one rule from the editor form, following CV-CUE's rule editor:

    - Any: name, IP/hostname, action. Port and direction don't apply (saved as any).
    - Other: as Any, plus a required IP protocol number 0-254.
    - TCP/UDP: as Any, plus port (0-65535 or a range) and direction.
    A blank or "*" IP/hostname or port means any.
    """
    errors: list[str] = []
    name = str(form.get("name", "")).strip()
    if not name:
        errors.append("Enter a rule name.")
    elif len(name) > 64:
        errors.append("Rule name must be 64 characters or fewer.")
    proto_choice = str(form.get("protocol", "1"))
    direction, port = 0, ""
    if proto_choice == "other":
        raw = str(form.get("protocol_number", "")).strip()
        if raw.isdigit() and 0 <= int(raw) <= 254:
            protocol = int(raw) + 3
        else:
            errors.append("Enter a protocol number from 0 to 254.")
            protocol = 0
    elif proto_choice in ("0", "1", "2"):
        protocol = int(proto_choice)
    else:
        errors.append("Pick a protocol.")
        protocol = 0
    if protocol in (1, 2) and proto_choice != "other":
        try:
            direction = int(form.get("direction", 2))
            assert direction in DIRECTIONS
        except (ValueError, AssertionError):
            errors.append("Pick a direction.")
            direction = 2
        port = str(form.get("port", "")).strip()
        if port == "*":
            port = ""
        if port and (not _PORT_RE.match(port) or any(not 0 <= int(p) <= 65535 for p in port.split("-"))):
            errors.append("Enter a port from 0 to 65535, or a range like 8000-8100.")
    host = str(form.get("host", "")).strip()
    if host == "*":
        host = ""
    if host and not _HOST_RE.match(host):
        errors.append("Enter a hostname, IP address, or subnet like 10.0.0.0/8.")
    try:
        action = int(form.get("action", 1))
        assert action in ACTIONS
    except (ValueError, AssertionError):
        errors.append("Pick allow or block.")
        action = 1
    if errors:
        return None, errors
    return new_rule(name, direction, protocol, port, host, action), []


def content_from_import(data: Any) -> dict:
    """Accept a rule set file exported by this app or written for sync.py."""
    if isinstance(data, dict) and "rules" in data:
        return normalize(data)
    if isinstance(data, dict) and "firewallProfile" in data:
        return from_role({"firewallEnabled": True, "firewallProfile": data["firewallProfile"]}) or empty_content()
    raise ValueError("Expected a rule set with 'rules' or 'firewallProfile'.")
