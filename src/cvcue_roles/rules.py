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
    return TAG_RE.findall(role.get("description") or "")


def set_tag(description: str | None, name: str | None) -> str:
    """Description with its ruleset tag replaced (or removed when name is None)."""
    text = TAG_RE.sub("", description or "").strip()
    text = re.sub(r"\s{2,}", " ", text)
    if name:
        text = f"{text} ruleset:{name}".strip()
    return text


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
    errors: list[str] = []
    name = str(form.get("name", "")).strip()
    if not name:
        errors.append("Enter a rule name.")
    elif len(name) > 64:
        errors.append("Rule name must be 64 characters or fewer.")
    try:
        direction = int(form.get("direction", 2))
        assert direction in DIRECTIONS
    except (ValueError, AssertionError):
        errors.append("Pick a direction.")
        direction = 2
    proto_choice = str(form.get("protocol", "1"))
    if proto_choice == "other":
        try:
            num = int(str(form.get("protocol_number", "")).strip())
            assert 0 <= num <= 255
            protocol = num + 3
        except (ValueError, AssertionError):
            errors.append("Enter an IP protocol number from 0 to 255.")
            protocol = 0
    else:
        try:
            protocol = int(proto_choice)
            assert protocol in (0, 1, 2)
        except (ValueError, AssertionError):
            errors.append("Pick a protocol.")
            protocol = 0
    port = str(form.get("port", "")).strip()
    if port:
        if protocol not in (1, 2):
            errors.append("Ports apply to TCP or UDP rules only.")
        elif not _PORT_RE.match(port) or any(not 0 < int(p) < 65536 for p in port.split("-")):
            errors.append("Enter a port from 1 to 65535, or a range like 8000-8100.")
    host = str(form.get("host", "")).strip()
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
