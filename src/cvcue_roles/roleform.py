"""Role profile form: validation and mapping of form fields onto a CV-CUE role profile body."""

from __future__ import annotations

import re
from typing import Any

from . import rules as R

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")
UNITS = {"0": "Kbps", "1": "Mbps"}
_MAX = {0: 1048576, 1: 1024}


def fields_from_role(role: dict) -> dict:
    """Form values for an existing role profile."""
    tags = R.tags_of(role)
    if not role.get("vlanEnabled"):
        mode = "ssid"
    elif not role.get("vlanId"):
        mode = "untagged"
    else:
        mode = "id"
    return {
        "name": role.get("templateName") or "",
        "description": R.set_tag(role.get("description"), None),
        "vlan_mode": mode,
        "vlan_id": str(role.get("vlanId") or "") if mode == "id" else "",
        "tc_enabled": "1" if role.get("perUserTrafficControlEnabled") else "",
        "down": str(role.get("trafficControlDownloadLimit") or ""),
        "down_unit": str(role.get("trafficControlDownloadLimitUnit") or 0),
        "up": str(role.get("trafficControlUploadLimit") or ""),
        "up_unit": str(role.get("trafficControlUploadLimitUnit") or 0),
        "ruleset": tags[0] if tags else "",
    }


def parse(form: dict, *, existing_names: set[str], published: set[str], current_ruleset: str = "",
          creating: bool, locations: dict | None = None) -> tuple[dict, list[str]]:
    """Validated values and a list of errors. `existing_names` excludes the role being edited."""
    f = {k: str(v).strip() for k, v in form.items() if k != "csrf"}
    errors: list[str] = []
    name = f.get("name", "")
    if not NAME_RE.match(name):
        errors.append("Enter a name of up to 64 letters, numbers, spaces, dots, dashes, or underscores.")
    elif name.lower() in existing_names:
        errors.append(f"A role profile named {name} already exists.")
    f["description"] = R.set_tag(f.get("description", ""), None)[:200]
    if f.get("vlan_mode") not in ("ssid", "untagged", "id"):
        f["vlan_mode"] = "ssid"
    if f["vlan_mode"] == "id":
        if not f.get("vlan_id", "").isdigit() or not 1 <= int(f["vlan_id"]) <= 4094:
            errors.append("Enter a VLAN ID from 1 to 4094.")
    if f.get("tc_enabled"):
        for key, label in (("down", "Download"), ("up", "Upload")):
            unit = 1 if f.get(f"{key}_unit") == "1" else 0
            value = f.get(key, "") or "0"
            if not value.isdigit() or int(value) > _MAX[unit]:
                errors.append(f"{label} limit must be a whole number up to {_MAX[unit]} {UNITS[str(unit)]}.")
    rs = f.get("ruleset", "")
    if rs and rs not in published and rs != current_ruleset:
        errors.append(f"Rule set {rs} has no published version.")
    if creating:
        loc = f.get("location", "")
        if not loc.lstrip("-").isdigit() or (locations is not None and int(loc) not in locations):
            errors.append("Pick a location.")
    return f, errors


def apply(body: dict, f: dict, *, creating: bool) -> dict:
    """Write validated form values onto a role profile body (in place) and return it."""
    body["templateName"] = f["name"]
    body["role"] = f["name"]
    body["description"] = R.set_tag(f["description"], f.get("ruleset") or None)
    mode = f["vlan_mode"]
    body["vlanEnabled"] = mode != "ssid"
    body["vlanId"] = int(f["vlan_id"]) if mode == "id" else 0
    on = bool(f.get("tc_enabled"))
    body["perUserTrafficControlEnabled"] = on
    for key, field, unit_field in (("down", "trafficControlDownloadLimit", "trafficControlDownloadLimitUnit"),
                                   ("up", "trafficControlUploadLimit", "trafficControlUploadLimitUnit")):
        body[field] = int(f.get(key) or 0) if on else 0
        body[unit_field] = (1 if f.get(f"{key}_unit") == "1" else 0) if on else 0
    if creating:
        body.pop("templateId", None)
        body["templateType"] = "ROLE_PROFILE"
        body["type"] = "roletemplate"
        body["createdAtLocationId"] = {"type": "locallocationid", "id": int(f["location"])}
        body["mnctemplate"] = False
        body["mncTemplateId"] = 0
    return body


def check(saved: dict, f: dict) -> list[str]:
    """Differences between what was saved and what the form asked for (empty when it matches)."""
    problems = []
    if saved.get("templateName") != f["name"]:
        problems.append("name")
    if (saved.get("description") or "") != R.set_tag(f["description"], f.get("ruleset") or None):
        problems.append("description")
    want_enabled = f["vlan_mode"] != "ssid"
    if bool(saved.get("vlanEnabled")) != want_enabled or (
            f["vlan_mode"] == "id" and saved.get("vlanId") != int(f["vlan_id"])):
        problems.append("VLAN")
    if bool(saved.get("perUserTrafficControlEnabled")) != bool(f.get("tc_enabled")):
        problems.append("traffic control")
    return problems


def summary(f: dict) -> list[tuple[str, Any]]:
    vlan = {"ssid": "Use the SSID's VLAN", "untagged": "Untagged"}.get(f["vlan_mode"], f"VLAN {f.get('vlan_id')}")
    tc = "Off"
    if f.get("tc_enabled"):
        tc = (f"Download {f.get('down') or 0} {UNITS[f.get('down_unit') or '0']}, "
              f"upload {f.get('up') or 0} {UNITS[f.get('up_unit') or '0']}")
    return [("Name", f["name"]), ("Description", f["description"] or "None"), ("VLAN", vlan),
            ("Per-user traffic control", tc), ("Firewall rule set", f.get("ruleset") or "None")]
