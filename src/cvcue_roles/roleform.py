"""
Role profile form: validation and mapping of form fields onto a CV-CUE role profile body.

Mirrors the CV-CUE role editor: Role Name and Profile Name, "Use SSID settings in absence of
role-specific settings", VLAN (ID, name, or pool), Layer 3-4 firewall (here: a rule set instead of
individual rules), and per-user upload/download limits. Application firewall rules and redirection
are left exactly as they are in CV-CUE.
"""

from __future__ import annotations

import re
from typing import Any

from . import rules as R

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")
VLAN_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
POOL_RE = re.compile(r"^\d{1,4}(-\d{1,4})?(,\d{1,4}(-\d{1,4})?)*$")
UNITS = {"0": "Kbps", "1": "Mbps"}
MAX_LIMIT = {"0": 1048576, "1": 1024}
NEW_RULESET = "__new__"


def fields_from_role(role: dict) -> dict:
    """Form values for an existing role profile."""
    tags = R.tags_of(role)
    if role.get("vlanPoolingEnabled"):
        vtype = "pool"
    elif role.get("vlanName"):
        vtype = "name"
    else:
        vtype = "id"
    tc = bool(role.get("perUserTrafficControlEnabled"))
    up = role.get("trafficControlUploadLimit") or 0
    down = role.get("trafficControlDownloadLimit") or 0
    return {
        "role_name": role.get("role") or role.get("templateName") or "",
        "profile_name": role.get("templateName") or "",
        "description": R.set_tag(role.get("description"), None),
        "inherit": "1" if role.get("inheritFromSSID") else "",
        "vlan_on": "1" if role.get("vlanEnabled") else "",
        "vlan_type": vtype,
        "vlan_id": str(role.get("vlanId") or 0),
        "vlan_name": role.get("vlanName") or "",
        "vlan_pool": role.get("vlanPool") or "",
        "fw_on": "1" if role.get("firewallEnabled") else "",
        "ruleset": tags[0] if tags else "",
        "up_on": "1" if tc and up else "",
        "up": str(up or ""),
        "up_unit": str(role.get("trafficControlUploadLimitUnit") if up else 1),
        "down_on": "1" if tc and down else "",
        "down": str(down or ""),
        "down_unit": str(role.get("trafficControlDownloadLimitUnit") if down else 1),
    }


def new_fields(location: str = "") -> dict:
    return {"vlan_on": "1", "vlan_type": "id", "vlan_id": "0", "fw_on": "1", "up_unit": "1", "down_unit": "1",
            "location": location}


def _pool_ok(pool: str) -> bool:
    if not POOL_RE.match(pool):
        return False
    for part in pool.split(","):
        nums = [int(x) for x in part.split("-")]
        if any(not 1 <= n <= 4094 for n in nums) or (len(nums) == 2 and nums[0] > nums[1]):
            return False
    return True


def parse(form: dict, *, existing_names: set[str], published: set[str], current_ruleset: str = "",
          creating: bool, locations: dict | None = None, keep_allowed: bool = False) -> tuple[dict, list[str]]:
    """Validated values and a list of errors. `existing_names` (lower case) excludes the role being edited."""
    f = {k: str(v).strip() for k, v in form.items() if k != "csrf"}
    errors: list[str] = []
    for key, label in (("role_name", "Role name"), ("profile_name", "Profile name")):
        if not NAME_RE.match(f.get(key, "")):
            errors.append(f"Enter a {label.lower()} of up to 64 letters, numbers, spaces, dots, dashes, "
                          "or underscores.")
    if f.get("profile_name", "").lower() in existing_names:
        errors.append(f"A role profile named {f['profile_name']} already exists.")
    f["name"] = f.get("profile_name", "")
    f["description"] = R.set_tag(f.get("description", ""), None)[:200]

    if f.get("vlan_on"):
        vtype = f.get("vlan_type") if f.get("vlan_type") in ("id", "name", "pool") else "id"
        f["vlan_type"] = vtype
        if vtype == "id" and (not f.get("vlan_id", "").isdigit() or int(f["vlan_id"]) > 4094):
            errors.append("Enter a VLAN ID from 0 to 4094 (0 = untagged).")
        if vtype == "name" and not VLAN_NAME_RE.match(f.get("vlan_name", "")):
            errors.append("Enter a VLAN name of up to 32 letters, numbers, dots, dashes, or underscores.")
        if vtype == "pool" and not _pool_ok(f.get("vlan_pool", "").replace(" ", "")):
            errors.append("Enter a VLAN pool like 1,2,6-23 (VLANs 1 to 4094).")
        f["vlan_pool"] = f.get("vlan_pool", "").replace(" ", "")

    for key, label in (("up", "Upload"), ("down", "Download")):
        if f.get(f"{key}_on"):
            unit = "1" if f.get(f"{key}_unit", "1") == "1" else "0"
            f[f"{key}_unit"] = unit
            value = f.get(key, "")
            if not value.isdigit() or not 1 <= int(value) <= MAX_LIMIT[unit]:
                errors.append(f"{label} limit must be from 1 to {MAX_LIMIT[unit]} {UNITS[unit]}.")

    rs = f.get("ruleset", "")
    if not f.get("fw_on"):
        f["ruleset"] = ""
    elif rs == NEW_RULESET:
        pass                                   # handled by the caller: go create one
    elif not rs and not keep_allowed:
        errors.append("Pick a firewall rule set, create a new one, or turn off Layer 3-4 firewall rules.")
    elif rs and rs not in published and rs != current_ruleset:
        errors.append(f"Rule set {rs} has no published version yet. Publish it first.")
    if creating:
        loc = f.get("location", "")
        if not loc.lstrip("-").isdigit() or (locations is not None and int(loc) not in locations):
            errors.append("Pick a location.")
    return f, errors


def apply(body: dict, f: dict, *, creating: bool) -> dict:
    """Write validated form values onto a role profile body (in place) and return it.

    Firewall rules themselves are applied by the caller from the chosen rule set.
    """
    body["templateName"] = f["profile_name"]
    body["role"] = f["role_name"]
    body["description"] = R.set_tag(f["description"], f.get("ruleset") or None)
    body["inheritFromSSID"] = bool(f.get("inherit"))

    on = bool(f.get("vlan_on"))
    body["vlanEnabled"] = on
    if on:
        vtype = f.get("vlan_type", "id")
        body["vlanPoolingEnabled"] = vtype == "pool"
        body["vlanPool"] = f["vlan_pool"] if vtype == "pool" else None
        body["vlanName"] = f["vlan_name"] if vtype == "name" else None
        if vtype == "id":
            body["vlanId"] = int(f["vlan_id"])
        elif vtype == "pool":
            body["vlanId"] = int(re.split(r"[-,]", f["vlan_pool"])[0])
        else:
            body["vlanId"] = 0
    else:
        body["vlanPoolingEnabled"], body["vlanPool"], body["vlanName"], body["vlanId"] = False, None, None, 0

    if not f.get("fw_on"):
        body["firewallEnabled"] = False

    up_on, down_on = bool(f.get("up_on")), bool(f.get("down_on"))
    body["perUserTrafficControlEnabled"] = up_on or down_on
    body["trafficControlUploadLimit"] = int(f["up"]) if up_on else 0
    body["trafficControlUploadLimitUnit"] = int(f.get("up_unit") or 1) if up_on else 0
    body["trafficControlDownloadLimit"] = int(f["down"]) if down_on else 0
    body["trafficControlDownloadLimitUnit"] = int(f.get("down_unit") or 1) if down_on else 0

    if creating:
        body.pop("templateId", None)
        body["templateType"] = "ROLE_PROFILE"
        body["type"] = "roletemplate"
        body["createdAtLocationId"] = {"type": "locallocationid", "id": int(f["location"])}
        body["mnctemplate"] = False
        body["mncTemplateId"] = 0
    return body


def check(saved: dict, f: dict) -> list[str]:
    """Settings that read back differently from what the form asked for (empty when it matches)."""
    want = apply({}, f, creating=False)
    problems = []
    labels = {"templateName": "profile name", "role": "role name", "description": "description",
              "inheritFromSSID": "SSID fallback", "vlanEnabled": "VLAN", "vlanId": "VLAN ID",
              "vlanName": "VLAN name", "vlanPool": "VLAN pool", "vlanPoolingEnabled": "VLAN pool",
              "perUserTrafficControlEnabled": "bandwidth control", "trafficControlUploadLimit": "upload limit",
              "trafficControlDownloadLimit": "download limit"}
    for key, label in labels.items():
        if key not in want:
            continue
        a, b = want[key], saved.get(key)
        if key in ("vlanName", "vlanPool") and not a and not b:
            continue
        if key in ("vlanId", "vlanName", "vlanPool", "vlanPoolingEnabled") and not want["vlanEnabled"]:
            continue
        if (a or None) != (b or None) and a != b and label not in problems:
            problems.append(label)
    if not f.get("fw_on") and saved.get("firewallEnabled"):
        problems.append("firewall still on")
    return problems


def _limit(f: dict, key: str) -> str:
    return f"{f.get(key)} {UNITS[f.get(key + '_unit') or '1']}" if f.get(f"{key}_on") else "No limit"


def summary(f: dict) -> list[tuple[str, Any]]:
    if not f.get("vlan_on"):
        vlan = "Not set (SSID's VLAN)"
    else:
        vlan = {"name": f"Name {f.get('vlan_name')}", "pool": f"Pool {f.get('vlan_pool')}"}.get(
            f.get("vlan_type"), "Untagged" if f.get("vlan_id") in ("", "0") else f"ID {f.get('vlan_id')}")
    return [("Role name", f["role_name"]), ("Profile name", f["profile_name"]), ("VLAN", vlan),
            ("Firewall rule set", f.get("ruleset") or ("Off" if not f.get("fw_on") else "Keep current rules")),
            ("Upload", _limit(f, "up")), ("Download", _limit(f, "down"))]
