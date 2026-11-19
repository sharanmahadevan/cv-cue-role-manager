"""
In-memory stand-in for CV-CUE (CVCUE_MOCK=true), for local development and demos.

It serves only what the app uses: the role profile list, single role profiles, PUT of a
role profile, and the location tree. Seed data mirrors a small home lab.
"""

from __future__ import annotations

import copy
import itertools
from typing import Any

from . import rules as R
from .client import CvcueError

_oid = itertools.count(100)


def _rule(name: str, direction: int, protocol: int, port: str, action: int) -> dict:
    return R.new_rule(name, direction, protocol, port, "", action)


BASIC_WEB_V1 = {"rules": [_rule("Allow-DNS", 2, 2, "53", 1), _rule("Allow-DHCP", 2, 2, "67", 1),
                          _rule("Allow-HTTP", 2, 1, "80", 1), _rule("Allow-HTTPS", 2, 1, "443", 1)],
                "default_action": 2}
BASIC_WEB_DRAFT = {"rules": BASIC_WEB_V1["rules"] + [_rule("Allow-8443", 2, 1, "8443", 1)], "default_action": 2}
IOT_V1 = {"rules": [_rule("Allow-DNS", 2, 2, "53", 1), _rule("Allow-MQTT-TLS", 2, 1, "8883", 1)],
          "default_action": 2}


def _role(tid: int, name: str, description: str, vlan: int, content: dict | None) -> dict:
    profile = []
    if content is not None:
        for entry in R.to_firewall_profile(content):
            entry = {**entry, "oid": next(_oid), "mncOid": 0, "ssid": tid}
            if not entry["defaultRule"]:
                entry["orderId"] += 1   # CV-CUE stores created rules 1-based
            profile.append(entry)
    return {
        "type": "roletemplate", "templateId": tid, "templateName": name,
        "createdAtLocationId": {"type": "locallocationid", "id": 3}, "description": description,
        "templateType": "ROLE_PROFILE", "mncTemplateId": 0, "role": name, "inheritFromSSID": False,
        "vlanEnabled": True, "vlanId": vlan, "vlanName": None, "firewallEnabled": content is not None,
        "applicationFirewallEnabled": False, "firewallProfile": profile, "applicationFirewallRules": None,
        "perUserTrafficControlEnabled": False, "trafficControlDownloadLimit": 0, "trafficControlDownloadLimitUnit": 0,
        "trafficControlUploadLimitUnit": 0, "trafficControlUploadLimit": 0, "vlanPoolingEnabled": False,
        "vlanPool": None, "mnctemplate": False,
        "redirection": {"redirectUrl": "", "exemptedWebHostList": [], "dynamicRedirectionEnabled": False,
                        "webQuarantineOption": 1, "webQuarantineEnabled": False},
    }


def seed_roles() -> dict[int, dict]:
    iot_drifted = copy.deepcopy(IOT_V1)
    iot_drifted["rules"].append(_rule("Allow-Any-TCP", 2, 1, "", 1))   # someone edited it in CV-CUE
    return {r["templateId"]: r for r in [
        _role(5, "Onboarding-Role", "", 999, None),
        _role(7, "Test", "ruleset:iot-lockdown", 0, iot_drifted),
        _role(8, "Demo-Sync-A", "ruleset:basic-web", 0, BASIC_WEB_V1),
        _role(9, "Demo-Sync-B", "Demo B ruleset:basic-web", 20, BASIC_WEB_V1),
        _role(10, "Guest", "Guest access", 30, None),
    ]}


def seed_store(store: Any) -> None:
    """Rule sets matching the seeded roles: basic-web v1 published with an unpublished draft."""
    if store.list_rulesets():
        return
    store.create_ruleset("basic-web", "Web browsing for staff devices", BASIC_WEB_V1, "seed")
    store.add_version("basic-web", BASIC_WEB_V1, "seed")
    store.save_draft("basic-web", BASIC_WEB_DRAFT, "seed")
    store.create_ruleset("iot-lockdown", "IoT devices: DNS and MQTT over TLS only", IOT_V1, "seed")
    store.add_version("iot-lockdown", IOT_V1, "seed")


class MockCvcue:
    base_url = "mock://cv-cue"

    def __init__(self) -> None:
        self.roles = seed_roles()
        self.puts: list[dict] = []

    async def aclose(self) -> None:
        return None

    async def get(self, path: str, params: dict | None = None, **_: Any) -> Any:
        if path == "/deviceconfiguration/roleprofiles":
            return copy.deepcopy(list(self.roles.values()))
        if path.startswith("/deviceconfiguration/roleprofiles/"):
            tid = int(path.rsplit("/", 1)[1])
            if tid not in self.roles:
                raise CvcueError(404, "GET", path, "not found")
            return copy.deepcopy(self.roles[tid])
        if path == "/locations/tree":
            return {"rootLocationId": {"type": "locallocationid", "id": 0}, "locations": {
                '{"type":"locallocationid","id":0}': {"name": "Arista Cognitive WiFi", "parentId": None},
                '{"type":"locallocationid","id":3}': {"name": "Sharan's Home",
                                                      "parentId": {"type": "locallocationid", "id": 0}},
            }}
        raise CvcueError(404, "GET", path, "mock does not serve this path")

    async def put(self, path: str, params: dict | None = None, json: Any = None, **_: Any) -> Any:
        if path != "/deviceconfiguration/roleprofiles" or not isinstance(json, dict):
            raise CvcueError(400, "PUT", path, "mock only accepts role profile updates")
        tid = json.get("templateId")
        if tid not in self.roles:
            raise CvcueError(404, "PUT", path, "role profile not found")
        body = copy.deepcopy(json)
        body["firewallProfile"] = [{**e, "oid": next(_oid), "mncOid": 0, "ssid": tid}
                                   for e in body.get("firewallProfile") or []]
        self.roles[tid] = body
        self.puts.append(body)
        return copy.deepcopy(body)
