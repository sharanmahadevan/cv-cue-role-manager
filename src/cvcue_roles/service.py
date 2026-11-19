"""
Business logic: role profile status, publish plans, and the writes to CV-CUE.

A role profile is linked to a rule set by the tag `ruleset:<name>` in its CV-CUE description.
The tag lives in CV-CUE (not in this app's database) so the link is visible in the CV-CUE UI
and survives a lost database. Rule sets and their published versions live in SQLite.

Every write follows the same pattern: GET the current role, change only the firewall (and,
for link/unlink, the description), PUT the whole role back, then GET it again and check.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from . import roleform as F
from . import rules as R
from .store import Store

log = logging.getLogger(__name__)

ROLES_PATH = "/deviceconfiguration/roleprofiles"


class Api(Protocol):
    async def get(self, path: str, **kw: Any) -> Any: ...
    async def put(self, path: str, **kw: Any) -> Any: ...
    async def post(self, path: str, **kw: Any) -> Any: ...
    async def delete(self, path: str, **kw: Any) -> Any: ...


class StalePlan(Exception):
    """The rule set or role profiles changed after the review page was shown."""


# Status of one role profile
IN_SYNC, BEHIND, DRIFTED, NOT_PUBLISHED, UNKNOWN_SET, MULTI_TAG, UNMANAGED = (
    "in_sync", "behind", "drifted", "not_published", "unknown_ruleset", "multiple_tags", "unmanaged")


@dataclass
class RoleRow:
    role: dict
    location: str
    ruleset: str | None
    status: str
    version: int | None = None   # matching published version (in_sync / behind)

    @property
    def template_id(self) -> int:
        return self.role["templateId"]

    @property
    def location_id(self) -> Any:
        return (self.role.get("createdAtLocationId") or {}).get("id")


@dataclass
class PlanItem:
    row: RoleRow
    changes: list[tuple[str, str]]


@dataclass
class Plan:
    ruleset: dict
    target: dict
    new_version: bool
    items: list[PlanItem] = field(default_factory=list)
    token: str = ""

    @property
    def to_update(self) -> list[PlanItem]:
        return [i for i in self.items if i.changes]


def _loc_id(value: Any) -> Any:
    if isinstance(value, dict) and "id" in value:
        return value["id"]
    if isinstance(value, str) and value.startswith("{"):
        try:
            return _loc_id(json.loads(value))
        except ValueError:
            return value
    return value


class Portal:
    def __init__(self, api: Api, store: Store, root_location: int = 0) -> None:
        self.api = api
        self.store = store
        self.root = root_location
        self._loc_cache: tuple[float, dict] = (0.0, {})
        self.location_types: dict = {}
        self._write_lock = asyncio.Lock()   # one publish at a time

    async def _db(self, fn, *args):
        return await asyncio.to_thread(fn, *args)

    # ------------------------------------------------------------ reads
    async def locations(self) -> dict:
        ts, cache = self._loc_cache
        if cache and time.time() - ts < 300:
            return cache
        try:
            tree = await self.api.get("/locations/tree")
        except Exception as exc:  # noqa: BLE001 - names are cosmetic
            log.warning("Could not load locations: %s", exc)
            return cache
        raw = {_loc_id(k): v for k, v in ((tree or {}).get("locations") or {}).items()}
        names = {k: v.get("name", "") for k, v in raw.items()}
        parents = {k: _loc_id(v.get("parentId")) for k, v in raw.items()}
        self.location_types = {k: v.get("type") for k, v in raw.items()}
        paths = {}
        for lid in raw:
            parts, cur, seen = [], lid, set()
            while cur is not None and cur in names and cur not in seen:
                seen.add(cur)
                parts.append(names[cur])
                cur = parents.get(cur)
            paths[lid] = " / ".join(reversed(parts))
        self._loc_cache = (time.time(), paths)
        return paths

    async def raw_roles(self) -> list[dict]:
        data = await self.api.get(ROLES_PATH, params={"locationid": self.root, "fetchSubTreeTemplates": True})
        return sorted(data or [], key=lambda r: (r.get("templateName") or "").lower())

    async def get_role(self, template_id: int, location_id: Any) -> dict:
        return await self.api.get(f"{ROLES_PATH}/{template_id}", params={"locationid": location_id})

    def classify(self, role: dict, location: str, versions_by_set: dict[str, list[dict]]) -> RoleRow:
        tags = R.tags_of(role)
        if not tags:
            return RoleRow(role, location, None, UNMANAGED)
        if len(set(tags)) > 1:
            return RoleRow(role, location, tags[0], MULTI_TAG)
        name = tags[0]
        if name not in versions_by_set:
            return RoleRow(role, location, name, UNKNOWN_SET)
        versions = versions_by_set[name]
        if not versions:
            return RoleRow(role, location, name, NOT_PUBLISHED)
        current = R.from_role(role)
        fp = R.fingerprint(current) if current is not None else None
        if fp == R.fingerprint(versions[0]["content"]):
            return RoleRow(role, location, name, IN_SYNC, versions[0]["version"])
        for v in versions[1:]:
            if fp == R.fingerprint(v["content"]):
                return RoleRow(role, location, name, BEHIND, v["version"])
        return RoleRow(role, location, name, DRIFTED)

    async def role_rows(self) -> list[RoleRow]:
        roles, locs, sets = await asyncio.gather(self.raw_roles(), self.locations(),
                                                 self._db(self.store.list_rulesets))
        versions = {s["name"]: await self._db(self.store.versions, s["name"]) for s in sets}
        rows = []
        for role in roles:
            lid = _loc_id(role.get("createdAtLocationId"))
            rows.append(self.classify(role, locs.get(lid, f"Location {lid}"), versions))
        return rows

    # ------------------------------------------------------------ publish
    async def plan(self, name: str) -> Plan:
        rs = await self._db(self.store.get_ruleset, name)
        if rs is None:
            raise KeyError(name)
        target = rs["draft"]
        rows = [r for r in await self.role_rows() if r.ruleset == name and r.status != MULTI_TAG]
        items = []
        for row in rows:
            current = R.from_role(row.role)
            same = current is not None and R.fingerprint(current) == R.fingerprint(target)
            items.append(PlanItem(row, [] if same else R.diff(current, target)))
        plan = Plan(rs, target, rs["has_changes"], items)
        plan.token = self._token(plan)
        return plan

    @staticmethod
    def _token(plan: Plan) -> str:
        h = hashlib.sha256(R.fingerprint(plan.target).encode())
        for item in plan.items:
            h.update(f"|{item.row.template_id}:{R.fingerprint(R.from_role(item.row.role))}".encode())
        return h.hexdigest()[:32]

    async def publish(self, name: str, token: str, user: str) -> int:
        """Publish the draft as a new version (if it changed) and push it to every linked role profile."""
        async with self._write_lock:
            plan = await self.plan(name)
            if plan.token != token:
                raise StalePlan("The rule set or its role profiles changed since you reviewed them.")
            version = (await self._db(self.store.add_version, name, plan.target, user) if plan.new_version
                       else plan.ruleset["latest"])
            run_id = await self._db(self.store.start_run, "publish", name, version, user)
            ok = failed = 0
            for item in plan.to_update:
                good, msg = await self._push(item.row.role, plan.target)
                await self._db(self.store.add_result, run_id, item.row.template_id, item.row.role["templateName"],
                               item.row.location_id, good, msg)
                ok, failed = ok + good, failed + (not good)
            summary = f"v{version}: {ok} updated" + (f", {failed} failed" if failed else "")
            if not plan.to_update:
                summary = f"v{version}: all role profiles were already in sync"
            await self._db(self.store.finish_run, run_id, summary)
            return run_id

    async def _push(self, role: dict, content: dict, description: str | None = None) -> tuple[bool, str]:
        """PUT one role profile with new firewall rules, then read it back and verify."""
        loc = _loc_id(role.get("createdAtLocationId"))
        try:
            fresh = await self.get_role(role["templateId"], loc)   # never PUT a stale copy
            body = R.apply_to_role(fresh, content)
            if description is not None:
                body["description"] = description
            await self.api.put(ROLES_PATH, params={"locationid": loc}, json=body)
            check = await self.get_role(role["templateId"], loc)
        except Exception as exc:  # noqa: BLE001 - recorded per role
            log.warning("Update of role %s failed: %s", role.get("templateName"), exc)
            return False, str(exc)
        got = R.from_role(check)
        if got is None or R.fingerprint(got) != R.fingerprint(content):
            return False, "CV-CUE accepted the update, but the rules read back don't match."
        if description is not None and (check.get("description") or "") != description:
            return False, "Rules updated, but the description read back doesn't match."
        return True, "Updated and verified"

    # ------------------------------------------------------------ single-role actions
    async def link(self, template_id: int, location_id: Any, name: str, user: str) -> int:
        """Tag a role profile with a rule set and apply its latest published version."""
        async with self._write_lock:
            versions = await self._db(self.store.versions, name)
            if not versions:
                raise ValueError(f"Publish {name} before linking role profiles to it.")
            role = await self.get_role(template_id, location_id)
            run_id = await self._db(self.store.start_run, "link", name, versions[0]["version"], user)
            good, msg = await self._push(role, versions[0]["content"], R.set_tag(role.get("description"), name))
            await self._db(self.store.add_result, run_id, template_id, role["templateName"], location_id, good, msg)
            await self._db(self.store.finish_run, run_id,
                           f"Linked {role['templateName']} to v{versions[0]['version']}" if good else "Link failed")
            return run_id

    async def revert(self, template_id: int, location_id: Any, user: str) -> int:
        """Put a drifted or behind role profile back to its rule set's latest published version."""
        async with self._write_lock:
            role = await self.get_role(template_id, location_id)
            tags = R.tags_of(role)
            if len(set(tags)) != 1:
                raise ValueError("This role profile isn't linked to exactly one rule set.")
            versions = await self._db(self.store.versions, tags[0])
            if not versions:
                raise ValueError(f"{tags[0]} has no published version yet.")
            run_id = await self._db(self.store.start_run, "revert", tags[0], versions[0]["version"], user)
            good, msg = await self._push(role, versions[0]["content"])
            await self._db(self.store.add_result, run_id, template_id, role["templateName"], location_id, good, msg)
            await self._db(self.store.finish_run, run_id,
                           f"Reverted {role['templateName']} to v{versions[0]['version']}" if good else "Revert failed")
            return run_id

    async def unlink(self, template_id: int, location_id: Any, user: str) -> int:
        """Remove the rule set tag. The role profile keeps its current firewall rules."""
        async with self._write_lock:
            role = await self.get_role(template_id, location_id)
            tags = R.tags_of(role)
            name = tags[0] if tags else "-"
            run_id = await self._db(self.store.start_run, "unlink", name, None, user)
            body = json.loads(json.dumps(role))
            body["description"] = R.set_tag(role.get("description"), None)
            try:
                await self.api.put(ROLES_PATH, params={"locationid": location_id}, json=body)
                check = await self.get_role(template_id, location_id)
                good = not R.tags_of(check)
                msg = "Unlinked; firewall rules left as they were" if good else "Tag still present after update"
            except Exception as exc:  # noqa: BLE001
                good, msg = False, str(exc)
            await self._db(self.store.add_result, run_id, template_id, role["templateName"], location_id, good, msg)
            summary = f"Unlinked {role['templateName']}" if good else "Unlink failed"
            await self._db(self.store.finish_run, run_id, summary)
            return run_id

    async def role_content(self, template_id: int, location_id: Any) -> tuple[dict, dict]:
        role = await self.get_role(template_id, location_id)
        return role, R.from_role(role) or R.empty_content()

    # ------------------------------------------------------------ create / edit / delete role profiles
    async def folder_locations(self) -> dict:
        """Locations a role profile can be created at (folders), id -> path."""
        paths = await self.locations()
        folders = {k: v for k, v in paths.items()
                   if (self.location_types.get(k) or "").lower() in ("folder", "folderlocation", "")}
        return dict(sorted((folders or paths).items(), key=lambda kv: kv[1]))

    async def references(self, template_id: int, location_id: Any) -> list[str]:
        """Names of SSID profiles and port profiles that use this role profile."""
        refs = await self.api.get(f"{ROLES_PATH}/{template_id}/references", params={"locationid": location_id})
        out = []
        for key in ("ssidHelperReference", "wapPortProfileHelperReference"):
            for r in (refs or {}).get(key) or []:
                out.append(str(r.get("templateName") or r.get("name") or r.get("ssid") or r))
        return out

    async def _ruleset_content(self, name: str | None) -> dict | None:
        if not name:
            return None
        versions = await self._db(self.store.versions, name)
        if not versions:
            raise ValueError(f"{name} has no published version.")
        return versions[0]

    async def create_role(self, f: dict, user: str) -> int:
        async with self._write_lock:
            loc = int(f["location"])
            version = await self._ruleset_content(f.get("ruleset"))
            base = await self.api.get(f"{ROLES_PATH}/-2", params={"locationid": loc})
            body = F.apply(json.loads(json.dumps(base)), f, creating=True)
            if version:
                body = R.apply_to_role(body, version["content"])
            else:
                body["firewallEnabled"], body["firewallProfile"] = False, []
            run_id = await self._db(self.store.start_run, "create", f.get("ruleset") or "-",
                                    version["version"] if version else None, user)
            tid, good, msg = None, False, ""
            try:
                created = await self.api.post(ROLES_PATH, params={"locationid": loc}, json=body)
                tid = (created or {}).get("templateId")
                if tid is None:
                    match = [r for r in await self.raw_roles() if r.get("templateName") == f["profile_name"]]
                    tid = match[0]["templateId"] if match else None
                if tid is None:
                    msg = "CV-CUE accepted the request, but the new role profile wasn't found."
                else:
                    saved = await self.get_role(tid, loc)
                    problems = F.check(saved, f)
                    if version and R.fingerprint(R.from_role(saved)) != R.fingerprint(version["content"]):
                        problems.append("firewall rules")
                    good = not problems
                    msg = "Created and verified" if good else "Created, but these didn't match: " + ", ".join(problems)
            except Exception as exc:  # noqa: BLE001
                msg = str(exc)
            await self._db(self.store.add_result, run_id, tid or 0, f["profile_name"], loc, good, msg)
            await self._db(self.store.finish_run, run_id, f"Created {f['profile_name']}" if tid else "Create failed")
            return run_id

    async def update_role(self, template_id: int, location_id: Any, f: dict, user: str) -> int:
        async with self._write_lock:
            role = await self.get_role(template_id, location_id)
            old_tags = R.tags_of(role)
            old = old_tags[0] if old_tags else ""
            new = f.get("ruleset") or ""
            version = await self._ruleset_content(new) if new and new != old else None
            body = F.apply(json.loads(json.dumps(role)), f, creating=False)
            if version:
                body = R.apply_to_role(body, version["content"])
            run_id = await self._db(self.store.start_run, "edit", new or old or "-",
                                    version["version"] if version else None, user)
            try:
                await self.api.put(ROLES_PATH, params={"locationid": location_id}, json=body)
                saved = await self.get_role(template_id, location_id)
                problems = F.check(saved, f)
                if version and R.fingerprint(R.from_role(saved)) != R.fingerprint(version["content"]):
                    problems.append("firewall rules")
                if (not version and f.get("fw_on") and role.get("firewallEnabled")
                        and R.fingerprint(R.from_role(saved)) != R.fingerprint(R.from_role(role))):
                    problems.append("firewall rules changed unexpectedly")
                good = not problems
                msg = "Saved and verified" if good else "Saved, but these didn't match: " + ", ".join(problems)
            except Exception as exc:  # noqa: BLE001
                good, msg = False, str(exc)
            await self._db(self.store.add_result, run_id, template_id, f["profile_name"], location_id, good, msg)
            await self._db(self.store.finish_run, run_id, f"Edited {f['profile_name']}" if good else "Edit failed")
            return run_id

    async def delete_role(self, template_id: int, location_id: Any, user: str) -> int:
        async with self._write_lock:
            role = await self.get_role(template_id, location_id)
            refs = await self.references(template_id, location_id)
            if refs:
                raise ValueError("This role profile is used by " + ", ".join(refs) + ". Remove it there first.")
            tags = R.tags_of(role)
            run_id = await self._db(self.store.start_run, "delete", tags[0] if tags else "-", None, user)
            try:
                await self.api.delete(f"{ROLES_PATH}/{template_id}", params={"locationid": location_id})
                still = [r for r in await self.raw_roles() if r.get("templateId") == template_id]
                good = not still
                msg = "Deleted" if good else "CV-CUE accepted the request, but the role profile is still listed."
            except Exception as exc:  # noqa: BLE001
                good, msg = False, str(exc)
            await self._db(self.store.add_result, run_id, template_id, role["templateName"], location_id, good, msg)
            await self._db(self.store.finish_run, run_id,
                           f"Deleted {role['templateName']}" if good else "Delete failed")
            return run_id
