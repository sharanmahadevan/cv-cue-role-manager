"""
Business logic: role profile status, publish plans, and the writes to CV-CUE.

A role profile is linked to one or more rule sets by tags `ruleset:<name>` in its CV-CUE
description, in the order they apply. The tags live in CV-CUE (not in this app's database) so the
links are visible in the CV-CUE UI and survive a lost database. Rule sets and their published
versions live in SQLite. A role profile's firewall is the linked rule sets combined in order
(`rules.compose`).

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
IN_SYNC, BEHIND, DRIFTED, NOT_PUBLISHED, UNKNOWN_SET, UNMANAGED = (
    "in_sync", "behind", "drifted", "not_published", "unknown_ruleset", "unmanaged")


@dataclass
class RoleRow:
    role: dict
    location: str
    rulesets: list[str]
    status: str
    versions: dict[str, int] = field(default_factory=dict)   # rule set -> version applied (in sync)
    missing: list[str] = field(default_factory=list)          # unknown or unpublished rule sets
    version: int | None = None                                # single rule set: matching older version

    @property
    def ruleset(self) -> str | None:
        return self.rulesets[0] if self.rulesets else None

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
    target: dict | None = None        # combined rules this role profile should get
    blocked: str = ""                  # why it can't be updated now


@dataclass
class Plan:
    ruleset: dict
    target: dict
    new_version: bool
    items: list[PlanItem] = field(default_factory=list)
    token: str = ""

    @property
    def to_update(self) -> list[PlanItem]:
        return [i for i in self.items if i.changes and not i.blocked]


def label(names: list[str]) -> str:
    return " + ".join(names) if names else "-"


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

    def classify(self, role: dict, location: str, versions_by_set: dict[str, list[dict]],
                 applied_fp: str | None = None) -> RoleRow:
        names = R.tags_of(role)
        if not names:
            return RoleRow(role, location, [], UNMANAGED)
        unknown = [n for n in names if n not in versions_by_set]
        if unknown:
            return RoleRow(role, location, names, UNKNOWN_SET, missing=unknown)
        unpublished = [n for n in names if not versions_by_set[n]]
        if unpublished:
            return RoleRow(role, location, names, NOT_PUBLISHED, missing=unpublished)
        latest = {n: versions_by_set[n][0] for n in names}
        current = R.from_role(role)
        fp = R.fingerprint(current) if current is not None else None
        if fp == R.fingerprint(R.compose([latest[n]["content"] for n in names])):
            return RoleRow(role, location, names, IN_SYNC, {n: v["version"] for n, v in latest.items()},
                           version=latest[names[0]]["version"] if len(names) == 1 else None)
        if fp is not None and fp == applied_fp:
            return RoleRow(role, location, names, BEHIND)
        if len(names) == 1:
            for v in versions_by_set[names[0]][1:]:
                if fp == R.fingerprint(v["content"]):
                    return RoleRow(role, location, names, BEHIND, version=v["version"])
        return RoleRow(role, location, names, DRIFTED)

    async def role_rows(self) -> list[RoleRow]:
        roles, locs, sets, applied = await asyncio.gather(self.raw_roles(), self.locations(),
                                                          self._db(self.store.list_rulesets),
                                                          self._db(self.store.applied_fingerprints))
        versions = {s["name"]: await self._db(self.store.versions, s["name"]) for s in sets}
        rows = []
        for role in roles:
            lid = _loc_id(role.get("createdAtLocationId"))
            rows.append(self.classify(role, locs.get(lid, f"Location {lid}"), versions,
                                      applied.get(role.get("templateId"))))
        return rows

    async def latest_contents(self, names: list[str], overrides: dict | None = None) -> tuple[dict, list[str]]:
        """Combined rules for `names` from their latest published versions (or `overrides`),
        plus the names that have no published version."""
        contents, missing, versions = [], [], {}
        for n in names:
            if overrides and n in overrides:
                contents.append(overrides[n])
                continue
            vs = await self._db(self.store.versions, n)
            if not vs:
                missing.append(n)
                continue
            contents.append(vs[0]["content"])
            versions[n] = vs[0]["version"]
        return R.compose(contents), missing

    # ------------------------------------------------------------ publish
    async def plan(self, name: str) -> Plan:
        rs = await self._db(self.store.get_ruleset, name)
        if rs is None:
            raise KeyError(name)
        draft = rs["draft"]
        items = []
        for row in [r for r in await self.role_rows() if name in r.rulesets]:
            target, missing = await self.latest_contents(row.rulesets, {name: draft})
            current = R.from_role(row.role)
            if missing:
                items.append(PlanItem(row, [], None, "Waiting for " + ", ".join(missing) + " to be published"))
                continue
            same = current is not None and R.fingerprint(current) == R.fingerprint(target)
            items.append(PlanItem(row, [] if same else R.diff(current, target), target))
        plan = Plan(rs, draft, rs["has_changes"], items)
        plan.token = self._token(plan)
        return plan

    @staticmethod
    def _token(plan: Plan) -> str:
        h = hashlib.sha256(R.fingerprint(plan.target).encode())
        for item in plan.items:
            h.update(f"|{item.row.template_id}:{R.fingerprint(R.from_role(item.row.role))}:"
                     f"{R.fingerprint(item.target) if item.target else '-'}".encode())
        return h.hexdigest()[:32]

    async def publish(self, name: str, token: str, user: str) -> int:
        """Publish the draft as a new version (if it changed) and push it to every role profile using it."""
        async with self._write_lock:
            plan = await self.plan(name)
            if plan.token != token:
                raise StalePlan("The rule set or its role profiles changed since you reviewed them.")
            version = (await self._db(self.store.add_version, name, plan.target, user) if plan.new_version
                       else plan.ruleset["latest"])
            run_id = await self._db(self.store.start_run, "publish", name, version, user)
            ok = failed = 0
            for item in plan.to_update:
                good, msg = await self._push(item.row.role, item.target, rulesets=item.row.rulesets)
                await self._db(self.store.add_result, run_id, item.row.template_id, item.row.role["templateName"],
                               item.row.location_id, good, msg)
                ok, failed = ok + good, failed + (not good)
            blocked = [i for i in plan.items if i.blocked]
            summary = f"v{version}: {ok} updated" + (f", {failed} failed" if failed else "")
            if not plan.to_update:
                summary = f"v{version}: all role profiles were already in sync"
            if blocked:
                summary += f", {len(blocked)} waiting on other rule sets"
            await self._db(self.store.finish_run, run_id, summary)
            return run_id

    async def _push(self, role: dict, content: dict, description: str | None = None,
                    rulesets: list[str] | None = None) -> tuple[bool, str]:
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
        await self._record(role["templateId"], content, rulesets or R.tags_of(check))
        return True, "Updated and verified"

    async def _record(self, template_id: int, content: dict, names: list[str]) -> None:
        await self._db(self.store.record_applied, template_id, R.fingerprint(content),
                       {"rulesets": names})

    # ------------------------------------------------------------ single-role actions
    async def link(self, template_id: int, location_id: Any, names: list[str] | str, user: str) -> int:
        """Link a role profile to rule sets (in order) and apply their latest published versions."""
        names = [names] if isinstance(names, str) else [n for i, n in enumerate(names) if n and n not in names[:i]]
        async with self._write_lock:
            content, missing = await self.latest_contents(names)
            if missing:
                raise ValueError("Publish " + ", ".join(missing) + " before linking role profiles to it.")
            role = await self.get_role(template_id, location_id)
            run_id = await self._db(self.store.start_run, "link", label(names), None, user)
            good, msg = await self._push(role, content, R.set_tags(role.get("description"), names), names)
            await self._db(self.store.add_result, run_id, template_id, role["templateName"], location_id, good, msg)
            await self._db(self.store.finish_run, run_id,
                           f"Linked {role['templateName']} to {label(names)}" if good else "Link failed")
            return run_id

    async def revert(self, template_id: int, location_id: Any, user: str) -> int:
        """Put a drifted or behind role profile back to its rule sets' latest published versions."""
        async with self._write_lock:
            role = await self.get_role(template_id, location_id)
            names = R.tags_of(role)
            if not names:
                raise ValueError("This role profile isn't linked to a rule set.")
            content, missing = await self.latest_contents(names)
            if missing:
                raise ValueError(", ".join(missing) + " has no published version yet.")
            run_id = await self._db(self.store.start_run, "revert", label(names), None, user)
            good, msg = await self._push(role, content, rulesets=names)
            await self._db(self.store.add_result, run_id, template_id, role["templateName"], location_id, good, msg)
            await self._db(self.store.finish_run, run_id,
                           f"Reverted {role['templateName']} to the latest {label(names)}" if good
                           else "Revert failed")
            return run_id

    async def unlink(self, template_id: int, location_id: Any, user: str) -> int:
        """Remove the rule set tag. The role profile keeps its current firewall rules."""
        async with self._write_lock:
            role = await self.get_role(template_id, location_id)
            run_id = await self._db(self.store.start_run, "unlink", label(R.tags_of(role)), None, user)
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

    async def create_role(self, f: dict, user: str) -> int:
        async with self._write_lock:
            loc = int(f["location"])
            names = f.get("rulesets") or []
            content, missing = await self.latest_contents(names) if names else (None, [])
            if missing:
                raise ValueError(", ".join(missing) + " has no published version.")
            base = await self.api.get(f"{ROLES_PATH}/-2", params={"locationid": loc})
            body = F.apply(json.loads(json.dumps(base)), f, creating=True)
            if content is not None:
                body = R.apply_to_role(body, content)
            else:
                body["firewallEnabled"], body["firewallProfile"] = False, []
            run_id = await self._db(self.store.start_run, "create", label(names), None, user)
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
                    if content is not None and R.fingerprint(R.from_role(saved)) != R.fingerprint(content):
                        problems.append("firewall rules")
                    good = not problems
                    msg = "Created and verified" if good else "Created, but these didn't match: " + ", ".join(problems)
                    if good and content is not None:
                        await self._record(tid, content, names)
            except Exception as exc:  # noqa: BLE001
                msg = str(exc)
            await self._db(self.store.add_result, run_id, tid or 0, f["profile_name"], loc, good, msg)
            await self._db(self.store.finish_run, run_id, f"Created {f['profile_name']}" if tid else "Create failed")
            return run_id

    async def update_role(self, template_id: int, location_id: Any, f: dict, user: str) -> int:
        async with self._write_lock:
            role = await self.get_role(template_id, location_id)
            old = R.tags_of(role)
            new = f.get("rulesets") or []
            content = None
            if new and new != old:
                content, missing = await self.latest_contents(new)
                if missing:
                    raise ValueError(", ".join(missing) + " has no published version.")
            body = F.apply(json.loads(json.dumps(role)), f, creating=False)
            if content is not None:
                body = R.apply_to_role(body, content)
            run_id = await self._db(self.store.start_run, "edit", label(new or old), None, user)
            try:
                await self.api.put(ROLES_PATH, params={"locationid": location_id}, json=body)
                saved = await self.get_role(template_id, location_id)
                problems = F.check(saved, f)
                if content is not None and R.fingerprint(R.from_role(saved)) != R.fingerprint(content):
                    problems.append("firewall rules")
                if (content is None and f.get("fw_on") and role.get("firewallEnabled")
                        and R.fingerprint(R.from_role(saved)) != R.fingerprint(R.from_role(role))):
                    problems.append("firewall rules changed unexpectedly")
                good = not problems
                msg = "Saved and verified" if good else "Saved, but these didn't match: " + ", ".join(problems)
                if good and content is not None:
                    await self._record(template_id, content, new)
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
            run_id = await self._db(self.store.start_run, "delete", label(R.tags_of(role)), None, user)
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
