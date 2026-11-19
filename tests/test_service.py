import pytest

from cvcue_roles import rules as R
from cvcue_roles.mock import MockCvcue, seed_store
from cvcue_roles.service import Portal, StalePlan
from cvcue_roles.store import Store


@pytest.fixture
def setup(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    seed_store(store)
    api = MockCvcue()
    return Portal(api, store), api, store


async def status_of(portal):
    return {r.role["templateName"]: r.status for r in await portal.role_rows()}


async def test_initial_status(setup):
    portal, _, _ = setup
    assert await status_of(portal) == {
        "Demo-Sync-A": "in_sync", "Demo-Sync-B": "in_sync", "Guest": "unmanaged",
        "Onboarding-Role": "unmanaged", "Test": "drifted"}


async def test_publish_updates_linked_roles_and_verifies(setup):
    portal, api, store = setup
    plan = await portal.plan("basic-web")
    assert plan.new_version and len(plan.to_update) == 2
    run_id = await portal.publish("basic-web", plan.token, "me@x.com")
    run = store.get_run(run_id)
    assert [r["ok"] for r in run["results"]] == [1, 1]
    assert run["version"] == 2
    assert {p["templateId"] for p in api.puts} == {8, 9}
    assert api.roles[9]["vlanId"] == 20                       # untouched settings survive
    assert (await status_of(portal))["Demo-Sync-B"] == "in_sync"
    again = await portal.plan("basic-web")
    assert not again.new_version and not again.to_update


async def test_stale_plan_is_refused(setup):
    portal, api, _ = setup
    plan = await portal.plan("basic-web")
    api.roles[8]["firewallProfile"] = api.roles[8]["firewallProfile"][1:]   # someone deletes a rule in CV-CUE
    with pytest.raises(StalePlan):
        await portal.publish("basic-web", plan.token, "me@x.com")
    assert not api.puts


async def test_behind_after_older_version(setup):
    portal, _, store = setup
    store.add_version("basic-web", store.get_ruleset("basic-web")["draft"], "me")   # v2 published, not pushed
    assert (await status_of(portal))["Demo-Sync-A"] == "behind"


async def test_revert_drifted_role(setup):
    portal, api, store = setup
    run_id = await portal.revert(7, 3, "me")
    assert store.get_run(run_id)["results"][0]["ok"] == 1
    assert (await status_of(portal))["Test"] == "in_sync"


async def test_link_and_unlink(setup):
    portal, api, store = setup
    run_id = await portal.link(10, 3, "basic-web", "me")
    assert store.get_run(run_id)["results"][0]["ok"] == 1
    assert api.roles[10]["description"] == "Guest access ruleset:basic-web"
    assert api.roles[10]["vlanId"] == 30
    assert (await status_of(portal))["Guest"] == "in_sync"
    await portal.unlink(10, 3, "me")
    assert api.roles[10]["description"] == "Guest access"
    assert api.roles[10]["firewallEnabled"]                    # rules kept
    assert (await status_of(portal))["Guest"] == "unmanaged"


async def test_link_requires_published_version(setup):
    portal, _, store = setup
    store.create_ruleset("empty", "", R.empty_content(), "me")
    with pytest.raises(ValueError):
        await portal.link(10, 3, "empty", "me")


async def test_failed_verification_is_reported(setup):
    portal, api, store = setup
    real_put = api.put

    async def lossy_put(path, params=None, json=None, **kw):
        json = dict(json)
        json["firewallProfile"] = json["firewallProfile"][1:]     # server drops a rule
        return await real_put(path, params=params, json=json)

    api.put = lossy_put
    plan = await portal.plan("basic-web")
    run = store.get_run(await portal.publish("basic-web", plan.token, "me"))
    assert all(r["ok"] == 0 for r in run["results"])
    assert "don't match" in run["results"][0]["message"]
    assert "2 failed" in run["summary"]
