"""Several rule sets linked to one role profile."""
import re

import pytest
from starlette.testclient import TestClient

from cvcue_roles import rules as R
from cvcue_roles.config import Settings
from cvcue_roles.mock import MockCvcue, seed_store
from cvcue_roles.service import Portal
from cvcue_roles.store import Store
from cvcue_roles.web.app import create_app


def names_in(role):
    return [e["name"] for e in sorted((e for e in role["firewallProfile"] if not e["defaultRule"]),
                                      key=lambda e: e["orderId"])]


def default_of(role):
    return next(e["action"] for e in role["firewallProfile"] if e["defaultRule"])


# ------------------------------------------------------------ helpers
def test_compose_keeps_order_and_blocks_by_default_if_any_set_blocks():
    a = {"rules": [R.new_rule("A1", port="1"), R.new_rule("A2", port="2")], "default_action": 1}
    b = {"rules": [R.new_rule("B1", port="3")], "default_action": 2}
    c = R.compose([a, b])
    assert [r["name"] for r in c["rules"]] == ["A1", "A2", "B1"] and c["default_action"] == 2
    assert R.compose([b, a])["rules"][0]["name"] == "B1"
    same_twice = R.compose([a, a])                    # identical rule sets: second copy adds nothing
    assert [r["name"] for r in same_twice["rules"]] == ["A1", "A2"] and same_twice["default_action"] == 1
    assert R.compose([]) == R.empty_content()


def test_tags_keep_order_and_drop_duplicates():
    assert R.tags_of({"description": "x ruleset:b ruleset:a ruleset:b"}) == ["b", "a"]
    assert R.set_tags("Staff ruleset:old", ["web", "iot"]) == "Staff ruleset:web ruleset:iot"
    assert R.set_tags("Staff ruleset:web ruleset:iot", []) == "Staff"


# ------------------------------------------------------------ service
@pytest.fixture
def setup(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    seed_store(store)
    api = MockCvcue()
    return Portal(api, store), api, store


async def status(portal):
    return {r.role["templateName"]: r for r in await portal.role_rows()}


async def test_link_two_rule_sets_in_order(setup):
    portal, api, store = setup
    run = store.get_run(await portal.link(10, 3, ["basic-web", "iot-lockdown"], "me"))
    assert run["results"][0]["ok"] == 1, run
    assert run["ruleset"] == "basic-web + iot-lockdown"
    guest = api.roles[10]
    assert guest["description"] == "Guest access ruleset:basic-web ruleset:iot-lockdown"
    # iot-lockdown's Allow-DNS repeats basic-web's, so it's left out
    assert names_in(guest) == ["Allow-DNS", "Allow-DHCP", "Allow-HTTP", "Allow-HTTPS", "Allow-MQTT-TLS"]
    assert default_of(guest) == 2
    row = (await status(portal))["Guest"]
    assert row.status == "in_sync" and row.versions == {"basic-web": 1, "iot-lockdown": 1}


async def test_publishing_one_set_updates_combined_roles_and_keeps_the_other(setup):
    portal, api, store = setup
    await portal.link(10, 3, ["iot-lockdown", "basic-web"], "me")
    plan = await portal.plan("basic-web")                      # draft adds Allow-8443
    guest_item = next(i for i in plan.items if i.row.template_id == 10)
    assert [r["name"] for r in guest_item.target["rules"]][:2] == ["Allow-DNS", "Allow-MQTT-TLS"]
    run = store.get_run(await portal.publish("basic-web", plan.token, "me"))
    assert {r["role_name"]: r["ok"] for r in run["results"]} == {"Demo-Sync-A": 1, "Demo-Sync-B": 1, "Guest": 1}
    assert names_in(api.roles[10])[:2] == ["Allow-DNS", "Allow-MQTT-TLS"]
    assert names_in(api.roles[10])[-1] == "Allow-8443"
    rows = await status(portal)
    assert rows["Guest"].status == "in_sync" and rows["Guest"].versions == {"iot-lockdown": 1, "basic-web": 2}


async def test_newer_version_not_yet_applied_is_update_pending(setup):
    portal, api, store = setup
    await portal.link(10, 3, ["basic-web", "iot-lockdown"], "me")
    store.add_version("iot-lockdown", {"rules": [R.new_rule("Only-NTP", 2, 2, "123")], "default_action": 2}, "me")
    assert (await status(portal))["Guest"].status == "behind"
    run = store.get_run(await portal.revert(10, 3, "me"))
    assert run["results"][0]["ok"] == 1 and names_in(api.roles[10])[-1] == "Only-NTP"
    assert (await status(portal))["Guest"].status == "in_sync"


async def test_unpublished_set_blocks_the_role(setup):
    portal, api, store = setup
    await portal.link(10, 3, ["basic-web"], "me")
    store.create_ruleset("draft-only", "", {"rules": [R.new_rule("X")], "default_action": 2}, "me")
    api.roles[10]["description"] += " ruleset:draft-only"       # e.g. tagged in CV-CUE by hand
    row = (await status(portal))["Guest"]
    assert row.status == "not_published" and row.missing == ["draft-only"]
    plan = await portal.plan("basic-web")
    guest = next(i for i in plan.items if i.row.template_id == 10)
    assert guest.blocked == "Waiting for draft-only to be published" and guest not in plan.to_update
    with pytest.raises(ValueError, match="draft-only"):
        await portal.link(10, 3, ["basic-web", "draft-only"], "me")


async def test_edit_reorders_rule_sets(setup):
    from cvcue_roles import roleform as F
    portal, api, store = setup
    await portal.link(10, 3, ["basic-web", "iot-lockdown"], "me")
    f = F.fields_from_role(api.roles[10])
    f["rulesets"] = ["iot-lockdown", "basic-web"]
    run = store.get_run(await portal.update_role(10, 3, f, "me"))
    assert run["results"][0]["ok"] == 1, run
    assert R.tags_of(api.roles[10]) == ["iot-lockdown", "basic-web"]
    assert names_in(api.roles[10])[:2] == ["Allow-DNS", "Allow-MQTT-TLS"]


async def test_drifted_multi_set_role_offers_revert_not_adopt(setup):
    portal, api, store = setup
    await portal.link(10, 3, ["basic-web", "iot-lockdown"], "me")
    api.roles[10]["firewallProfile"] = api.roles[10]["firewallProfile"][2:]
    assert (await status(portal))["Guest"].status == "drifted"


# ------------------------------------------------------------ web
@pytest.fixture
def client(tmp_path):
    cfg = Settings(mock=True, dev_login=True, db_path=str(tmp_path / "a.db"), session_secret="s")
    api = MockCvcue()
    c = TestClient(create_app(cfg, api))
    c.post("/auth/dev", data={"email": "dev@localhost", "next": "/roles"})
    return c, api


def csrf_of(html):
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def test_create_role_with_two_rule_sets_from_the_form(client):
    c, api = client
    page = c.get("/roles/new").text
    assert 'id="rsAdd"' in page and page.count('name="rulesets"') >= 2
    token = csrf_of(page)
    r = c.post("/roles/new", data={"csrf": token, "role_name": "lab", "profile_name": "Lab", "location": "3",
                                   "vlan_on": "1", "vlan_type": "id", "vlan_id": "0", "fw_on": "1",
                                   "rulesets": ["iot-lockdown", "basic-web", ""]})
    assert "Created and verified" in r.text
    lab = next(x for x in api.roles.values() if x["templateName"] == "Lab")
    assert R.tags_of(lab) == ["iot-lockdown", "basic-web"]
    roles = c.get("/roles").text
    joined = ('href="/rulesets/iot-lockdown">iot-lockdown</a><span class="none"> + </span>'
              '<a href="/rulesets/basic-web">')
    assert joined in roles
    assert "In sync · v1 + v1" in roles
    edit = c.get(f"/roles/{lab['templateId']}/edit?loc=3").text
    assert edit.index('<option value="iot-lockdown" selected>') < edit.index('<option value="basic-web" selected>')


def test_role_page_adds_a_second_rule_set(client):
    c, api = client
    page = c.get("/roles/8?loc=3").text
    assert "Add rule set" in page and '<input type="hidden" name="rulesets" value="basic-web">' in page
    review = c.get("/roles/8/link?loc=3&rulesets=basic-web&rulesets=iot-lockdown").text
    assert "Link Demo-Sync-A to basic-web + iot-lockdown" in review and "Allow-MQTT-TLS" in review
    done = c.post("/roles/8/link", data={"csrf": csrf_of(review), "loc": "3",
                                         "rulesets": ["basic-web", "iot-lockdown"]}).text
    assert "Linked Demo-Sync-A to basic-web + iot-lockdown" in done
    assert R.tags_of(api.roles[8]) == ["basic-web", "iot-lockdown"]
    usage = c.get("/rulesets").text
    assert usage.count("iot-lockdown") >= 1


# ------------------------------------------------------------ duplicates and conflicts
def test_combine_leaves_out_duplicates_and_reports_conflicts():
    base = {"rules": [R.new_rule("DNS", 2, 2, "53"), R.new_rule("Web", 2, 1, "80")], "default_action": 2}
    other = {"rules": [R.new_rule("dns-again", 2, 2, "53"),                 # same traffic, same action
                       R.new_rule("No-Web", 2, 1, "80", action=2),          # same traffic, opposite action
                       R.new_rule("DNS-any-dir", 0, 2, "53"),               # overlaps but not the same traffic
                       R.new_rule("MQTT", 2, 1, "8883")], "default_action": 1}
    content, skipped, conflicts = R.combine([("base", base), ("other", other)])
    assert [r["name"] for r in content["rules"]] == ["DNS", "Web", "No-Web", "DNS-any-dir", "MQTT"]
    assert content["default_action"] == 2
    assert [R.note_text(n, "skipped") for n in skipped] == [
        "dns-again in other left out: DNS in base already matches the same traffic with the same action"]
    assert [R.note_text(n, "conflict") for n in conflicts] == [
        "No-Web in other never applies: Web in base matches the same traffic first (allow)"]


def test_duplicates_inside_one_rule_set_are_kept_but_flagged():
    one = {"rules": [R.new_rule("A", 2, 1, "443"), R.new_rule("B", 2, 1, "443"),
                     R.new_rule("C", 2, 1, "443", action=2)], "default_action": 2}
    assert [r["name"] for r in R.combine([("x", one)])[0]["rules"]] == ["A", "B", "C"]
    assert R.issues_in(one) == [
        "Rule 2 (B) duplicates rule 1 (A).",
        "Rule 3 (C) never applies: rule 1 (A) matches the same traffic first."]


def test_hostname_case_doesnt_hide_a_duplicate():
    a = {"rules": [R.new_rule("A", 2, 1, "443", "Intranet.Corp")], "default_action": 2}
    b = {"rules": [R.new_rule("B", 2, 1, "443", "intranet.corp")], "default_action": 2}
    assert len(R.combine([("a", a), ("b", b)])[1]) == 1


async def test_publish_plan_carries_notes(setup):
    portal, api, store = setup
    await portal.link(10, 3, ["basic-web", "iot-lockdown"], "me")
    plan = await portal.plan("iot-lockdown")
    guest = next(i for i in plan.items if i.row.template_id == 10)
    assert guest.notes == ["Allow-DNS in iot-lockdown left out: Allow-DNS in basic-web already matches the same traffic with the same action"]  # noqa: E501


def test_pages_show_combine_notes_and_editor_warnings(client):
    c, api = client
    review = c.get("/roles/8/link?loc=3&rulesets=basic-web&rulesets=iot-lockdown").text
    assert "Combining these rule sets" in review
    assert "Allow-DNS in iot-lockdown left out: Allow-DNS in basic-web already matches the same traffic with the same action" in review  # noqa: E501
    token = csrf_of(review)
    c.post("/roles/8/link", data={"csrf": token, "loc": "3", "rulesets": ["basic-web", "iot-lockdown"]})
    role_page = c.get("/roles/8?loc=3").text
    assert "Combining basic-web + iot-lockdown" in role_page and "left out" in role_page
    pub = c.get("/rulesets/iot-lockdown/review").text
    assert "Combining these rule sets" in pub
    form = c.get("/roles/8/edit?loc=3").text
    assert 'id="rsDupSummary"' in form and 'data-key="2|2|53|"' in form
    c.post("/rulesets/basic-web/edit", data={"csrf": token, "op": "add", "name": "DNS-copy", "direction": "2",
                                              "protocol": "2", "port": "53", "action": "1"})
    editor = c.get("/rulesets/basic-web").text
    assert "Check these rules" in editor and "Rule 6 (DNS-copy) duplicates rule 1 (Allow-DNS)." in editor


def test_same_action_different_marking_is_reported_as_never_applying():
    a = {"rules": [R.new_rule("Voice", 2, 2, "5060")], "default_action": 2}
    marked = R.new_rule("Voice-EF", 2, 2, "5060")
    marked["dscp"] = 46
    _, skipped, conflicts = R.combine([("a", a), ("b", {"rules": [marked], "default_action": 2})])
    assert not skipped and [c["rule"]["name"] for c in conflicts] == ["Voice-EF"]


def test_broader_earlier_rule_covers_later_ones():
    anything = R.new_rule("Allow-All", 0, 0, "", "", 1)            # direction, protocol, host: Any
    assert R.covers(anything, R.new_rule("Web", 2, 1, "443", "10.0.0.5"))
    assert R.covers(R.new_rule("Range", 2, 1, "8000-8100"), R.new_rule("App", 2, 1, "8080"))
    assert not R.covers(R.new_rule("Range", 2, 1, "8000-8100"), R.new_rule("Wide", 2, 1, "7000-8050"))
    assert not R.covers(R.new_rule("Out", 2, 1, "443"), R.new_rule("AnyDir", 0, 1, "443"))
    assert not R.covers(R.new_rule("Host", 2, 1, "443", "a.corp"), R.new_rule("AnyHost", 2, 1, "443"))
    assert not R.covers(R.new_rule("TCP", 2, 1, ""), R.new_rule("UDP", 2, 2, ""))


def test_catch_all_in_first_set_is_reported_like_live_block_internet():
    # Live data: Block-Internet has "Https" = protocol Any, direction Any, host Any, allow.
    block_internet = {"rules": [R.new_rule("Allow DNS", 2, 2, "24"), R.new_rule("Https", 0, 0, "", "", 1)],
                      "default_action": 2}
    firewall_1 = {"rules": [R.new_rule("Allow-Https", 2, 1, "443"), R.new_rule("Block-Telnet", 0, 1, "23", action=2)],
                  "default_action": 2}
    content, skipped, conflicts = R.combine([("Block-Internet", block_internet), ("Firewall-1", firewall_1)])
    assert [r["name"] for r in content["rules"]] == ["Allow DNS", "Https", "Block-Telnet"]
    assert R.note_text(skipped[0], "skipped") == (
        "Allow-Https in Firewall-1 left out: Https in Block-Internet already matches all of its traffic with the same action")  # noqa: E501
    assert R.note_text(conflicts[0], "conflict") == (
        "Block-Telnet in Firewall-1 never applies: Https in Block-Internet matches all of its traffic first (allow)")
    # the other order is fine: Firewall-1's specific rules come before the catch-all
    _, skipped, conflicts = R.combine([("Firewall-1", firewall_1), ("Block-Internet", block_internet)])
    assert not skipped and not conflicts


def test_editor_flags_rules_after_a_broader_rule():
    rs = {"rules": [R.new_rule("All-TCP-Out", 2, 1, ""), R.new_rule("Web", 2, 1, "443"),
                    R.new_rule("No-SMB", 2, 1, "445", action=2)], "default_action": 2}
    assert R.issues_in(rs) == [
        "Rule 2 (Web) is already covered by rule 1 (All-TCP-Out).",
        "Rule 3 (No-SMB) never applies: rule 1 (All-TCP-Out) matches all of its traffic first."]
