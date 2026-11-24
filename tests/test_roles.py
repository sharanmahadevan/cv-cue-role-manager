import re

import pytest
from starlette.testclient import TestClient

from cvcue_roles import roleform as F
from cvcue_roles import rules as R
from cvcue_roles.config import Settings
from cvcue_roles.mock import MockCvcue, seed_store
from cvcue_roles.service import Portal
from cvcue_roles.store import Store
from cvcue_roles.web.app import create_app

LOCS = {3: "Home"}


@pytest.fixture
def setup(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    seed_store(store)
    api = MockCvcue()
    return Portal(api, store), api, store


def form(**kw):
    if "ruleset" in kw:                       # shorthand for a single rule set
        one = kw.pop("ruleset")
        kw["rulesets"] = [one] if one else []
    base = {"role_name": "Staff", "profile_name": "Staff", "description": "Employees", "vlan_on": "1",
            "vlan_type": "id", "vlan_id": "40", "fw_on": "1", "rulesets": ["basic-web"], "location": "3"}
    return {k: v for k, v in {**base, **kw}.items() if v is not None}


def parse(published=frozenset({"basic-web", "iot-lockdown"}), names=frozenset(), **kw):
    return F.parse(form(**kw), existing_names=set(names), published=set(published), creating=True, locations=LOCS)


# ------------------------------------------------------------ form rules
def test_parse_validation():
    _, errs = parse(role_name="bad/name", vlan_id="5000", down_on="1", down="2000", down_unit="1")
    assert len(errs) == 3
    _, errs = parse(profile_name="test", names={"test"})
    assert errs == ["A role profile named test already exists."]
    _, errs = parse(ruleset="nope", published=set())
    assert "nope has no published version" in errs[0]
    _, errs = parse(ruleset="")
    assert errs == ["Pick a firewall rule set, create a new one, or turn off Layer 3-4 firewall rules."]
    f, errs = parse(ruleset="", fw_on=None)
    assert not errs and f["rulesets"] == []
    f, errs = parse(description="hi ruleset:sneaky")
    assert not errs and f["description"] == "hi"          # tags come only from the rule set field
    _, errs = parse(vlan_type="pool", vlan_pool="1,2,6-23")
    assert not errs
    _, errs = parse(vlan_type="pool", vlan_pool="9-3")
    assert errs and "VLAN pool" in errs[0]
    _, errs = parse(vlan_type="name", vlan_name="Staff VLAN")
    assert errs and "VLAN name" in errs[0]
    f, errs = parse(ruleset=F.NEW_RULESET)
    assert not errs and f["rulesets"] == [F.NEW_RULESET]


def test_apply_maps_cvcue_fields():
    f, _ = parse(role_name="staff-role", profile_name="Staff Profile", inherit="1", vlan_type="pool",
                 vlan_pool="10,20-29", up_on="1", up="5", up_unit="1", fw_on=None, ruleset="")
    body = F.apply({}, f, creating=True)
    assert body["role"] == "staff-role" and body["templateName"] == "Staff Profile"
    assert body["inheritFromSSID"] and body["vlanPoolingEnabled"] and body["vlanPool"] == "10,20-29"
    assert body["vlanId"] == 10 and body["firewallEnabled"] is False
    assert body["perUserTrafficControlEnabled"] and body["trafficControlUploadLimit"] == 5 * 1024
    assert body["trafficControlDownloadLimit"] == 0
    assert F.check(body, f) == []


def test_fields_round_trip_from_role(setup):
    _, api, _ = setup
    f = F.fields_from_role(api.roles[9])
    assert f["rulesets"] == ["basic-web"] and f["description"] == "Demo B"
    assert f["vlan_on"] == "1" and f["vlan_type"] == "id" and f["vlan_id"] == "20" and f["fw_on"] == "1"


# ------------------------------------------------------------ service against the mock
async def test_create_with_ruleset(setup):
    portal, api, store = setup
    f, _ = parse(down_on="1", down="20", down_unit="1", up_on="1", up="5", up_unit="1")
    run = store.get_run(await portal.create_role(f, "me"))
    assert run["results"][0]["ok"] == 1, run
    new = api.roles[run["results"][0]["template_id"]]
    assert new["templateName"] == "Staff" and new["vlanId"] == 40 and new["vlanEnabled"]
    assert new["description"] == "Employees ruleset:basic-web"
    assert new["trafficControlDownloadLimit"] == 20 * 1024 and new["perUserTrafficControlEnabled"]
    assert R.fingerprint(R.from_role(new)) == R.fingerprint(store.versions("basic-web")[0]["content"])
    status = {r.role["templateName"]: r.status for r in await portal.role_rows()}
    assert status["Staff"] == "in_sync"


async def test_create_with_firewall_off(setup):
    portal, api, store = setup
    f, _ = parse(vlan_on=None, fw_on=None, ruleset="")
    run = store.get_run(await portal.create_role(f, "me"))
    new = api.roles[run["results"][0]["template_id"]]
    assert run["results"][0]["ok"] == 1 and not new["firewallEnabled"] and not new["vlanEnabled"]


async def test_edit_keep_current_rules_unlinks(setup):
    portal, api, store = setup
    before = R.from_role(api.roles[9])
    f = F.fields_from_role(api.roles[9])
    f.update(profile_name="Demo-Sync-B2", vlan_id="25", rulesets=[])
    f, errs = F.parse(f, existing_names=set(), published={"basic-web"}, current_rulesets=["basic-web"],
                      creating=False, keep_allowed=True)
    assert not errs
    run = store.get_run(await portal.update_role(9, 3, f, "me"))
    assert run["results"][0]["ok"] == 1, run
    role = api.roles[9]
    assert role["templateName"] == "Demo-Sync-B2" and role["vlanId"] == 25 and role["description"] == "Demo B"
    assert R.fingerprint(R.from_role(role)) == R.fingerprint(before)


async def test_edit_links_new_ruleset_and_turns_firewall_off(setup):
    portal, api, store = setup
    f = F.fields_from_role(api.roles[10])
    f.update(fw_on="1", rulesets=["iot-lockdown"])
    run = store.get_run(await portal.update_role(10, 3, f, "me"))
    assert run["results"][0]["ok"] == 1
    assert R.tags_of(api.roles[10]) == ["iot-lockdown"] and api.roles[10]["firewallEnabled"]
    f = F.fields_from_role(api.roles[10])
    f.update(fw_on="", rulesets=[])
    run = store.get_run(await portal.update_role(10, 3, f, "me"))
    assert run["results"][0]["ok"] == 1, run
    assert not api.roles[10]["firewallEnabled"] and not R.tags_of(api.roles[10])


async def test_delete_blocked_by_reference_then_allowed(setup):
    portal, api, store = setup
    with pytest.raises(ValueError, match="IoT-A"):
        await portal.delete_role(7, 3, "me")
    run = store.get_run(await portal.delete_role(10, 3, "me"))
    assert run["results"][0]["ok"] == 1 and 10 not in api.roles


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


def test_roles_list_has_radio_toolbar(client):
    c, _ = client
    html = c.get("/roles").text
    assert html.count('type="radio" name="sel"') == 5
    assert 'href="/roles/new"' in html and 'formaction="/roles/edit"' in html and 'formaction="/roles/delete"' in html
    r = c.get("/roles/edit?sel=9:3", follow_redirects=False)
    assert r.headers["location"] == "/roles/9/edit?loc=3"
    assert c.get("/roles/delete", follow_redirects=True).text.count("Select a role profile first.") == 1


def test_form_matches_cvcue_layout(client):
    c, _ = client
    html = c.get("/roles/new").text
    for text in ("Role name", "Profile name", "Use SSID settings in absence of role-specific settings",
                 "VLAN pool", "Layer 3-4 firewall rules", "Limit the maximum upload bandwidth per user to",
                 "+ Create new rule set…", "basic-web (v1, 4 rules)"):
        assert text in html, text
    assert 'name="vlan_on" value="1" checked' in html and 'name="fw_on" value="1" checked' in html
    assert "Basement" not in html                          # floors aren't offered as locations


def test_unpublished_ruleset_listed_but_not_selectable(client):
    c, _ = client
    token = csrf_of(c.get("/rulesets").text)
    c.post("/rulesets", data={"csrf": token, "name": "draft-only"})
    assert '<option value="draft-only" disabled>draft-only (not published yet)</option>' in c.get("/roles/new").text


def test_create_edit_delete_pages(client):
    c, api = client
    token = csrf_of(c.get("/roles/new").text)
    data = {"csrf": token, "role_name": "contractors", "profile_name": "Contractors", "location": "3",
            "vlan_on": "1", "vlan_type": "id", "vlan_id": "0", "fw_on": "1", "rulesets": "basic-web"}
    bad = c.post("/roles/new", data={**data, "profile_name": ""})
    assert bad.status_code == 400 and "Enter a profile name" in bad.text
    ok = c.post("/roles/new", data=data)
    assert "Created and verified" in ok.text
    new = [r for r in api.roles.values() if r["templateName"] == "Contractors"][0]
    assert new["role"] == "contractors"
    edit = c.get("/roles/9/edit?loc=3").text
    assert 'value="Demo B"' in edit and 'value="20"' in edit
    assert "current rules without a rule set" in edit and '<option value="basic-web" selected>' in edit
    saved = c.post("/roles/9/edit", data={"csrf": token, "loc": "3", "role_name": "Demo-Sync-B",
                                          "profile_name": "Demo-Sync-B", "description": "Lab", "vlan_on": "1",
                                          "vlan_type": "id", "vlan_id": "21", "fw_on": "1",
                                          "rulesets": "basic-web"})
    assert "Saved and verified" in saved.text and api.roles[9]["vlanId"] == 21
    assert api.roles[9]["description"] == "Lab ruleset:basic-web"
    confirm = c.get("/roles/7/delete?loc=3").text
    assert "IoT-A" in confirm and "can't be deleted" in confirm
    gone = c.post("/roles/10/delete", data={"csrf": token, "loc": "3"})
    assert "Deleted Guest" in gone.text and 10 not in api.roles


def test_create_new_ruleset_from_role_form_and_return(client):
    c, api = client
    token = csrf_of(c.get("/roles/new").text)
    data = {"csrf": token, "role_name": "printers", "profile_name": "Printers", "location": "3",
            "description": "Office printers", "vlan_on": "1", "vlan_type": "id", "vlan_id": "60", "fw_on": "1",
            "rulesets": "__new__", "up_on": "1", "up": "2", "up_unit": "1"}
    r = c.post("/roles/new", data=data, follow_redirects=False)
    assert r.headers["location"] == "/rulesets/new"
    page = c.get("/rulesets/new").text
    assert "Creating a rule set for <b>Printers</b>" in page and 'name="for_role"' in page
    editor = c.post("/rulesets", data={"csrf": token, "name": "printer-only", "for_role": "1"}).text
    assert "Creating this rule set for <b>Printers</b>" in editor
    c.post("/rulesets/printer-only/edit", data={"csrf": token, "op": "add", "name": "Allow-IPP", "direction": "1",
                                                "protocol": "1", "port": "631", "action": "1"})
    review = c.get("/rulesets/printer-only/review").text
    plan_token = re.search(r'name="token" value="([^"]+)"', review).group(1)
    done = c.post("/rulesets/printer-only/publish", data={"csrf": token, "token": plan_token}).text
    assert "Return to role profile" in done and 'href="/roles/new?resume=1"' in done
    back = c.get("/roles/new?resume=1").text
    assert 'value="Printers"' in back and 'value="60"' in back and 'value="Office printers"' in back
    assert '<option value="printer-only" selected>' in back
    assert "Return to role profile" not in c.get("/rulesets/printer-only").text   # handoff finished
    created = c.post("/roles/new", data={**data, "rulesets": "printer-only"})
    assert "Created and verified" in created.text
    role = [r for r in api.roles.values() if r["templateName"] == "Printers"][0]
    assert [e["name"] for e in role["firewallProfile"]] == ["Allow-IPP", ""]


def test_ruleset_created_on_rulesets_page_shows_in_role_dropdown(client):
    c, _ = client
    token = csrf_of(c.get("/rulesets/new").text)
    c.post("/rulesets", data={"csrf": token, "name": "made-elsewhere", "description": "from the rule sets page"})
    c.post("/rulesets/made-elsewhere/edit", data={"csrf": token, "op": "add", "name": "Allow-DNS", "direction": "2",
                                                  "protocol": "2", "port": "53", "action": "1"})
    review = c.get("/rulesets/made-elsewhere/review").text
    plan_token = re.search(r'name="token" value="([^"]+)"', review).group(1)
    c.post("/rulesets/made-elsewhere/publish", data={"csrf": token, "token": plan_token})
    assert "made-elsewhere (v1, 1 rules)" in c.get("/roles/new").text
    assert "made-elsewhere (v1, 1 rules)" in c.get("/roles/8/edit?loc=3").text


def test_missing_ruleset_page_offers_create_from_role(tmp_path):
    cfg = Settings(dev_login=True, db_path=str(tmp_path / "empty.db"), session_secret="s")
    api = MockCvcue()                       # live-like: tags in CV-CUE, empty app database
    c = TestClient(create_app(cfg, api))
    c.post("/auth/dev", data={"email": "dev@localhost", "next": "/roles"})
    assert "Unknown rule set" in c.get("/roles").text
    page = c.get("/rulesets/basic-web").text
    assert "isn't set up in this app yet" in page and "Copy current rules from Demo-Sync-A" in page
    token = csrf_of(page)
    c.post("/rulesets", data={"csrf": token, "name": "basic-web", "source": "role:8:3"})
    review = c.get("/rulesets/basic-web/review").text
    assert review.count("Already matches. Not updated.") == 2
    plan_token = re.search(r'name="token" value="([^"]+)"', review).group(1)
    c.post("/rulesets/basic-web/publish", data={"csrf": token, "token": plan_token})
    assert c.get("/roles").text.count("In sync · v1") == 2
    assert not api.puts                      # nothing written to CV-CUE


def test_delete_result_page_has_no_dead_links(client):
    c, _ = client
    token = csrf_of(c.get("/roles").text)
    html = c.post("/roles/10/delete", data={"csrf": token, "loc": "3"}).text
    assert "Delete · Guest" in html and 'Guest <span class="tag">Deleted</span>' in html
    assert 'href="/roles/10' not in html and 'href="/rulesets/-"' not in html
    assert 'href="/roles">Back to role profiles' in html


def test_edit_result_page_links_role_and_ruleset(client):
    c, _ = client
    token = csrf_of(c.get("/roles").text)
    html = c.post("/roles/9/edit", data={"csrf": token, "loc": "3", "role_name": "Demo-Sync-B",
                                         "profile_name": "Demo-Sync-B", "vlan_on": "1", "vlan_type": "id",
                                         "vlan_id": "20", "fw_on": "1", "rulesets": "basic-web"}).text
    assert 'href="/roles/9?loc=3">Open Demo-Sync-B' in html and 'href="/rulesets/basic-web">Open rule set' in html


def test_bandwidth_is_mbps_in_form_and_kbps_in_cvcue():
    # Live CV-CUE: limit 500 with unit Mbps displays as 0.49 Mbps, so the stored number is Kbps.
    f, errs = parse(up_on="1", up="500", down_on="1", down="1024")
    assert not errs
    body = F.apply({}, f, creating=True)
    assert body["trafficControlUploadLimit"] == 500 * 1024 and body["trafficControlUploadLimitUnit"] == 1
    assert body["trafficControlDownloadLimit"] == 1024 * 1024 and body["trafficControlDownloadLimitUnit"] == 1
    back = F.fields_from_role({**body, "perUserTrafficControlEnabled": True})
    assert (back["up_on"], back["up"], back["down"]) == ("1", "500", "1024")
    for bad in ("0", "1025", "2.5", "abc", ""):
        _, errs = parse(up_on="1", up=bad)
        assert errs == ["Upload limit must be a whole number from 1 to 1024 Mbps."], bad


def test_value_saved_before_the_fix_shows_in_mbps():
    # Test3 was saved as 500 (Kbps) by the old version: show what CV-CUE shows, 0.488 Mbps.
    f = F.fields_from_role({"perUserTrafficControlEnabled": True, "trafficControlUploadLimit": 500,
                            "trafficControlUploadLimitUnit": 1})
    assert (f["up_on"], f["up"]) == ("1", "0.488")
    assert F.from_kbps(0) == "" and F.from_kbps(2048) == "2"


def test_form_offers_only_mbps(client):
    c, _ = client
    html = c.get("/roles/new").text
    assert "Kbps" not in html and "_unit" not in html and "<span>Mbps</span>" in html
