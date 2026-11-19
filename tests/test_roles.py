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


@pytest.fixture
def setup(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    seed_store(store)
    api = MockCvcue()
    return Portal(api, store), api, store


def form(**kw):
    base = {"name": "Staff", "description": "Employees", "vlan_mode": "id", "vlan_id": "40", "ruleset": "",
            "location": "3"}
    return {**base, **kw}


def test_parse_validation():
    f, errs = F.parse(form(name="bad/name", vlan_id="5000", tc_enabled="1", down="2000", down_unit="1"),
                      existing_names=set(), published=set(), creating=True, locations={3: "x"})
    assert len(errs) == 3
    _, errs = F.parse(form(name="test"), existing_names={"test"}, published=set(), creating=True, locations={3: "x"})
    assert errs == ["A role profile named test already exists."]
    _, errs = F.parse(form(ruleset="nope"), existing_names=set(), published=set(), creating=True, locations={3: "x"})
    assert "nope has no published version." in errs[0]
    f, errs = F.parse(form(description="hi ruleset:sneaky"), existing_names=set(), published=set(), creating=True,
                      locations={3: "x"})
    assert not errs and f["description"] == "hi"     # tags are managed through the rule set field only


async def test_create_with_ruleset(setup):
    portal, api, store = setup
    f, _ = F.parse(form(ruleset="basic-web", tc_enabled="1", down="20", down_unit="1", up="5", up_unit="1"),
                   existing_names=set(), published={"basic-web"}, creating=True, locations={3: "x"})
    run = store.get_run(await portal.create_role(f, "me"))
    assert run["results"][0]["ok"] == 1, run
    new = api.roles[run["results"][0]["template_id"]]
    assert new["templateName"] == "Staff" and new["vlanId"] == 40 and new["vlanEnabled"]
    assert new["description"] == "Employees ruleset:basic-web"
    assert new["trafficControlDownloadLimit"] == 20 and new["perUserTrafficControlEnabled"]
    assert R.fingerprint(R.from_role(new)) == R.fingerprint(store.versions("basic-web")[0]["content"])
    status = {r.role["templateName"]: r.status for r in await portal.role_rows()}
    assert status["Staff"] == "in_sync"


async def test_create_without_ruleset_has_firewall_off(setup):
    portal, api, store = setup
    f, _ = F.parse(form(vlan_mode="ssid"), existing_names=set(), published=set(), creating=True,
                   locations={3: "x"})
    run = store.get_run(await portal.create_role(f, "me"))
    new = api.roles[run["results"][0]["template_id"]]
    assert not new["firewallEnabled"] and not new["vlanEnabled"]


async def test_edit_keeps_rules_and_unlinks(setup):
    portal, api, store = setup
    before = R.from_role(api.roles[9])
    f = F.fields_from_role(api.roles[9])
    assert f["ruleset"] == "basic-web" and f["description"] == "Demo B" and f["vlan_mode"] == "id"
    f.update(name="Demo-Sync-B2", vlan_id="25", ruleset="")
    run = store.get_run(await portal.update_role(9, 3, f, "me"))
    assert run["results"][0]["ok"] == 1, run
    role = api.roles[9]
    assert role["templateName"] == "Demo-Sync-B2" and role["vlanId"] == 25 and role["description"] == "Demo B"
    assert R.fingerprint(R.from_role(role)) == R.fingerprint(before)


async def test_edit_links_new_ruleset(setup):
    portal, api, store = setup
    f = F.fields_from_role(api.roles[10])
    f["ruleset"] = "iot-lockdown"
    run = store.get_run(await portal.update_role(10, 3, f, "me"))
    assert run["results"][0]["ok"] == 1
    assert R.tags_of(api.roles[10]) == ["iot-lockdown"] and api.roles[10]["firewallEnabled"]


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


def test_create_edit_delete_pages(client):
    c, api = client
    page = c.get("/roles/new").text
    token = csrf_of(page)
    assert "Sharan&#x27;s Home" in page and "Basement" not in page     # floors aren't offered
    bad = c.post("/roles/new", data={"csrf": token, "name": "", "location": "3", "vlan_mode": "ssid"})
    assert bad.status_code == 400 and "Enter a name" in bad.text
    ok = c.post("/roles/new", data={"csrf": token, "name": "Contractors", "location": "3", "vlan_mode": "untagged",
                                    "ruleset": "basic-web", "description": ""})
    assert "Created and verified" in ok.text
    edit = c.get("/roles/9/edit?loc=3").text
    assert 'value="Demo B"' in edit and 'value="20"' in edit
    saved = c.post("/roles/9/edit", data={"csrf": token, "loc": "3", "name": "Demo-Sync-B", "description": "Lab",
                                          "vlan_mode": "id", "vlan_id": "21", "ruleset": "basic-web"})
    assert "Saved and verified" in saved.text and api.roles[9]["vlanId"] == 21
    assert api.roles[9]["description"] == "Lab ruleset:basic-web"
    confirm = c.get("/roles/7/delete?loc=3").text
    assert "IoT-A" in confirm and "can't be deleted" in confirm
    gone = c.post("/roles/10/delete", data={"csrf": token, "loc": "3"})
    assert "Deleted Guest" in gone.text and 10 not in api.roles


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
