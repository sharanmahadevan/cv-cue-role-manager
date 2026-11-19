import re

import pytest
from starlette.testclient import TestClient

from cvcue_roles.config import Settings
from cvcue_roles.mock import MockCvcue
from cvcue_roles.web.app import create_app


def make(tmp_path, **kw):
    cfg = Settings(mock=True, dev_login=True, db_path=str(tmp_path / "a.db"), session_secret="s", **kw)
    api = MockCvcue()
    return TestClient(create_app(cfg, api)), api


def csrf_of(html: str) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


@pytest.fixture
def client(tmp_path):
    c, api = make(tmp_path)
    c.post("/auth/dev", data={"email": "dev@localhost", "next": "/roles"})
    return c, api


def test_requires_sign_in(tmp_path):
    c, _ = make(tmp_path)
    r = c.get("/roles", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login")
    assert c.get("/healthz").json() == {"ok": True}


def test_google_allowlist(tmp_path):
    cfg = Settings(allowed_emails=("@arista.com", "me@gmail.com"))
    assert cfg.email_allowed("a@arista.com") and cfg.email_allowed("ME@gmail.com")
    assert not cfg.email_allowed("x@gmail.com") and not cfg.email_allowed("a@notarista.com")


def test_roles_page_lists_status(client):
    c, _ = client
    html = c.get("/roles").text
    assert "Demo-Sync-B" in html and "Edited in CV-CUE" in html and "Not managed" in html
    assert "basic-web</b> has unpublished changes" in html


def test_post_without_csrf_is_rejected(client):
    c, api = client
    r = c.post("/rulesets/basic-web/edit", data={"op": "delete", "i": "0"})
    assert r.status_code == 400


def test_edit_review_publish(client):
    c, api = client
    page = c.get("/rulesets/basic-web").text
    token = csrf_of(page)
    r = c.post("/rulesets/basic-web/edit", data={"csrf": token, "op": "add", "name": "Allow-SSH", "direction": "2",
                                                  "protocol": "1", "port": "22", "action": "1"})
    assert r.status_code == 200 and "Allow-SSH" in r.text
    bad = c.post("/rulesets/basic-web/edit", data={"csrf": token, "op": "add", "name": "", "protocol": "1",
                                                    "port": "99999", "action": "1"})
    assert "Enter a rule name." in bad.text
    review = c.get("/rulesets/basic-web/review").text
    assert "updates 2 of 2 linked role profile(s)" in review and "Allow-SSH" in review
    plan_token = re.search(r'name="token" value="([^"]+)"', review).group(1)
    done = c.post("/rulesets/basic-web/publish", data={"csrf": token, "token": plan_token})
    assert "v2: 2 updated" in done.text
    names = [e["name"] for e in api.roles[8]["firewallProfile"]]
    assert names == ["Allow-DNS", "Allow-DHCP", "Allow-HTTP", "Allow-HTTPS", "Allow-8443", "Allow-SSH", ""]
    assert "In sync · v2" in c.get("/roles").text


def test_role_page_revert_and_link(client):
    c, api = client
    page = c.get("/roles/7?loc=3").text
    assert "Out of sync with iot-lockdown v1" in page and "Allow-Any-TCP" in page
    token = csrf_of(page)
    r = c.post("/roles/7/revert", data={"csrf": token, "loc": "3"})
    assert "Reverted Test to v1" in r.text
    link = c.get("/roles/10/link?loc=3&ruleset=basic-web").text
    assert "firewall: off → on" in link
    r = c.post("/roles/10/link", data={"csrf": token, "loc": "3", "ruleset": "basic-web"})
    assert "Linked Guest to v1" in r.text and api.roles[10]["description"].endswith("ruleset:basic-web")


def test_create_from_role_and_export(client):
    c, _ = client
    token = csrf_of(c.get("/rulesets").text)
    r = c.post("/rulesets", data={"csrf": token, "name": "from-test", "source": "role:7:3"})
    assert "Allow-MQTT-TLS" in r.text
    exported = c.get("/rulesets/from-test/export?which=draft").json()
    assert exported["name"] == "from-test" and exported["firewallProfile"][-1]["defaultRule"]


def test_rule_form_fields_follow_protocol(client):
    c, api = client
    html = c.get("/rulesets/basic-web").text
    assert 'data-show="tcpudp" style="grid-area:1/3">Port' in html and '>Direction<select' in html
    assert '<span>Protocol number' in html and "[0-254]" in html
    token = csrf_of(html)
    # "Any" saves with no port and direction "any" even if hidden fields were sent
    c.post("/rulesets/basic-web/edit", data={"csrf": token, "op": "add", "name": "Allow-Https", "protocol": "0",
                                              "host": "*", "port": "443", "direction": "1", "action": "1"})
    c.post("/rulesets/basic-web/edit", data={"csrf": token, "op": "add", "name": "GRE", "protocol": "other",
                                              "protocol_number": "47", "action": "1"})
    store = c.app.state.store
    rules = store.get_ruleset("basic-web")["draft"]["rules"]
    assert (rules[-2]["protocol"], rules[-2]["port"], rules[-2]["direction"]) == (0, "", 0)
    assert (rules[-1]["protocol"], rules[-1]["port"], rules[-1]["direction"]) == (50, "", 0)
    edit = c.get(f"/rulesets/basic-web?edit={len(rules) - 1}").text
    assert '<option value="other" selected>Other</option>' in edit and 'value="47"' in edit
