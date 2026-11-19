from cvcue_roles import rules as R

# Shape CV-CUE returned on the live server after a POST (orderIds renumbered 1-based).
LIVE_ROLE = {
    "firewallEnabled": True,
    "description": "Demo B ruleset:basic-web",
    "firewallProfile": [
        {"hostName": "", "direction": 0, "protocol": 0, "action": 2, "port": "", "orderId": -1, "mncOid": 0,
         "markDirection": "TO_WIRELESS", "dscpValue": 0, "ssid": 9, "name": "", "oid": 43, "defaultRule": True},
        {"hostName": "", "direction": 2, "protocol": 1, "action": 1, "port": "80", "orderId": 3, "mncOid": 0,
         "markDirection": "TO_WIRELESS", "dscpValue": 0, "ssid": 9, "name": "Allow-HTTP", "oid": 46,
         "defaultRule": False},
        {"hostName": "", "direction": 2, "protocol": 2, "action": 1, "port": "53", "orderId": 1, "mncOid": 0,
         "markDirection": "TO_WIRELESS", "dscpValue": 0, "ssid": 9, "name": "Allow-DNS", "oid": 44,
         "defaultRule": False},
    ],
}


def test_from_role_orders_by_order_id_and_ignores_server_ids():
    c = R.from_role(LIVE_ROLE)
    assert [r["name"] for r in c["rules"]] == ["Allow-DNS", "Allow-HTTP"]
    assert c["default_action"] == 2


def test_round_trip_matches_regardless_of_order_id_base():
    c = R.from_role(LIVE_ROLE)
    sent = R.to_firewall_profile(c)          # 0-based, as PUT keeps them
    assert R.fingerprint(R.from_role({"firewallEnabled": True, "firewallProfile": sent})) == R.fingerprint(c)


def test_firewall_off_is_none():
    assert R.from_role({"firewallEnabled": False, "firewallProfile": []}) is None


def test_apply_to_role_keeps_other_settings():
    role = {**LIVE_ROLE, "vlanId": 20, "templateId": 9}
    body = R.apply_to_role(role, {"rules": [R.new_rule("X", 2, 1, "443", "", 1)], "default_action": 2})
    assert body["vlanId"] == 20 and body["templateId"] == 9 and body["firewallEnabled"]
    assert [e["name"] for e in body["firewallProfile"]] == ["X", ""]
    assert role["firewallProfile"][1]["name"] == "Allow-HTTP"     # original not mutated


def test_tags():
    assert R.tags_of(LIVE_ROLE) == ["basic-web"]
    assert R.set_tag("Demo B ruleset:basic-web", "iot") == "Demo B ruleset:iot"
    assert R.set_tag("Demo B ruleset:basic-web", None) == "Demo B"
    assert R.set_tag(None, "x") == "ruleset:x"


def test_diff_shows_added_rule_and_firewall_on():
    base = R.from_role(LIVE_ROLE)
    want = {"rules": base["rules"] + [R.new_rule("Allow-8443", 2, 1, "8443", "", 1)], "default_action": 2}
    changes = R.diff(base, want)
    assert changes == [("+", "#3 " + R.describe(want["rules"][2]))]
    assert R.diff(None, want)[0] == ("~", "firewall: off → on")


def test_rule_form_validation():
    rule, errs = R.rule_from_form({"name": "Web", "direction": "2", "protocol": "1", "port": "443", "action": "1"})
    assert not errs and rule["port"] == "443"
    _, errs = R.rule_from_form({"name": "", "protocol": "0", "port": "80", "action": "1"})
    assert "Enter a rule name." in errs and any("TCP or UDP" in e for e in errs)
    rule, errs = R.rule_from_form({"name": "GRE", "protocol": "other", "protocol_number": "47", "action": "1"})
    assert not errs and rule["protocol"] == 50
    _, errs = R.rule_from_form({"name": "x", "protocol": "1", "port": "70000", "action": "1"})
    assert errs


def test_import_formats():
    sync_file = {"firewallProfile": R.to_firewall_profile({"rules": [R.new_rule("A")], "default_action": 2})}
    assert R.content_from_import(sync_file)["rules"][0]["name"] == "A"
    assert R.content_from_import({"rules": [], "default_action": 1})["default_action"] == 1
