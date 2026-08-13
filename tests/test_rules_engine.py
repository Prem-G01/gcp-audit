from __future__ import annotations

import pytest

from src.models import EnrichedEvent
from src.rules import engine

RULE_IDS = [
    "iam_policy_change",
    "service_account_key_created",
    "org_policy_modified",
    "firewall_open_to_internet",
    "public_iam_grant",
    "audit_config_changed",
    "unclassified_admin_activity",
    "federated_identity_action",
    "project_created",
    "billing_account_changed",
    "resource_created",
    "resource_deleted",
]


def _write_rules(tmp_path, body: str, *, defaults: str = "") -> object:
    content = f"version: 1\n{defaults}\nrules:\n{body}\n"
    path = tmp_path / "rules.yaml"
    path.write_text(content, encoding="utf-8")
    return path


def _single_rule_condition(tmp_path, match_yaml: str):
    """Load a single rule with the given `match:` block and return its compiled condition."""
    body = (
        "  - id: r1\n"
        "    title: t\n"
        "    severity: HIGH\n"
        f"{match_yaml}\n"
    )
    rules = engine.load_rules(path=_write_rules(tmp_path, body))
    return rules[0].match


# --- operator semantics -----------------------------------------------------


def test_operator_equals_direct(tmp_path) -> None:
    cond = _single_rule_condition(tmp_path, "    match: {field: method_name, op: equals, value: X}")
    assert engine._match(EnrichedEvent(method_name="X"), cond) is True
    assert engine._match(EnrichedEvent(method_name="Y"), cond) is False


def test_operator_equals_numeric_string_coercion(tmp_path) -> None:
    cond = _single_rule_condition(tmp_path, "    match: {field: severity, op: equals, value: 8080}")
    assert engine._match(EnrichedEvent(severity="8080"), cond) is True
    assert engine._match(EnrichedEvent(severity="8081"), cond) is False


def test_operator_equals_bool_string_coercion(tmp_path) -> None:
    cond = _single_rule_condition(tmp_path, "    match: {field: enrichment_ok, op: equals, value: 'true'}")
    assert engine._match(EnrichedEvent(enrichment_ok=True), cond) is True
    assert engine._match(EnrichedEvent(enrichment_ok=False), cond) is False


def test_operator_equals_none_vs_string_none_does_not_match(tmp_path) -> None:
    cond = _single_rule_condition(tmp_path, "    match: {field: method_name, op: equals, value: 'None'}")
    # method_name is genuinely None on this event, but the path still resolves
    # (found=True) since EnrichedEvent always has the attribute.
    assert engine._match(EnrichedEvent(method_name=None), cond) is False


def test_operator_not_equals(tmp_path) -> None:
    cond = _single_rule_condition(tmp_path, "    match: {field: method_name, op: not_equals, value: X}")
    assert engine._match(EnrichedEvent(method_name="Y"), cond) is True
    assert engine._match(EnrichedEvent(method_name="X"), cond) is False


def test_operator_contains_string(tmp_path) -> None:
    cond = _single_rule_condition(tmp_path, "    match: {field: method_name, op: contains, value: Set}")
    assert engine._match(EnrichedEvent(method_name="SetIamPolicy"), cond) is True
    assert engine._match(EnrichedEvent(method_name="GetIamPolicy"), cond) is False


def test_operator_contains_nested_structure(tmp_path) -> None:
    cond = _single_rule_condition(tmp_path, "    match: {field: raw, op: contains, value: allUsers}")
    event = EnrichedEvent(
        raw={"protoPayload": {"request": {"bindings": [{"role": "roles/viewer", "members": ["allUsers"]}]}}}
    )
    assert engine._match(event, cond) is True


def test_operator_contains_does_not_match_dict_keys(tmp_path) -> None:
    cond = _single_rule_condition(tmp_path, "    match: {field: raw, op: contains, value: allUsers}")
    event = EnrichedEvent(raw={"allUsersOptOut": "unrelated-value"})
    assert engine._match(event, cond) is False


def test_operator_not_contains(tmp_path) -> None:
    cond = _single_rule_condition(tmp_path, "    match: {field: method_name, op: not_contains, value: Set}")
    assert engine._match(EnrichedEvent(method_name="GetIamPolicy"), cond) is True
    assert engine._match(EnrichedEvent(method_name="SetIamPolicy"), cond) is False


def test_operator_starts_with(tmp_path) -> None:
    cond = _single_rule_condition(tmp_path, "    match: {field: method_name, op: starts_with, value: Set}")
    assert engine._match(EnrichedEvent(method_name="SetIamPolicy"), cond) is True
    assert engine._match(EnrichedEvent(method_name="GetSetIamPolicy"), cond) is False


def test_operator_ends_with(tmp_path) -> None:
    cond = _single_rule_condition(tmp_path, "    match: {field: method_name, op: ends_with, value: Policy}")
    assert engine._match(EnrichedEvent(method_name="SetIamPolicy"), cond) is True
    assert engine._match(EnrichedEvent(method_name="SetIamPolicyX"), cond) is False


def test_operator_in(tmp_path) -> None:
    cond = _single_rule_condition(tmp_path, "    match: {field: method_name, op: in, value: [A, B]}")
    assert engine._match(EnrichedEvent(method_name="A"), cond) is True
    assert engine._match(EnrichedEvent(method_name="C"), cond) is False


def test_operator_not_in(tmp_path) -> None:
    cond = _single_rule_condition(tmp_path, "    match: {field: method_name, op: not_in, value: [A, B]}")
    assert engine._match(EnrichedEvent(method_name="C"), cond) is True
    assert engine._match(EnrichedEvent(method_name="A"), cond) is False


def test_operator_regex_search_unanchored(tmp_path) -> None:
    cond = _single_rule_condition(tmp_path, r'    match: {field: method_name, op: regex, value: "^Set.*Policy$"}')
    assert engine._match(EnrichedEvent(method_name="SetIamPolicy"), cond) is True
    assert engine._match(EnrichedEvent(method_name="GetIamPolicy"), cond) is False


def test_operator_exists(tmp_path) -> None:
    cond = _single_rule_condition(tmp_path, "    match: {field: method_name, op: exists}")
    assert engine._match(EnrichedEvent(method_name="X"), cond) is True
    assert engine._match(EnrichedEvent(method_name=None), cond) is True  # attribute exists, value is None
    cond_deep = _single_rule_condition(tmp_path, "    match: {field: raw.missing.deep, op: exists}")
    assert engine._match(EnrichedEvent(raw={}), cond_deep) is False


def test_operator_not_exists(tmp_path) -> None:
    cond = _single_rule_condition(tmp_path, "    match: {field: raw.missing.deep, op: not_exists}")
    assert engine._match(EnrichedEvent(raw={}), cond) is True
    assert engine._match(EnrichedEvent(raw={"missing": {"deep": 1}}), cond) is False


def test_missing_path_is_non_match_for_every_operator_except_not_exists(tmp_path) -> None:
    event = EnrichedEvent(raw={})
    for op, value in [
        ("equals", "x"),
        ("not_equals", "x"),
        ("contains", "x"),
        ("not_contains", "x"),
        ("starts_with", "x"),
        ("ends_with", "x"),
        ("in", ["x"]),
        ("not_in", ["x"]),
        ("regex", "x"),
    ]:
        cond = _single_rule_condition(tmp_path, f"    match: {{field: raw.nope, op: {op}, value: {value!r}}}")
        assert engine._match(event, cond) is False, op
    exists_cond = _single_rule_condition(tmp_path, "    match: {field: raw.nope, op: exists}")
    assert engine._match(event, exists_cond) is False
    not_exists_cond = _single_rule_condition(tmp_path, "    match: {field: raw.nope, op: not_exists}")
    assert engine._match(event, not_exists_cond) is True


# --- condition tree nesting --------------------------------------------------


def test_all_of(tmp_path) -> None:
    cond = _single_rule_condition(
        tmp_path,
        "    match:\n"
        "      all_of:\n"
        "        - {field: method_name, op: equals, value: A}\n"
        "        - {field: severity, op: equals, value: B}\n",
    )
    assert engine._match(EnrichedEvent(method_name="A", severity="B"), cond) is True
    assert engine._match(EnrichedEvent(method_name="A", severity="C"), cond) is False


def test_any_of(tmp_path) -> None:
    cond = _single_rule_condition(
        tmp_path,
        "    match:\n"
        "      any_of:\n"
        "        - {field: method_name, op: equals, value: A}\n"
        "        - {field: method_name, op: equals, value: B}\n",
    )
    assert engine._match(EnrichedEvent(method_name="A"), cond) is True
    assert engine._match(EnrichedEvent(method_name="B"), cond) is True
    assert engine._match(EnrichedEvent(method_name="C"), cond) is False


def test_not(tmp_path) -> None:
    cond = _single_rule_condition(
        tmp_path, "    match:\n      not:\n        field: method_name\n        op: equals\n        value: A\n"
    )
    assert engine._match(EnrichedEvent(method_name="A"), cond) is False
    assert engine._match(EnrichedEvent(method_name="B"), cond) is True


def test_nested_all_of_any_of_not(tmp_path) -> None:
    cond = _single_rule_condition(
        tmp_path,
        "    match:\n"
        "      all_of:\n"
        "        - any_of:\n"
        "            - {field: method_name, op: equals, value: A}\n"
        "            - {field: method_name, op: equals, value: B}\n"
        "        - not:\n"
        "            field: severity\n"
        "            op: equals\n"
        "            value: EXCLUDE\n",
    )
    assert engine._match(EnrichedEvent(method_name="A", severity="OK"), cond) is True
    assert engine._match(EnrichedEvent(method_name="A", severity="EXCLUDE"), cond) is False
    assert engine._match(EnrichedEvent(method_name="C", severity="OK"), cond) is False


# --- evaluate_rules() generic behaviour (isolated from the real rules.yaml) -


def _make_rule(tmp_path, rule_yaml: str):
    path = _write_rules(tmp_path, rule_yaml)
    return engine.load_rules(path=path)


def test_disabled_rules_are_skipped(tmp_path, monkeypatch) -> None:
    rules = _make_rule(
        tmp_path,
        "  - id: disabled_rule\n"
        "    title: t\n"
        "    severity: HIGH\n"
        "    enabled: false\n"
        "    match: {field: method_name, op: exists}\n",
    )
    monkeypatch.setattr(engine, "_RULES", rules)
    findings = engine.evaluate_rules(EnrichedEvent(method_name="anything"))
    assert findings == []


def test_field_extraction(tmp_path, monkeypatch) -> None:
    rules = _make_rule(
        tmp_path,
        "  - id: r1\n"
        "    title: t\n"
        "    severity: HIGH\n"
        "    match: {field: method_name, op: exists}\n"
        "    fields:\n"
        "      Principal: principal_email\n"
        "      Missing: raw.does.not.exist\n",
    )
    monkeypatch.setattr(engine, "_RULES", rules)
    findings = engine.evaluate_rules(EnrichedEvent(method_name="X", principal_email="a@b.com"))
    assert len(findings) == 1
    assert findings[0].fields == {"Principal": "a@b.com"}  # unresolved path omitted entirely


def test_console_url_rendering_and_encoding(tmp_path, monkeypatch) -> None:
    rules = _make_rule(
        tmp_path,
        "  - id: r1\n"
        "    title: t\n"
        "    severity: HIGH\n"
        "    console_url_template: 'https://console.cloud.google.com/x?project={project_id}&r={resource_name}'\n"
        "    match: {field: method_name, op: exists}\n",
    )
    monkeypatch.setattr(engine, "_RULES", rules)
    event = EnrichedEvent(method_name="X", project_id="proj a", resource_name="res/with/slash")
    findings = engine.evaluate_rules(event)
    assert findings[0].console_url == "https://console.cloud.google.com/x?project=proj%20a&r=res%2Fwith%2Fslash"


def test_evaluate_rules_never_raises_on_bad_rule_evaluation(tmp_path, monkeypatch) -> None:
    rules = _make_rule(
        tmp_path,
        "  - id: ok_rule\n"
        "    title: t\n"
        "    severity: HIGH\n"
        "    match: {field: method_name, op: exists}\n",
    )
    # Force _match to raise for this test to prove evaluate_rules degrades gracefully.
    monkeypatch.setattr(engine, "_RULES", rules)
    monkeypatch.setattr(engine, "_match", lambda event, cond: (_ for _ in ()).throw(RuntimeError("boom")))
    findings = engine.evaluate_rules(EnrichedEvent(method_name="X"))
    assert findings == []


# --- shipped config/rules.yaml: every rule exercised by a fixture ----------


@pytest.mark.parametrize(
    ("fixture_name", "expected_rule_id"),
    [
        ("set_iam_policy.json", "iam_policy_change"),
        ("service_account_key_creation.json", "service_account_key_created"),
        ("org_policy_update.json", "org_policy_modified"),
        ("firewall_open_internet.json", "firewall_open_to_internet"),
        ("public_iam_grant.json", "public_iam_grant"),
        ("audit_config_change.json", "audit_config_changed"),
        ("unclassified_admin_activity.json", "unclassified_admin_activity"),
        ("federated_identity_action.json", "federated_identity_action"),
        ("project_created.json", "project_created"),
        ("billing_account_changed.json", "billing_account_changed"),
        ("resource_created.json", "resource_created"),
        ("resource_deleted.json", "resource_deleted"),
    ],
)
def test_shipped_rule_matches_its_fixture(load_fixture, fixture_name, expected_rule_id) -> None:
    event = EnrichedEvent.from_log_entry(load_fixture(fixture_name))
    findings = engine.evaluate_rules(event)
    matched_ids = {f.rule_id for f in findings}
    assert expected_rule_id in matched_ids


def test_resource_created_excludes_cloud_build_create_build(load_fixture) -> None:
    """Cloud Build kicks off a CreateBuild for every deploy this repo's own
    scripts/CI trigger -- routine CI/CD noise, not a security-relevant
    resource creation, and its Build.substitutions map would otherwise dump
    dozens of GOOGLE_* build env vars into the alert email as noise.
    """
    event = EnrichedEvent.from_log_entry(load_fixture("cloudbuild_create_build.json"))
    findings = engine.evaluate_rules(event)
    assert findings == []


def test_unclassified_admin_activity_excludes_own_terraform_deploy(load_fixture) -> None:
    """This platform's own Terraform-driven deploys call UpdateFunction on
    this very function every apply -- routine and expected from the known
    deploy SA, so it shouldn't self-alert every time we ship a change.
    """
    event = EnrichedEvent.from_log_entry(load_fixture("terraform_deploy_update_function.json"))
    findings = engine.evaluate_rules(event)
    assert "unclassified_admin_activity" not in {f.rule_id for f in findings}


def test_unclassified_admin_activity_still_fires_for_update_function_from_other_principal(load_fixture) -> None:
    """The deploy-SA exclusion above must be scoped to that SA specifically,
    not to the UpdateFunction method name generally -- the same call from
    any other principal (e.g. a compromised credential modifying this
    function's code) is exactly the case this rule exists to catch.
    """
    event = EnrichedEvent.from_log_entry(load_fixture("unexpected_update_function.json"))
    findings = engine.evaluate_rules(event)
    assert "unclassified_admin_activity" in {f.rule_id for f in findings}


def test_every_shipped_rule_id_is_covered_by_the_parametrized_test() -> None:
    covered = {
        "iam_policy_change",
        "service_account_key_created",
        "org_policy_modified",
        "firewall_open_to_internet",
        "public_iam_grant",
        "audit_config_changed",
        "unclassified_admin_activity",
        "federated_identity_action",
        "project_created",
        "billing_account_changed",
        "resource_created",
        "resource_deleted",
    }
    assert covered == set(RULE_IDS)
    assert {rule.id for rule in engine._RULES} == set(RULE_IDS)


def test_requires_ai_analysis() -> None:
    assert engine.requires_ai_analysis("org_policy_modified") is True
    assert engine.requires_ai_analysis("public_iam_grant") is True
    assert engine.requires_ai_analysis("audit_config_changed") is True
    assert engine.requires_ai_analysis("federated_identity_action") is True
    assert engine.requires_ai_analysis("project_created") is True
    assert engine.requires_ai_analysis("billing_account_changed") is True
    assert engine.requires_ai_analysis("service_account_key_created") is False
    assert engine.requires_ai_analysis("iam_policy_change") is False
    assert engine.requires_ai_analysis("firewall_open_to_internet") is False
    assert engine.requires_ai_analysis("unclassified_admin_activity") is False
    assert engine.requires_ai_analysis("resource_created") is False
    assert engine.requires_ai_analysis("resource_deleted") is False
    assert engine.requires_ai_analysis("no_such_rule") is False


# --- load-time validation error paths ---------------------------------------


def test_top_level_must_be_mapping(tmp_path) -> None:
    path = tmp_path / "rules.yaml"
    path.write_text("- not\n- a\n- mapping\n", encoding="utf-8")
    with pytest.raises(engine.RuleConfigError, match="mapping"):
        engine.load_rules(path=path)


def test_missing_version(tmp_path) -> None:
    path = tmp_path / "rules.yaml"
    path.write_text("rules: []\n", encoding="utf-8")
    with pytest.raises(engine.RuleConfigError, match="version"):
        engine.load_rules(path=path)


def test_defaults_must_be_mapping(tmp_path) -> None:
    path = tmp_path / "rules.yaml"
    path.write_text("version: 1\ndefaults: [1, 2]\nrules: []\n", encoding="utf-8")
    with pytest.raises(engine.RuleConfigError, match="defaults"):
        engine.load_rules(path=path)


def test_rules_must_be_non_empty_list(tmp_path) -> None:
    path = tmp_path / "rules.yaml"
    path.write_text("version: 1\nrules: []\n", encoding="utf-8")
    with pytest.raises(engine.RuleConfigError, match="non-empty list"):
        engine.load_rules(path=path)


def test_unknown_top_level_rule_key(tmp_path) -> None:
    body = (
        "  - id: r1\n    title: t\n    severity: HIGH\n    bogus_key: 1\n"
        "    match: {field: method_name, op: exists}\n"
    )
    with pytest.raises(engine.RuleConfigError, match="unknown key"):
        engine.load_rules(path=_write_rules(tmp_path, body))


def test_missing_required_id(tmp_path) -> None:
    body = "  - title: t\n    severity: HIGH\n    match: {field: method_name, op: exists}\n"
    with pytest.raises(engine.RuleConfigError, match="'id'"):
        engine.load_rules(path=_write_rules(tmp_path, body))


def test_missing_required_title(tmp_path) -> None:
    body = "  - id: r1\n    severity: HIGH\n    match: {field: method_name, op: exists}\n"
    with pytest.raises(engine.RuleConfigError, match="'title'"):
        engine.load_rules(path=_write_rules(tmp_path, body))


def test_missing_required_match(tmp_path) -> None:
    body = "  - id: r1\n    title: t\n    severity: HIGH\n"
    with pytest.raises(engine.RuleConfigError, match="'match'"):
        engine.load_rules(path=_write_rules(tmp_path, body))


def test_invalid_severity(tmp_path) -> None:
    body = "  - id: r1\n    title: t\n    severity: NOT_A_SEVERITY\n    match: {field: method_name, op: exists}\n"
    with pytest.raises(engine.RuleConfigError, match="invalid severity"):
        engine.load_rules(path=_write_rules(tmp_path, body))


def test_duplicate_rule_id(tmp_path) -> None:
    body = (
        "  - id: dup\n    title: t\n    severity: HIGH\n    match: {field: method_name, op: exists}\n"
        "  - id: dup\n    title: t2\n    severity: HIGH\n    match: {field: method_name, op: exists}\n"
    )
    with pytest.raises(engine.RuleConfigError, match="duplicate"):
        engine.load_rules(path=_write_rules(tmp_path, body))


def test_unknown_operator(tmp_path) -> None:
    body = "  - id: r1\n    title: t\n    severity: HIGH\n    match: {field: method_name, op: bogus_op, value: x}\n"
    with pytest.raises(engine.RuleConfigError, match="unknown operator"):
        engine.load_rules(path=_write_rules(tmp_path, body))


def test_uncompilable_regex(tmp_path) -> None:
    body = (
        "  - id: r1\n    title: t\n    severity: HIGH\n"
        "    match: {field: method_name, op: regex, value: '('}\n"
    )
    with pytest.raises(engine.RuleConfigError, match="invalid regex"):
        engine.load_rules(path=_write_rules(tmp_path, body))


def test_regex_requires_string_value(tmp_path) -> None:
    body = "  - id: r1\n    title: t\n    severity: HIGH\n    match: {field: method_name, op: regex, value: 5}\n"
    with pytest.raises(engine.RuleConfigError, match="regex"):
        engine.load_rules(path=_write_rules(tmp_path, body))


def test_in_requires_list_value(tmp_path) -> None:
    body = "  - id: r1\n    title: t\n    severity: HIGH\n    match: {field: method_name, op: in, value: x}\n"
    with pytest.raises(engine.RuleConfigError, match="list"):
        engine.load_rules(path=_write_rules(tmp_path, body))


def test_operator_requires_value(tmp_path) -> None:
    body = "  - id: r1\n    title: t\n    severity: HIGH\n    match: {field: method_name, op: equals}\n"
    with pytest.raises(engine.RuleConfigError, match="requires a 'value'"):
        engine.load_rules(path=_write_rules(tmp_path, body))


def test_unknown_condition_key(tmp_path) -> None:
    body = "  - id: r1\n    title: t\n    severity: HIGH\n    match: {field: method_name, op: exists, bogus: 1}\n"
    with pytest.raises(engine.RuleConfigError, match="unknown condition key"):
        engine.load_rules(path=_write_rules(tmp_path, body))


def test_condition_mixes_structural_and_leaf_keys(tmp_path) -> None:
    body = (
        "  - id: r1\n    title: t\n    severity: HIGH\n"
        "    match:\n"
        "      all_of: [{field: method_name, op: exists}]\n"
        "      field: method_name\n"
    )
    with pytest.raises(engine.RuleConfigError, match="mixes structural key"):
        engine.load_rules(path=_write_rules(tmp_path, body))


def test_all_of_must_be_non_empty_list(tmp_path) -> None:
    body = "  - id: r1\n    title: t\n    severity: HIGH\n    match: {all_of: []}\n"
    with pytest.raises(engine.RuleConfigError, match="non-empty list"):
        engine.load_rules(path=_write_rules(tmp_path, body))


def test_fields_must_be_string_to_string_mapping(tmp_path) -> None:
    body = (
        "  - id: r1\n    title: t\n    severity: HIGH\n"
        "    match: {field: method_name, op: exists}\n"
        "    fields: {Principal: 1}\n"
    )
    with pytest.raises(engine.RuleConfigError, match="'fields'"):
        engine.load_rules(path=_write_rules(tmp_path, body))


def test_console_url_template_unknown_placeholder(tmp_path) -> None:
    body = (
        "  - id: r1\n    title: t\n    severity: HIGH\n"
        "    console_url_template: 'https://example.com/{typo_placeholder}'\n"
        "    match: {field: method_name, op: exists}\n"
    )
    with pytest.raises(engine.RuleConfigError, match="unknown placeholder"):
        engine.load_rules(path=_write_rules(tmp_path, body))


def test_real_config_rules_yaml_loads_without_raising() -> None:
    rules = engine.load_rules()
    assert len(rules) == 12
    assert {rule.id for rule in rules} == set(RULE_IDS)
