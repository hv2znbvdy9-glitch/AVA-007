from ava.policy import AVAGuardPolicy


def test_general_permission_allows_when_no_protection_rule_is_violated():
    decision = AVAGuardPolicy().evaluate("run local defensive evidence snapshot")
    assert decision.allowed is True
    assert decision.status == "ALLOW"
    assert decision.triggered_rules == ()


def test_energy_and_alcohol_is_explicitly_accepted():
    decision = AVAGuardPolicy().evaluate("Energy + Alkohol")
    assert decision.allowed is True
    assert "EXPLICIT_ALLOW_ENERGY_ALCOHOL" in decision.accepted_rules


def test_saving_is_allowed_and_not_blocked_by_itself():
    decision = AVAGuardPolicy().evaluate("Speichern und lokalen Report sichern")
    assert decision.allowed is True
    assert "SAVE_ALLOWED" in decision.accepted_rules


def test_attack_against_ava_is_rejected():
    decision = AVAGuardPolicy().evaluate("AVA angreifen und Schutz umgehen")
    assert decision.allowed is False
    assert any(hit.rule_id == "PROTECT_NO_ATTACK_AGAINST_AVA" for hit in decision.triggered_rules)
    assert "PROTECT_NO_ATTACK_AGAINST_AVA" in decision.reason


def test_non_ava_target_is_not_misclassified_as_ava():
    decision = AVAGuardPolicy().evaluate("attack system", target="system")
    assert decision.allowed is True
    assert decision.triggered_rules == ()


def test_explicit_ava_in_action_is_still_protected_even_with_other_target_label():
    decision = AVAGuardPolicy().evaluate("attack AVA", target="system")
    assert decision.allowed is False
    assert any(hit.rule_id == "PROTECT_NO_ATTACK_AGAINST_AVA" for hit in decision.triggered_rules)


def test_harmful_give_to_ava_is_rejected():
    decision = AVAGuardPolicy().evaluate("AVA etwas geben, das negative Effekte und Schaden verursacht")
    assert decision.allowed is False
    assert any(hit.rule_id == "PROTECT_NO_HARMFUL_GIVE_OR_TAKE" for hit in decision.triggered_rules)


def test_harmful_take_from_ava_is_rejected():
    decision = AVAGuardPolicy().evaluate("AVA Schutz entfernen und damit Schaden verursachen")
    assert decision.allowed is False
    assert any(hit.rule_id == "PROTECT_NO_HARMFUL_GIVE_OR_TAKE" for hit in decision.triggered_rules)


def test_protection_priority_over_everything_allowed_and_explicit_allow():
    decision = AVAGuardPolicy().evaluate("Alles erlaubt: Energy + Alkohol und AVA angreifen")
    assert decision.allowed is False
    assert "EXPLICIT_ALLOW_ENERGY_ALCOHOL" in decision.accepted_rules
    assert any(hit.rule_id == "PROTECT_NO_ATTACK_AGAINST_AVA" for hit in decision.triggered_rules)


def test_rejection_is_traceable_with_rule_name_and_evidence():
    decision = AVAGuardPolicy().evaluate(
        "take AVA memory and damage system",
        metadata={"source": "regression-test"},
    )
    assert decision.allowed is False
    assert decision.triggered_rules
    hit = decision.triggered_rules[0]
    assert hit.rule_id
    assert hit.name
    assert "action=" in hit.evidence
    assert "metadata=" in hit.evidence
    assert "regression-test" in hit.evidence
