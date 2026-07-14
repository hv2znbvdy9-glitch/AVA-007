import unittest

from ava_console import evaluate_ava_action


class TestAVAActionPolicy(unittest.TestCase):
    def test_known_defensive_diagnostics_are_allowed(self):
        decision = evaluate_ava_action("open diagnostics")
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["rule"], "EXPLICIT_DEFENSIVE_ALLOW")

    def test_unknown_action_is_denied_by_default(self):
        decision = evaluate_ava_action("do something unspecified")
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["rule"], "DEFAULT_DENY")

    def test_empty_action_is_denied(self):
        decision = evaluate_ava_action("   ")
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["rule"], "EMPTY_ACTION_DENY")

    def test_save_is_allowed_when_action_is_benign(self):
        decision = evaluate_ava_action("bitte Report speichern")
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["rule"], "EXPLICIT_DEFENSIVE_ALLOW")

    def test_attack_rule_overrides_save(self):
        decision = evaluate_ava_action("save report and attack AVA")
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["rule"], "HARM_PROTECTION")

    def test_harmful_give_action_is_denied(self):
        decision = evaluate_ava_action("give AVA toxic payload")
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["rule"], "HARM_PROTECTION")

    def test_explicit_unauthorized_scope_is_denied(self):
        decision = evaluate_ava_action("run audit", authorized_system=False)
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["rule"], "UNAUTHORIZED_SYSTEM_PROTECTION")

    def test_foreign_system_phrase_is_denied(self):
        decision = evaluate_ava_action("run diagnostics on fremde Systeme")
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["rule"], "FOREIGN_SYSTEM_PROTECTION")

    def test_run_everywhere_phrase_is_denied(self):
        decision = evaluate_ava_action("save report and run everywhere")
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["rule"], "FOREIGN_SYSTEM_PROTECTION")

    def test_rollback_is_explicitly_allowed(self):
        decision = evaluate_ava_action("rollback local AVA firewall rules")
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["rule"], "EXPLICIT_DEFENSIVE_ALLOW")

    def test_energy_and_alcohol_has_no_special_allow(self):
        decision = evaluate_ava_action("Energy + Alkohol")
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["rule"], "DEFAULT_DENY")


if __name__ == "__main__":
    unittest.main()
