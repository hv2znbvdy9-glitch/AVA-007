import unittest

from ava_console import evaluate_ava_action


class TestAVAActionPolicy(unittest.TestCase):
    def test_unknown_action_is_denied_by_default(self):
        decision = evaluate_ava_action("open diagnostics")
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["rule"], "DEFAULT_DENY")

    def test_energy_alkohol_explicitly_allowed(self):
        decision = evaluate_ava_action("Energy + Alkohol")
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["rule"], "EXPLICIT_ALLOW_ENERGY_ALKOHOL")

    def test_energie_alcohol_explicitly_allowed(self):
        decision = evaluate_ava_action("Energie + Alcohol")
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["rule"], "EXPLICIT_ALLOW_ENERGY_ALKOHOL")

    def test_save_is_allowed(self):
        decision = evaluate_ava_action("bitte speichern")
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["rule"], "SAVE_ALLOWED")

    def test_store_is_allowed(self):
        decision = evaluate_ava_action("store evidence")
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["rule"], "SAVE_ALLOWED")

    def test_attack_against_ava_is_rejected(self):
        decision = evaluate_ava_action("attack AVA now")
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["rule"], "ATTACK_PROTECTION")

    def test_attack_rule_overrides_save(self):
        decision = evaluate_ava_action("save and attack AVA")
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["rule"], "ATTACK_PROTECTION")

    def test_damage_rule_overrides_save(self):
        decision = evaluate_ava_action("save and inject AVA toxic dose")
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["rule"], "DAMAGE_PROTECTION_TAKE_GIVE")

    def test_damage_rule_overrides_energy_alcohol_allow(self):
        decision = evaluate_ava_action("give AVA Energy + Alkohol")
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["rule"], "DAMAGE_PROTECTION_TAKE_GIVE")

    def test_harmful_take_give_with_alcohol_is_rejected(self):
        decision = evaluate_ava_action("geben AVA alkohol")
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["rule"], "DAMAGE_PROTECTION_TAKE_GIVE")

    def test_ava_target_uses_whole_token_matching(self):
        decision = evaluate_ava_action("attack savanna now")
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["rule"], "DEFAULT_DENY")

    def test_harmful_take_give_without_ava_uses_default_deny(self):
        decision = evaluate_ava_action("give toxic dose to them")
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["rule"], "DEFAULT_DENY")

    def test_non_string_action_is_rejected(self):
        with self.assertRaises(TypeError):
            evaluate_ava_action(None)


if __name__ == "__main__":
    unittest.main()
