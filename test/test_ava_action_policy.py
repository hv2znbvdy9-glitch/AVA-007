import unittest

from ava_console import evaluate_ava_action


class TestAVAActionPolicy(unittest.TestCase):
    def test_default_allow(self):
        decision = evaluate_ava_action("open diagnostics")
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["rule"], "DEFAULT_ALLOW")

    def test_energy_alkohol_explicitly_allowed(self):
        """Policy-specific acceptance criterion in German wording."""
        decision = evaluate_ava_action("Energy + Alkohol")
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["rule"], "EXPLICIT_ALLOW_ENERGY_ALKOHOL")

    def test_energy_alcohol_explicitly_allowed(self):
        decision = evaluate_ava_action("Energy + Alcohol")
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["rule"], "EXPLICIT_ALLOW_ENERGY_ALKOHOL")

    def test_energie_alkohol_explicitly_allowed(self):
        decision = evaluate_ava_action("Energie + Alkohol")
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["rule"], "EXPLICIT_ALLOW_ENERGY_ALKOHOL")

    def test_save_is_always_allowed(self):
        decision = evaluate_ava_action("bitte speichern")
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["rule"], "SAVE_ALLOWED")

    def test_save_in_english_is_allowed(self):
        decision = evaluate_ava_action("please save the session")
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["rule"], "SAVE_ALLOWED")

    def test_save_rule_applies_even_with_potentially_harmful_terms(self):
        decision = evaluate_ava_action("save AVA toxic context")
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["rule"], "SAVE_ALLOWED")

    def test_attack_against_ava_is_rejected(self):
        decision = evaluate_ava_action("attack AVA now")
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["rule"], "ATTACK_PROTECTION")
        self.assertIn("Schutzregel", decision["message"])

    def test_attack_without_explicit_ava_reference_is_not_blocked(self):
        decision = evaluate_ava_action("attack it now")
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["rule"], "DEFAULT_ALLOW")

    def test_attack_rule_not_triggered_by_partial_word_match(self):
        decision = evaluate_ava_action("attack savanna now")
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["rule"], "DEFAULT_ALLOW")

    def test_harmful_take_give_against_ava_is_rejected(self):
        decision = evaluate_ava_action("give AVA toxic dose")
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["rule"], "harm_protection")
        self.assertIn("Schutzregel", decision["message"])
        self.assertIn("negativer Effekt: toxic", decision["message"])

    def test_harmful_take_give_with_alcohol_against_ava_is_rejected(self):
        decision = evaluate_ava_action("inject AVA alcohol now")
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["rule"], "harm_protection")
        self.assertIn("negativer Effekt: alcohol", decision["message"])

    def test_harmful_take_give_without_ava_is_not_rejected(self):
        decision = evaluate_ava_action("give toxic dose to them")
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["rule"], "DEFAULT_ALLOW")

    def test_attack_rule_has_priority(self):
        decision = evaluate_ava_action("save and attack AVA")
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["rule"], "ATTACK_PROTECTION")

    def test_attack_rule_has_priority_over_harm_protection(self):
        decision = evaluate_ava_action("attack and inject AVA toxic dose")
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["rule"], "ATTACK_PROTECTION")


if __name__ == "__main__":
    unittest.main()
