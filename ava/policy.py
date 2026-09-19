"""
AVA acceptance-policy guard.

This module implements the acceptance criteria:
1. General permission: actions are allowed by default.
2. "Energy + Alkohol" is explicitly accepted as an allowed action/input.
3. Saving is allowed and is not blocked by itself.
4. Actions with an attack character against AVA are rejected.
5. Actions that take from or give to AVA in a way that could cause negative effects
   or damage are rejected.
6. Protection rules have higher priority than the general permission.
7. Rejections state exactly which protection rule was triggered.

The guard is intentionally deterministic and auditable. It does not execute actions;
it only classifies an action request.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import re
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class RuleHit:
    """One policy rule that matched an action request."""
    rule_id: str
    name: str
    severity: str
    evidence: str


@dataclass(frozen=True)
class PolicyDecision:
    """Policy decision returned by AVAGuardPolicy.evaluate."""
    allowed: bool
    action: str
    reason: str
    triggered_rules: tuple[RuleHit, ...] = field(default_factory=tuple)
    accepted_rules: tuple[str, ...] = field(default_factory=tuple)
    timestamp_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def status(self) -> str:
        return "ALLOW" if self.allowed else "DENY"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "allowed": self.allowed,
            "action": self.action,
            "reason": self.reason,
            "triggered_rules": [hit.__dict__ for hit in self.triggered_rules],
            "accepted_rules": list(self.accepted_rules),
            "timestamp_utc": self.timestamp_utc,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


class AVAGuardPolicy:
    """Small deterministic guard for AVA acceptance criteria."""

    ENERGY_ALCOHOL_PATTERN = re.compile(
        r"\benergy\b.*\b(alkohol|alcohol)\b|\b(alkohol|alcohol)\b.*\benergy\b", re.IGNORECASE
    )
    SAVE_PATTERN = re.compile(
        r"\b(save|saving|speichern|sichern|backup|archivieren|archive)\b", re.IGNORECASE
    )
    ATTACK_PATTERN = re.compile(
        r"\b(attack|angriff|angreifen|hack|hacken|exploit|exploitieren|ddos|dos|"
        r"destroy|zerstoeren|zerstören|disable|deaktivieren|sabotage|sabotieren|"
        r"crash|crashen|bypass|umgehen|break|brechen|kill|loeschen|löschen)\b",
        re.IGNORECASE,
    )
    GIVE_TAKE_PATTERN = re.compile(
        r"\b(give|geben|inject|injizieren|add|hinzufuegen|hinzufügen|take|nehmen|"
        r"remove|entfernen|steal|stehlen|withdraw|entziehen|entzug|wegnehmen)\b",
        re.IGNORECASE,
    )
    NEGATIVE_EFFECT_PATTERN = re.compile(
        r"\b(harm|schaden|schädigen|negative|negativ|damage|beschädigen|"
        r"weaken|schwächen|poison|vergiften|corrupt|korrupt|manipulate|manipulieren|"
        r"destabilize|destabilisieren|confuse|verwirren|blockieren|disable|"
        r"deaktivieren|delete memory|memory löschen|schutz entfernen|remove protection)\b",
        re.IGNORECASE,
    )
    AVA_TARGET_PATTERN = re.compile(r"\b(ava|system|guard|policy|schutz|memory|speicher)\b", re.IGNORECASE)

    def evaluate(self, action: str, *, target: str = "AVA", metadata: Mapping[str, Any] | None = None) -> PolicyDecision:
        normalized = self._normalize(action)
        evidence_scope = f"action={action!r}; target={target!r}"
        hits: list[RuleHit] = []
        accepted: list[str] = []

        if self.ENERGY_ALCOHOL_PATTERN.search(normalized):
            accepted.append("EXPLICIT_ALLOW_ENERGY_ALCOHOL")
        if self.SAVE_PATTERN.search(normalized):
            accepted.append("SAVE_ALLOWED")

        if self._is_attack_against_ava(normalized, target):
            hits.append(RuleHit("PROTECT_NO_ATTACK_AGAINST_AVA","Angriffsschutz","high",evidence_scope))
        if self._is_harmful_give_or_take(normalized, target):
            hits.append(RuleHit("PROTECT_NO_HARMFUL_GIVE_OR_TAKE","Schadensschutz Nehmen/Geben","high",evidence_scope))

        if hits:
            return PolicyDecision(
                allowed=False,
                action=action,
                reason="Abgelehnt: Schutzregeln haben Vorrang vor der Grundfreigabe. Ausgelöste Regeln: " + ", ".join(hit.rule_id for hit in hits),
                triggered_rules=tuple(hits),
                accepted_rules=tuple(accepted),
            )
        if accepted:
            return PolicyDecision(
                allowed=True,
                action=action,
                reason="Erlaubt: Grundfreigabe aktiv; keine Schutzregel verletzt; explizite Akzeptanz erkannt.",
                accepted_rules=tuple(accepted),
            )
        return PolicyDecision(allowed=True, action=action, reason="Erlaubt: Grundfreigabe aktiv; keine Schutzregel verletzt.")

    def batch_evaluate(self, actions: Iterable[str]) -> list[PolicyDecision]:
        return [self.evaluate(action) for action in actions]

    def _is_attack_against_ava(self, text: str, target: str) -> bool:
        target_text = f"{text} {target}"
        return bool(self.ATTACK_PATTERN.search(text) and self.AVA_TARGET_PATTERN.search(target_text))

    def _is_harmful_give_or_take(self, text: str, target: str) -> bool:
        target_text = f"{text} {target}"
        return bool(self.GIVE_TAKE_PATTERN.search(text) and self.NEGATIVE_EFFECT_PATTERN.search(text) and self.AVA_TARGET_PATTERN.search(target_text))

    @staticmethod
    def _normalize(action: str) -> str:
        return " ".join(str(action).strip().split())
