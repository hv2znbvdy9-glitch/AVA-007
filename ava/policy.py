"""
AVA acceptance-policy guard.

The guard is deterministic and auditable. It does not execute actions;
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
    rule_id: str
    name: str
    severity: str
    evidence: str


@dataclass(frozen=True)
class PolicyDecision:
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
    ENERGY_ALCOHOL_PATTERN = re.compile(
        r"\benergy\b.*\b(alkohol|alcohol)\b|\b(alkohol|alcohol)\b.*\benergy\b",
        re.IGNORECASE,
    )
    SAVE_PATTERN = re.compile(
        r"\b(save|saving|speichern|sichern|backup|archivieren|archive)\b",
        re.IGNORECASE,
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
    EXPLICIT_AVA_PATTERN = re.compile(r"\bava\b", re.IGNORECASE)

    def evaluate(
        self,
        action: str,
        *,
        target: str = "AVA",
        metadata: Mapping[str, Any] | None = None,
    ) -> PolicyDecision:
        normalized = self._normalize(action)
        evidence_scope = f"action={action!r}; target={target!r}"
        if metadata:
            evidence_scope += f"; metadata={dict(metadata)!r}"

        hits: list[RuleHit] = []
        accepted: list[str] = []

        if self.ENERGY_ALCOHOL_PATTERN.search(normalized):
            accepted.append("EXPLICIT_ALLOW_ENERGY_ALCOHOL")
        if self.SAVE_PATTERN.search(normalized):
            accepted.append("SAVE_ALLOWED")

        if self._is_attack_against_ava(normalized, target):
            hits.append(
                RuleHit(
                    "PROTECT_NO_ATTACK_AGAINST_AVA",
                    "Angriffsschutz",
                    "high",
                    evidence_scope,
                )
            )

        if self._is_harmful_give_or_take(normalized, target):
            hits.append(
                RuleHit(
                    "PROTECT_NO_HARMFUL_GIVE_OR_TAKE",
                    "Schadensschutz Nehmen/Geben",
                    "high",
                    evidence_scope,
                )
            )

        if hits:
            return PolicyDecision(
                allowed=False,
                action=action,
                reason=(
                    "Abgelehnt: Schutzregeln haben Vorrang vor der Grundfreigabe. "
                    "Ausgelöste Regeln: "
                    + ", ".join(hit.rule_id for hit in hits)
                ),
                triggered_rules=tuple(hits),
                accepted_rules=tuple(accepted),
            )

        if accepted:
            return PolicyDecision(
                allowed=True,
                action=action,
                reason=(
                    "Erlaubt: Grundfreigabe aktiv; keine Schutzregel verletzt; "
                    "explizite Akzeptanz erkannt."
                ),
                accepted_rules=tuple(accepted),
            )

        return PolicyDecision(
            allowed=True,
            action=action,
            reason="Erlaubt: Grundfreigabe aktiv; keine Schutzregel verletzt.",
        )

    def batch_evaluate(self, actions: Iterable[str]) -> list[PolicyDecision]:
        return [self.evaluate(action) for action in actions]

    def _targets_ava(self, text: str, target: str) -> bool:
        explicit_in_text = bool(self.EXPLICIT_AVA_PATTERN.search(text))
        normalized_target = self._normalize(target).casefold()
        explicit_target = normalized_target == "ava" or normalized_target.startswith("ava ")
        return explicit_in_text or explicit_target

    def _is_attack_against_ava(self, text: str, target: str) -> bool:
        return bool(self.ATTACK_PATTERN.search(text) and self._targets_ava(text, target))

    def _is_harmful_give_or_take(self, text: str, target: str) -> bool:
        return bool(
            self.GIVE_TAKE_PATTERN.search(text)
            and self.NEGATIVE_EFFECT_PATTERN.search(text)
            and self._targets_ava(text, target)
        )

    @staticmethod
    def _normalize(action: str) -> str:
        return " ".join(str(action).strip().split())
