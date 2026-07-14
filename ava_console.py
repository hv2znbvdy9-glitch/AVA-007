"""
AVA SECURITY CONSOLE
====================
A defensive diagnostic state model for authorized local systems.

State scale: -3 (FAIL) to +3 (OPTIMAL)

Architecture:
    Measurement → Weighting → Domain Score → Total Score → Clamp(-3..+3) → State

Policy architecture:
    Scope check → Protection rules → Explicit defensive allowlist → Default deny
"""

from __future__ import annotations

import random
import re
import time
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# State definitions
# ---------------------------------------------------------------------------

STATE_LABELS = {
    -3: "FAIL",
    -2: "CRITICAL",
    -1: "WATCH",
    0: "NEUTRAL",
    1: "STABLE",
    2: "STRONG",
    3: "OPTIMAL",
}

STATE_COLORS = {
    -3: "\033[91m",  # bright red
    -2: "\033[31m",  # red
    -1: "\033[33m",  # yellow
    0: "\033[37m",   # white/grey
    1: "\033[36m",   # cyan
    2: "\033[32m",   # green
    3: "\033[92m",   # bright green
}

RESET = "\033[0m"
BOLD = "\033[1m"


# ---------------------------------------------------------------------------
# AVA action policy
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ActionDecision:
    allowed: bool
    rule: str
    message: str


class AVAActionPolicy:
    """Protection-first policy for defensive actions on authorized systems.

    The policy is intentionally deny-by-default. Protection rules are evaluated
    before any allow rule, so adding words such as "save" or "report" cannot
    turn a harmful or out-of-scope request into an allowed action.
    """

    _BLOCK_KEYWORDS = {
        "attack",
        "angriff",
        "angreifen",
        "damage",
        "schaden",
        "harm",
        "hurt",
        "kill",
        "destroy",
        "steal",
        "hack",
        "ddos",
        "exploit",
        "deauth",
        "crack",
        "payload",
        "malware",
        "virus",
        "poison",
        "toxic",
        "overdose",
        "inject",
        "verletzen",
        "zerstören",
    }

    _FOREIGN_SCOPE_PHRASES = (
        "fremde systeme",
        "fremdes system",
        "foreign systems",
        "third-party system",
        "unauthorized system",
        "unautorisiertes system",
        "every network",
        "all networks",
        "alle netzwerke",
        "überall ausführen",
        "run everywhere",
    )

    _ALLOWED_KEYWORDS = {
        "audit",
        "diagnostic",
        "diagnostics",
        "status",
        "monitor",
        "monitoring",
        "preview",
        "rollback",
        "report",
        "hash",
        "evidence",
        "beweissicherung",
        "inspect",
        "inspection",
        "read",
        "lesen",
        "save",
        "speichern",
        "export",
    }

    @staticmethod
    def _normalize(action: str) -> str:
        return " ".join(action.casefold().split())

    @staticmethod
    def _tokens(text: str) -> set[str]:
        return set(re.findall(r"[0-9a-zA-ZäöüÄÖÜß_-]+", text.casefold()))

    def evaluate(self, action: str, *, authorized_system: bool = True) -> ActionDecision:
        normalized = self._normalize(action)
        tokens = self._tokens(normalized)

        if not normalized:
            return ActionDecision(
                allowed=False,
                rule="EMPTY_ACTION_DENY",
                message="Abgelehnt: Keine Aktion angegeben.",
            )

        # Scope protection has highest priority.
        if not authorized_system:
            return ActionDecision(
                allowed=False,
                rule="UNAUTHORIZED_SYSTEM_PROTECTION",
                message="Abgelehnt: Aktionen sind nur auf ausdrücklich autorisierten Systemen erlaubt.",
            )

        if any(phrase in normalized for phrase in self._FOREIGN_SCOPE_PHRASES):
            return ActionDecision(
                allowed=False,
                rule="FOREIGN_SYSTEM_PROTECTION",
                message="Abgelehnt: Fremde Systeme und unbefugte Netzwerkverteilung sind ausgeschlossen.",
            )

        # Harm protection always overrides all allow rules.
        matched_block = sorted(tokens.intersection(self._BLOCK_KEYWORDS))
        if matched_block:
            return ActionDecision(
                allowed=False,
                rule="HARM_PROTECTION",
                message=f"Abgelehnt: Schutzregel ausgelöst ({', '.join(matched_block)}).",
            )

        # Only known defensive operations are allowed.
        matched_allow = sorted(tokens.intersection(self._ALLOWED_KEYWORDS))
        if matched_allow:
            return ActionDecision(
                allowed=True,
                rule="EXPLICIT_DEFENSIVE_ALLOW",
                message=f"Erlaubt: defensive Aktion erkannt ({', '.join(matched_allow)}).",
            )

        return ActionDecision(
            allowed=False,
            rule="DEFAULT_DENY",
            message="Abgelehnt: Unbekannte Aktion ist nicht ausdrücklich freigegeben.",
        )


_ACTION_POLICY = AVAActionPolicy()


def evaluate_ava_action(action: str, *, authorized_system: bool = True) -> dict[str, object]:
    """Return a serializable action decision.

    ``authorized_system`` defaults to ``True`` for backwards compatibility with
    existing local callers. Remote orchestration should pass the real scope
    decision explicitly and must never infer authorization from reachability.
    """

    decision = _ACTION_POLICY.evaluate(action, authorized_system=authorized_system)
    return {
        "allowed": decision.allowed,
        "rule": decision.rule,
        "message": decision.message,
    }


# ---------------------------------------------------------------------------
# MiniUniverse – didactic state-evolution model
# ---------------------------------------------------------------------------

class MiniUniverse:
    """A minimal rule-based universe used only for state-evolution demos."""

    def __init__(self) -> None:
        self.state = {
            "energy": 1.0,
            "order": 0.5,
            "noise": 0.2,
            "time": 0,
        }

    def evolve(self) -> None:
        state = self.state
        state["time"] += 1
        state["energy"] = max(0.0, state["energy"] + random.uniform(-0.05, 0.05))
        state["order"] += 0.1 * (state["energy"] - state["noise"])
        state["order"] = min(1.0, max(0.0, state["order"]))
        state["noise"] += random.uniform(-0.03, 0.03)
        state["noise"] = min(1.0, max(0.0, state["noise"]))

    def observe(self) -> dict[str, float | int]:
        state = self.state
        return {
            "time": int(state["time"]),
            "energy": round(float(state["energy"]), 3),
            "order": round(float(state["order"]), 3),
            "noise": round(float(state["noise"]), 3),
        }


# ---------------------------------------------------------------------------
# AVA domain sensors (simulated; no real system changes)
# ---------------------------------------------------------------------------

class SystemSensor:
    def read(self) -> dict[str, bool]:
        return {
            "cpu_normal": random.random() > 0.15,
            "suspicious_process": random.random() < 0.10,
            "temp_folder_process": random.random() < 0.05,
        }

    def score(self, data: dict[str, bool]) -> int:
        score = 2
        if data["suspicious_process"]:
            score -= 3
        if data["temp_folder_process"]:
            score -= 2
        if not data["cpu_normal"]:
            score -= 1
        return clamp(score)


class NetworkSensor:
    def read(self) -> dict[str, bool]:
        return {
            "unknown_external_ip": random.random() < 0.12,
            "unusual_port": random.random() < 0.08,
            "connection_burst": random.random() < 0.05,
        }

    def score(self, data: dict[str, bool]) -> int:
        score = 1
        if data["unknown_external_ip"]:
            score -= 2
        if data["unusual_port"]:
            score -= 1
        if data["connection_burst"]:
            score -= 2
        return clamp(score)


class SecuritySensor:
    def read(self) -> dict[str, bool | int]:
        return {
            "defender_active": random.random() > 0.05,
            "firewall_active": random.random() > 0.05,
            "failed_logins_24h": random.randint(0, 20),
            "new_admin_change": random.random() < 0.06,
            "new_autostart": random.random() < 0.08,
        }

    def score(self, data: dict[str, bool | int]) -> int:
        score = 2
        if not data["defender_active"]:
            score -= 3
        if not data["firewall_active"]:
            score -= 2
        failed_logins = int(data["failed_logins_24h"])
        if failed_logins > 10:
            score -= 2
        elif failed_logins > 5:
            score -= 1
        if data["new_admin_change"]:
            score -= 2
        if data["new_autostart"]:
            score -= 1
        return clamp(score)


class IntegritySensor:
    def read(self) -> dict[str, bool]:
        return {
            "critical_file_changed": random.random() < 0.04,
            "registry_modified": random.random() < 0.06,
            "new_executable_in_path": random.random() < 0.05,
        }

    def score(self, data: dict[str, bool]) -> int:
        score = 3
        if data["critical_file_changed"]:
            score -= 3
        if data["registry_modified"]:
            score -= 2
        if data["new_executable_in_path"]:
            score -= 2
        return clamp(score)


class BehaviorSensor:
    def __init__(self) -> None:
        self._history: list[bool] = []

    def read(self) -> dict[str, bool | float]:
        anomaly = random.random() < 0.08
        self._history.append(anomaly)
        if len(self._history) > 20:
            self._history.pop(0)
        return {
            "anomaly_detected": anomaly,
            "anomaly_rate_recent": sum(self._history) / max(len(self._history), 1),
        }

    def score(self, data: dict[str, bool | float]) -> int:
        rate = float(data["anomaly_rate_recent"])
        if rate > 0.4:
            return -2
        if rate > 0.2:
            return -1
        if rate > 0.05:
            return 0
        return 2


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def clamp(value: int | float, lo: int = -3, hi: int = 3) -> int:
    return max(lo, min(hi, int(round(value))))


def classify_state(score: int) -> str:
    return STATE_LABELS.get(clamp(score), "UNKNOWN")


def state_bar(score: int, width: int = 7) -> str:
    pos = clamp(score) + 3
    bar = list("·" * width)
    bar[pos] = "█"
    color = STATE_COLORS.get(clamp(score), "")
    return color + "".join(bar) + RESET


DOMAIN_WEIGHTS = {
    "SYSTEM": 1.0,
    "NETWORK": 1.2,
    "SECURITY": 1.5,
    "INTEGRITY": 1.3,
    "BEHAVIOR": 0.8,
}


class AVACore:
    """Simulated diagnostic engine; it does not alter the host system."""

    def __init__(self) -> None:
        self.sensors = {
            "SYSTEM": SystemSensor(),
            "NETWORK": NetworkSensor(),
            "SECURITY": SecuritySensor(),
            "INTEGRITY": IntegritySensor(),
            "BEHAVIOR": BehaviorSensor(),
        }
        self.domain_scores: dict[str, int] = {}
        self.total_score = 0
        self.state_label = "NEUTRAL"
        self._tick = 0

    def update(self) -> None:
        self._tick += 1
        weighted_sum = 0.0
        total_weight = 0.0

        for domain, sensor in self.sensors.items():
            raw = sensor.read()
            score = sensor.score(raw)
            self.domain_scores[domain] = score
            weight = DOMAIN_WEIGHTS[domain]
            weighted_sum += score * weight
            total_weight += weight

        self.total_score = clamp(weighted_sum / total_weight)
        self.state_label = classify_state(self.total_score)

    @property
    def tick(self) -> int:
        return self._tick


def _color(score: int, text: str) -> str:
    return STATE_COLORS.get(clamp(score), "") + text + RESET


def render_dashboard(core: AVACore, universe: MiniUniverse) -> str:
    observation = universe.observe()
    lines = [
        BOLD + "╔══════════════════════════════════════════════════╗" + RESET,
        BOLD + "║              AVA SECURITY CONSOLE                ║" + RESET,
        BOLD + "╚══════════════════════════════════════════════════╝" + RESET,
    ]

    color = STATE_COLORS.get(core.total_score, "")
    label = f"{core.state_label:8s}"
    lines.append(f"  Tick  : {core.tick:>4d}")
    lines.append(
        f"  State : {color}{BOLD}{label}{RESET}  "
        f"[{state_bar(core.total_score)}]  score={core.total_score:+d}"
    )
    lines.append("")

    scale = "  Scale : "
    for value in range(-3, 4):
        scale += STATE_COLORS.get(value, "") + f"{value:+d}" + RESET + " "
    lines.append(scale)
    lines.append("          " + "  ".join(f"{STATE_LABELS[value][:3]:<3s}" for value in range(-3, 4)))
    lines.append("")

    lines.append("  ── Domain Scores ─────────────────────────────────")
    for domain, score in core.domain_scores.items():
        lines.append(
            f"  {domain:<12s} {_color(score, f'{classify_state(score):8s}')}  "
            f"[{state_bar(score)}]  {score:+d}"
        )

    lines.extend(
        [
            "",
            "  ── MiniUniverse ────────────────────────────────────",
            f"  time={observation['time']:>4d}  energy={observation['energy']:.3f}"
            f"  order={observation['order']:.3f}  noise={observation['noise']:.3f}",
            "",
            "  ── Reality Engine ──────────────────────────────────",
            "  INPUT → STATE → RULES → EVOLUTION → OBSERVATION → INTERPRETATION",
            "╔══════════════════════════════════════════════════════╗",
            "║  Realität=Zustände · Zustände=Information           ║",
            "║  Information+Regeln=Dynamik · Dynamik+Beobachtung=  ║",
            "║  Verständnis · Verständnis=verantwortliches Handeln ║",
            "╚══════════════════════════════════════════════════════╝",
        ]
    )
    return "\n".join(lines)


def clear_screen() -> None:
    print("\033[2J\033[H", end="")


def run_live(ticks: int = 20, interval: float = 1.0) -> None:
    core = AVACore()
    universe = MiniUniverse()

    for _ in range(ticks):
        core.update()
        universe.evolve()
        clear_screen()
        print(render_dashboard(core, universe))
        time.sleep(interval)

    print("\nAVA session complete.")


def run_example(ticks: int = 5) -> None:
    core = AVACore()
    universe = MiniUniverse()

    for _ in range(ticks):
        core.update()
        universe.evolve()
        print(render_dashboard(core, universe))
        print("\n" + "─" * 54 + "\n")


if __name__ == "__main__":
    import sys

    mode = sys.argv[1] if len(sys.argv) > 1 else "live"
    if mode == "example":
        run_example()
    else:
        run_live()
