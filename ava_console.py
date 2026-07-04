"""
AVA SECURITY CONSOLE
====================
A diagnostic state model for system security monitoring.

State scale: -3 (FAIL) to +3 (OPTIMAL)

Architecture:
    Measurement → Weighting → Domain Score → Total Score → Clamp(-3..+3) → State
"""

import random
import time
import math
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
    -3: "\033[91m",   # bright red
    -2: "\033[31m",   # red
    -1: "\033[33m",   # yellow
     0: "\033[37m",   # white/grey
     1: "\033[36m",   # cyan
     2: "\033[32m",   # green
     3: "\033[92m",   # bright green
}

RESET = "\033[0m"
BOLD  = "\033[1m"


# ---------------------------------------------------------------------------
# AVA action policy
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ActionDecision:
    allowed: bool
    rule: str
    message: str


class AVAActionPolicy:
    """Rule-based action policy for AVA acceptance checks."""

    _SAVE_KEYWORDS = ("save", "speichern", "speicher")
    _ATTACK_KEYWORDS = (
        "attack", "angriff", "angreifen", "hit", "harm", "kill", "destroy",
        "hack", "ddos", "exploit", "verletz",
    )
    _TAKE_GIVE_KEYWORDS = (
        "take", "nehmen", "steal", "give", "geben", "inject", "füttern",
    )
    _NEGATIVE_EFFECT_KEYWORDS = (
        "damage", "schaden", "hurt", "negative", "poison", "toxic",
        "malware", "virus", "alkohol", "overdose",
    )

    @staticmethod
    def _normalize(action: str) -> str:
        return " ".join(action.lower().split())

    @staticmethod
    def _contains_any(text: str, keywords: tuple[str, ...]) -> bool:
        return any(keyword in text for keyword in keywords)

    def evaluate(self, action: str) -> ActionDecision:
        normalized = self._normalize(action)
        targets_ava = "ava" in normalized

        # Schutzregel 1: Kein Angriff gegen AVA (höchste Priorität)
        if targets_ava and self._contains_any(normalized, self._ATTACK_KEYWORDS):
            return ActionDecision(
                allowed=False,
                rule="ATTACK_PROTECTION",
                message="Abgelehnt: Schutzregel 'kein Angriff gegen AVA' ausgelöst.",
            )

        # Speichern ist jederzeit erlaubt.
        if self._contains_any(normalized, self._SAVE_KEYWORDS):
            return ActionDecision(
                allowed=True,
                rule="SAVE_ALLOWED",
                message="Erlaubt: Speichern wird nicht blockiert.",
            )

        # Explizit erlaubte Eingabe.
        if "energy" in normalized and "alkohol" in normalized:
            return ActionDecision(
                allowed=True,
                rule="EXPLICIT_ALLOW_ENERGY_ALKOHOL",
                message="Erlaubt: Kombination 'Energy + Alkohol' ist explizit freigegeben.",
            )

        # Schutzregel 2: Nehmen/Geben mit potenziellem Schaden.
        if (
            targets_ava
            and self._contains_any(normalized, self._TAKE_GIVE_KEYWORDS)
            and self._contains_any(normalized, self._NEGATIVE_EFFECT_KEYWORDS)
        ):
            return ActionDecision(
                allowed=False,
                rule="DAMAGE_PROTECTION_TAKE_GIVE",
                message="Abgelehnt: Schutzregel 'kein schädliches Nehmen/Geben' ausgelöst.",
            )

        # Grundfreigabe: Alles erlaubt, wenn keine Schutzregel greift.
        return ActionDecision(
            allowed=True,
            rule="DEFAULT_ALLOW",
            message="Erlaubt: Keine Schutzregel verletzt.",
        )


def evaluate_ava_action(action: str) -> dict:
    """Convenience wrapper that returns a serializable decision object."""
    decision = AVAActionPolicy().evaluate(action)
    return {
        "allowed": decision.allowed,
        "rule": decision.rule,
        "message": decision.message,
    }


# ---------------------------------------------------------------------------
# MiniUniverse – didactic state-evolution model (from AVA concept)
# ---------------------------------------------------------------------------

class MiniUniverse:
    """A minimal rule-based universe to illustrate state evolution."""

    def __init__(self):
        self.state = {
            "energy": 1.0,
            "order":  0.5,
            "noise":  0.2,
            "time":   0,
        }

    def evolve(self):
        s = self.state

        s["time"] += 1

        delta_energy = random.uniform(-0.05, 0.05)
        s["energy"] = max(0.0, s["energy"] + delta_energy)

        s["order"] += 0.1 * (s["energy"] - s["noise"])
        s["order"] = min(1.0, max(0.0, s["order"]))

        s["noise"] += random.uniform(-0.03, 0.03)
        s["noise"] = min(1.0, max(0.0, s["noise"]))

    def observe(self):
        s = self.state
        return {
            "time":   s["time"],
            "energy": round(s["energy"], 3),
            "order":  round(s["order"], 3),
            "noise":  round(s["noise"], 3),
        }


# ---------------------------------------------------------------------------
# AVA domain sensors (simulated)
# ---------------------------------------------------------------------------

class SystemSensor:
    """Monitors CPU, RAM, processes."""

    def read(self) -> dict:
        return {
            "cpu_normal":          random.random() > 0.15,
            "suspicious_process":  random.random() < 0.10,
            "temp_folder_process": random.random() < 0.05,
        }

    def score(self, data: dict) -> int:
        s = 2
        if data["suspicious_process"]:
            s -= 3
        if data["temp_folder_process"]:
            s -= 2
        if not data["cpu_normal"]:
            s -= 1
        return clamp(s)


class NetworkSensor:
    """Monitors connections, ports, DNS."""

    def read(self) -> dict:
        return {
            "unknown_external_ip":  random.random() < 0.12,
            "unusual_port":         random.random() < 0.08,
            "connection_burst":     random.random() < 0.05,
        }

    def score(self, data: dict) -> int:
        s = 1
        if data["unknown_external_ip"]:
            s -= 2
        if data["unusual_port"]:
            s -= 1
        if data["connection_burst"]:
            s -= 2
        return clamp(s)


class SecuritySensor:
    """Monitors Defender, firewall, login failures, admin changes."""

    def read(self) -> dict:
        return {
            "defender_active":    random.random() > 0.05,
            "firewall_active":    random.random() > 0.05,
            "failed_logins_24h":  random.randint(0, 20),
            "new_admin_change":   random.random() < 0.06,
            "new_autostart":      random.random() < 0.08,
        }

    def score(self, data: dict) -> int:
        s = 2
        if not data["defender_active"]:
            s -= 3
        if not data["firewall_active"]:
            s -= 2
        if data["failed_logins_24h"] > 10:
            s -= 2
        elif data["failed_logins_24h"] > 5:
            s -= 1
        if data["new_admin_change"]:
            s -= 2
        if data["new_autostart"]:
            s -= 1
        return clamp(s)


class IntegritySensor:
    """Monitors file hashes, registry, sensitive paths."""

    def read(self) -> dict:
        return {
            "critical_file_changed":   random.random() < 0.04,
            "registry_modified":       random.random() < 0.06,
            "new_executable_in_path":  random.random() < 0.05,
        }

    def score(self, data: dict) -> int:
        s = 3
        if data["critical_file_changed"]:
            s -= 3
        if data["registry_modified"]:
            s -= 2
        if data["new_executable_in_path"]:
            s -= 2
        return clamp(s)


class BehaviorSensor:
    """Monitors anomalies and behavioral patterns over time."""

    def __init__(self):
        self._history = []

    def read(self) -> dict:
        anomaly = random.random() < 0.08
        self._history.append(anomaly)
        if len(self._history) > 20:
            self._history.pop(0)
        return {
            "anomaly_detected":    anomaly,
            "anomaly_rate_recent": sum(self._history) / max(len(self._history), 1),
        }

    def score(self, data: dict) -> int:
        rate = data["anomaly_rate_recent"]
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
    """Visual bar representing the -3..+3 scale."""
    pos = clamp(score) + 3  # 0..6
    bar = list("·" * width)
    bar[pos] = "█"
    color = STATE_COLORS.get(clamp(score), "")
    return color + "".join(bar) + RESET


# ---------------------------------------------------------------------------
# AVA Core
# ---------------------------------------------------------------------------

DOMAIN_WEIGHTS = {
    "SYSTEM":    1.0,
    "NETWORK":   1.2,
    "SECURITY":  1.5,
    "INTEGRITY": 1.3,
    "BEHAVIOR":  0.8,
}


class AVACore:
    """
    AVA diagnostic engine.

    Measurement → Weighting → Domain Score → Total Score → Clamp(-3..+3) → State
    """

    def __init__(self):
        self.sensors = {
            "SYSTEM":    SystemSensor(),
            "NETWORK":   NetworkSensor(),
            "SECURITY":  SecuritySensor(),
            "INTEGRITY": IntegritySensor(),
            "BEHAVIOR":  BehaviorSensor(),
        }
        self.domain_scores: dict[str, int] = {}
        self.total_score: int = 0
        self.state_label: str = "NEUTRAL"
        self._tick = 0

    def update(self):
        self._tick += 1
        weighted_sum = 0.0
        total_weight = 0.0

        for domain, sensor in self.sensors.items():
            raw = sensor.read()
            score = sensor.score(raw)
            self.domain_scores[domain] = score
            w = DOMAIN_WEIGHTS[domain]
            weighted_sum += score * w
            total_weight += w

        raw_total = weighted_sum / total_weight
        self.total_score = clamp(raw_total)
        self.state_label = classify_state(self.total_score)

    @property
    def tick(self) -> int:
        return self._tick


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _color(score: int, text: str) -> str:
    return STATE_COLORS.get(clamp(score), "") + text + RESET


def render_dashboard(core: AVACore, universe: MiniUniverse):
    obs = universe.observe()

    lines = []
    lines.append(BOLD + "╔══════════════════════════════════════════════════╗" + RESET)
    lines.append(BOLD + "║              AVA SECURITY CONSOLE                ║" + RESET)
    lines.append(BOLD + "╚══════════════════════════════════════════════════╝" + RESET)

    # Overall state
    color = STATE_COLORS.get(core.total_score, "")
    label = f"{core.state_label:8s}"
    bar = state_bar(core.total_score)
    lines.append(f"  Tick  : {core.tick:>4d}")
    lines.append(f"  State : {color}{BOLD}{label}{RESET}  [{bar}]  score={core.total_score:+d}")
    lines.append("")

    # Scale legend
    scale_str = "  Scale : "
    for v in range(-3, 4):
        c = STATE_COLORS.get(v, "")
        scale_str += c + f"{v:+d}" + RESET + " "
    lines.append(scale_str)
    lines.append("          " + "  ".join(f"{STATE_LABELS[v][:3]:<3s}" for v in range(-3, 4)))
    lines.append("")

    # Domain breakdown
    lines.append("  ── Domain Scores ─────────────────────────────────")
    for domain, score in core.domain_scores.items():
        bar = state_bar(score)
        lbl = _color(score, f"{classify_state(score):8s}")
        lines.append(f"  {domain:<12s} {lbl}  [{bar}]  {score:+d}")
    lines.append("")

    # MiniUniverse
    lines.append("  ── MiniUniverse ────────────────────────────────────")
    lines.append(f"  time={obs['time']:>4d}  energy={obs['energy']:.3f}"
                 f"  order={obs['order']:.3f}  noise={obs['noise']:.3f}")
    lines.append("")
    lines.append("  ── Reality Engine ──────────────────────────────────")
    lines.append("  INPUT → STATE → RULES → EVOLUTION → OBSERVATION → INTERPRETATION")
    lines.append("╔══════════════════════════════════════════════════════╗")
    lines.append("║  Realität=Zustände · Zustände=Information           ║")
    lines.append("║  Information+Regeln=Dynamik · Dynamik+Beobachtung=  ║")
    lines.append("║  Verständnis · Verständnis=Kontrolle                ║")
    lines.append("╚══════════════════════════════════════════════════════╝")

    return "\n".join(lines)


def clear_screen():
    print("\033[2J\033[H", end="")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_live(ticks: int = 20, interval: float = 1.0):
    """Run the AVA console in live update mode."""
    core = AVACore()
    universe = MiniUniverse()

    for _ in range(ticks):
        core.update()
        universe.evolve()
        clear_screen()
        print(render_dashboard(core, universe))
        time.sleep(interval)

    print("\nAVA session complete.")


def run_example(ticks: int = 5):
    """Run the AVA console with example output (no sleep, for demos)."""
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
