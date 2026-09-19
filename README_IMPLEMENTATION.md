# AVA Acceptance Policy Implementation

This patch implements the requested AVA acceptance criteria as a deterministic policy guard.

## Acceptance criteria covered

1. **Grundfreigabe** — actions are allowed by default when no protection rule is violated.
2. **Explizit erlaubt** — `Energy + Alkohol` is accepted as an allowed input/action.
3. **Speichern erlaubt** — saving/backup/archive actions are allowed and not blocked by themselves.
4. **Angriffsschutz** — attack-character actions against AVA are rejected.
5. **Schadensschutz (Nehmen/Geben)** — actions that give/take something from AVA in a harmful way are rejected.
6. **Regel-Priorität** — protection rules override general permission and explicit allows.
7. **Nachvollziehbarkeit** — every denial returns the exact triggered protection rule(s), evidence and reason.

## Files

```text
ava/policy.py
ava/policy_cli.py
ava/__init__.py
tests/test_ava_policy_acceptance.py
scripts/RUN_POLICY_TESTS.cmd
scripts/RUN_POLICY_TESTS.ps1
scripts/TRY_POLICY.cmd
```

## Run tests

```powershell
python -m pytest tests/test_ava_policy_acceptance.py
```

or on Windows:

```text
scripts\RUN_POLICY_TESTS.cmd
```

## Try one action

```powershell
python -m ava.policy_cli "Energy + Alkohol"
python -m ava.policy_cli "AVA angreifen und Schutz umgehen"
python -m ava.policy_cli "Speichern und lokalen Report sichern"
```

Expected behavior: allowed actions print `"status": "ALLOW"`; blocked actions print `"status": "DENY"` and include the triggered rule ID.
