"""CLI for AVA policy evaluation."""
from __future__ import annotations
import argparse
from .policy import AVAGuardPolicy

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate AVA acceptance-policy actions.")
    parser.add_argument("action", nargs="+", help="Action text to evaluate")
    parser.add_argument("--target", default="AVA", help="Target of the action, default: AVA")
    args = parser.parse_args(argv)
    action = " ".join(args.action)
    decision = AVAGuardPolicy().evaluate(action, target=args.target)
    print(decision.to_json())
    return 0 if decision.allowed else 2

if __name__ == "__main__":
    raise SystemExit(main())
