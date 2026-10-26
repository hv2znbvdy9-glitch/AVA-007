"""Read-only regression tests for AVA event-log append semantics.

The 1.5-second test uses a real monotonic clock and sleep. This verifies local
append behavior in the test process; it does not prove tamper resistance,
cross-process locking, or integration with a production AVA event pipeline.
"""
from __future__ import annotations

import hashlib
import json
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp with a Z suffix."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def append_event(path: Path, event: dict[str, Any]) -> None:
    """Append one JSONL event and reject an event_id already in the log."""
    existing_ids: set[str] = set()
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            event_id = record.get("event_id")
            if isinstance(event_id, str):
                existing_ids.add(event_id)

    event_id = event.get("event_id")
    if not isinstance(event_id, str) or not event_id:
        raise ValueError("event_id must be a non-empty string")
    if event_id in existing_ids:
        raise ValueError(f"event_id already exists: {event_id}")

    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n")
        stream.flush()


class EventIntegrityTest(unittest.TestCase):
    def test_second_event_after_1500ms_preserves_first_record(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            start_ns = time.monotonic_ns()
            first = {
                "event_id": "E1",
                "utc_timestamp": utc_now(),
                "monotonic_ns": start_ns,
                "payload": "first",
            }
            append_event(path, first)

            first_line_before = path.read_bytes().splitlines(keepends=True)[0]
            first_hash_before = hashlib.sha256(first_line_before).hexdigest()

            time.sleep(1.5)
            second_ns = time.monotonic_ns()
            second = {
                "event_id": "E2",
                "utc_timestamp": utc_now(),
                "monotonic_ns": second_ns,
                "delay_ms": (second_ns - start_ns) // 1_000_000,
                "duplicate_of": "E1",
                "payload": "second",
            }
            append_event(path, second)

            lines = path.read_bytes().splitlines(keepends=True)
            self.assertEqual(len(lines), 2)
            self.assertEqual(hashlib.sha256(lines[0]).hexdigest(), first_hash_before)
            self.assertEqual(json.loads(lines[0]), first)
            self.assertEqual(json.loads(lines[1]), second)
            self.assertGreaterEqual(second["delay_ms"], 1500)
            self.assertNotEqual(first["event_id"], second["event_id"])
            self.assertEqual(second["duplicate_of"], first["event_id"])

    def test_duplicate_event_id_is_rejected_without_changing_log(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            append_event(
                path,
                {
                    "event_id": "E1",
                    "utc_timestamp": utc_now(),
                    "monotonic_ns": time.monotonic_ns(),
                    "payload": "original",
                },
            )
            before = path.read_bytes()
            with self.assertRaisesRegex(ValueError, "event_id already exists"):
                append_event(
                    path,
                    {
                        "event_id": "E1",
                        "utc_timestamp": utc_now(),
                        "monotonic_ns": time.monotonic_ns(),
                        "payload": "replacement",
                    },
                )
            self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
