"""
tools/verify_evidence_integrity.py

Independent auditor tool: reads every row of the evidence database and
re-derives its cryptographic protections from scratch (AES-256-GCM decrypt
-> SHA-256 rehash -> HMAC-SHA256 re-verify), reporting any row where the
result does not match what is stored. This is the project's "deliberate
tampering test" capability referenced in the synopsis:

    1. Run the system normally for a while (or run device_a_attacker.py
       run-all) so the evidence database has several rows.
    2. Run this tool -- every row should report INTACT.
    3. Run: python3 -m attacker.device_a_attacker evidence-tampering
    4. Run this tool again -- the tampered row should report TAMPERED, with
       a specific reason, while every other row still reports INTACT.

Exit code is 0 if every row is intact, 1 if any row fails verification (so
this can also be wired into a CI/test pipeline or a pre-report sanity check).
"""

from __future__ import annotations

import datetime
import sys

from gateway import evidence_store


def main() -> int:
    evidence_store.init_db()
    rows = evidence_store.fetch_all_raw_rows()

    if not rows:
        print("No evidence records found. Run the Gateway and send at least one "
              "command (legitimate or attack) before running this tool.")
        return 0

    print(f"Verifying {len(rows)} evidence record(s) from {evidence_store.DB_PATH}\n")
    print(f"{'ID':>4}  {'EVENT_ID':<36}  {'RESULT':<10}  DETAIL")
    print("-" * 100)

    intact_count = 0
    tampered_count = 0

    for row in rows:
        is_intact, record, detail = evidence_store.decrypt_and_verify_event(row)
        status = "INTACT" if is_intact else "TAMPERED"
        print(f"{row['id']:>4}  {row['event_id']:<36}  {status:<10}  {detail}")
        if is_intact:
            intact_count += 1
        else:
            tampered_count += 1

    print("-" * 100)
    print(f"Summary: {intact_count} intact, {tampered_count} tampered, out of {len(rows)} total.")
    print(f"Checked at: {datetime.datetime.now().isoformat(timespec='seconds')}")

    return 1 if tampered_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
