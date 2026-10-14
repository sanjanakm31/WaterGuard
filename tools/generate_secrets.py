"""
tools/generate_secrets.py

Generates three fresh, cryptographically random 256-bit keys, hex-encoded,
ready to paste into your .env file:

    WG_COMMAND_HMAC_KEY   -- authenticates WCP commands (client <-> Gateway)
    WG_EVIDENCE_HMAC_KEY  -- signs the hash of every stored evidence record
    WG_EVIDENCE_AES_KEY   -- AES-256-GCM key encrypting evidence records

Run once per environment (once for your development machine, and again -
with DIFFERENT values, copied to all three VMs identically - for your
graded multi-VM deployment, since the Gateway and every client must share
the same WG_COMMAND_HMAC_KEY to interoperate). Never commit the resulting
.env file to Git -- .gitignore in this repo already excludes it.
"""

from __future__ import annotations

import secrets


def main() -> None:
    print("# Paste the following three lines into your .env file")
    print("# (copy the SAME values to every VM in a multi-VM deployment).")
    print(f"WG_COMMAND_HMAC_KEY={secrets.token_hex(32)}")
    print(f"WG_EVIDENCE_HMAC_KEY={secrets.token_hex(32)}")
    print(f"WG_EVIDENCE_AES_KEY={secrets.token_hex(32)}")


if __name__ == "__main__":
    main()
