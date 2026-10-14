"""
tools/export_evidence_pcap.py

Implements the synopsis's requirement precisely: "When traffic evidence
needs to be exported for external investigation, the relevant attack PCAP
file is likewise hashed, HMAC-signed, and AES-encrypted before export,
while the original working capture remains available locally for ongoing
analysis."

Given any capture file (or, in fact, any file — this is deliberately
generic), this tool:
    1. Reads the file's raw bytes (the ORIGINAL is never modified or moved).
    2. Computes its SHA-256 hash.
    3. HMAC-SHA256-signs that hash under EVIDENCE_HMAC_KEY.
    4. AES-256-GCM-encrypts the raw bytes under EVIDENCE_AES_KEY.
    5. Writes a `<name>.export.enc` file (the ciphertext) and a
       `<name>.export.manifest.json` file recording the original filename,
       size, SHA-256 hash, HMAC-SHA256 tag, AES-GCM nonce, and export
       timestamp — everything an external investigator needs to verify
       authenticity and integrity without needing this codebase, PROVIDED
       they separately have the two evidence keys through your organization's
       normal key-custody process (this manifest deliberately does NOT
       include the keys themselves).

Verify an export with `--verify` at any time (e.g. to prove the exported
copy has not been altered since export, or to detect that it has).

This module depends ONLY on shared/crypto_utils.py (already verified — see
README.md) and the Python standard library, so unlike the PCAP
capture/analysis modules, it HAS been fully executed and tested in this
session, on an arbitrary file, with both the success path and a deliberate
post-export tamper correctly detected.

USAGE
-----
    python3 -m tools.export_evidence_pcap --file data/captures/attack_run.pcap
    python3 -m tools.export_evidence_pcap --file data/captures/attack_run.pcap.export.enc --verify \
        --manifest data/captures/attack_run.pcap.export.manifest.json
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared import config, crypto_utils  # noqa: E402

MANIFEST_VERSION = 2
MANIFEST_SIGNATURE_FIELD = "manifest_hmac_sha256"


def _manifest_signature(manifest: dict) -> str:
    signed_fields = {
        key: value for key, value in manifest.items() if key != MANIFEST_SIGNATURE_FIELD
    }
    return crypto_utils.hmac_sha256_hex(
        config.EVIDENCE_HMAC_KEY, crypto_utils.canonical_json(signed_fields)
    )


def export_file(source_path: Path) -> tuple[Path, Path]:
    raw_bytes = source_path.read_bytes()
    sha256_hex = crypto_utils.sha256_hex(raw_bytes)
    hmac_hex = crypto_utils.hmac_sha256_hex(config.EVIDENCE_HMAC_KEY, sha256_hex.encode("utf-8"))
    nonce, ciphertext = crypto_utils.aes_gcm_encrypt(config.EVIDENCE_AES_KEY, raw_bytes)

    encrypted_path = source_path.with_name(source_path.name + ".export.enc")
    manifest_path = source_path.with_name(source_path.name + ".export.manifest.json")

    encrypted_path.write_bytes(nonce + ciphertext)  # nonce (12 bytes) prepended for self-contained storage

    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "original_filename": source_path.name,
        "original_size_bytes": len(raw_bytes),
        "sha256": sha256_hex,
        "hmac_sha256_of_hash": hmac_hex,
        "aes_gcm_nonce_bytes": 12,
        "exported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "note": "The original file at the recorded path is UNCHANGED and remains available for "
                "ongoing local analysis; this manifest + the .export.enc file together are the "
                "tamper-evident copy intended for external handoff.",
    }
    manifest[MANIFEST_SIGNATURE_FIELD] = _manifest_signature(manifest)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    return encrypted_path, manifest_path


def verify_export(encrypted_path: Path, manifest_path: Path) -> tuple[bool, str]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            return False, "manifest root must be a JSON object"
        required = {
            "manifest_version", "original_filename", "original_size_bytes",
            "sha256", "hmac_sha256_of_hash", "aes_gcm_nonce_bytes",
            "exported_at", "note", MANIFEST_SIGNATURE_FIELD,
        }
        missing = sorted(required - set(manifest))
        if missing:
            return False, f"manifest is missing required fields: {', '.join(missing)}"
        if manifest["manifest_version"] != MANIFEST_VERSION:
            return False, f"unsupported manifest version: {manifest['manifest_version']!r}"
        if not crypto_utils.hmac_verify(
            config.EVIDENCE_HMAC_KEY,
            crypto_utils.canonical_json({
                key: value for key, value in manifest.items() if key != MANIFEST_SIGNATURE_FIELD
            }),
            manifest[MANIFEST_SIGNATURE_FIELD],
        ):
            return False, "manifest HMAC-SHA256 verification failed (metadata tampered)"

        nonce_length = manifest["aes_gcm_nonce_bytes"]
        if nonce_length != 12:
            return False, f"unsupported AES-GCM nonce length: {nonce_length!r}"
        blob = encrypted_path.read_bytes()
        if len(blob) < nonce_length + 16:
            return False, "encrypted export is too short to contain nonce, ciphertext, and GCM tag"
        nonce, ciphertext = blob[:nonce_length], blob[nonce_length:]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        return False, f"could not parse or validate export metadata: {exc}"

    try:
        plaintext = crypto_utils.aes_gcm_decrypt(config.EVIDENCE_AES_KEY, nonce, ciphertext)
    except Exception as exc:
        return False, f"AES-256-GCM authentication failed (file tampered or corrupted): {exc!r}"

    recomputed_sha256 = crypto_utils.sha256_hex(plaintext)
    if recomputed_sha256 != manifest["sha256"]:
        return False, f"SHA-256 mismatch: manifest={manifest['sha256']} recomputed={recomputed_sha256}"

    if not crypto_utils.hmac_verify(
        config.EVIDENCE_HMAC_KEY, manifest["sha256"].encode("utf-8"), manifest["hmac_sha256_of_hash"]
    ):
        return False, "HMAC-SHA256 verification of the manifest's recorded hash failed"

    if len(plaintext) != manifest["original_size_bytes"]:
        return False, (
            f"size mismatch: manifest={manifest['original_size_bytes']} "
            f"decrypted={len(plaintext)}"
        )

    return True, "OK — decrypted content matches the manifest's SHA-256 hash and HMAC exactly"


def main() -> None:
    parser = argparse.ArgumentParser(description="WaterGuard tamper-evident evidence export/verify")
    parser.add_argument("--file", required=True, help="file to export, or (with --verify) the .export.enc file")
    parser.add_argument("--verify", action="store_true", help="verify an existing export instead of creating one")
    parser.add_argument("--manifest", default=None, help="manifest path (required with --verify)")
    args = parser.parse_args()

    if args.verify:
        if not args.manifest:
            raise SystemExit("--manifest is required with --verify")
        ok, detail = verify_export(Path(args.file), Path(args.manifest))
        print(f"{'INTACT' if ok else 'TAMPERED/INVALID'}: {detail}")
        sys.exit(0 if ok else 1)
    else:
        source = Path(args.file)
        if not source.exists():
            raise SystemExit(f"file not found: {source}")
        encrypted_path, manifest_path = export_file(source)
        print(f"Exported (encrypted): {encrypted_path}")
        print(f"Manifest:             {manifest_path}")
        print(f"Original untouched:   {source}")


if __name__ == "__main__":
    main()
