"""
shared/crypto_utils.py

All cryptographic primitives used by WaterGuard live in exactly one place so
they can be reviewed, tested, and cited in the report as a single unit:

    - SHA-256 hashing            (hashlib, stdlib)
    - HMAC-SHA256 sign/verify    (hmac + hashlib, stdlib)
    - AES-256-GCM encrypt/decrypt (cryptography package — authenticated
      encryption; a tampered ciphertext fails to decrypt rather than
      silently returning corrupted plaintext)

Design note for the report: the evidence pipeline is deliberately
"hash -> HMAC-sign the hash -> AES-GCM-encrypt the payload" rather than
relying on AES-GCM's own authentication tag alone. This gives two
independent, separately-keyed integrity checks (the HMAC over the hash, and
GCM's own tag) plus a content-addressable SHA-256 hash that can be quoted in
an incident report without needing to decrypt the record at all. It is
belt-and-suspenders by design — call this out explicitly if asked at viva
why we did not simply rely on GCM's tag.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AES_NONCE_BYTES = 12  # 96-bit nonce, the standard/recommended size for AES-GCM


def sha256_hex(data: bytes) -> str:
    """Returns the lowercase hex-encoded SHA-256 digest of `data`."""
    return hashlib.sha256(data).hexdigest()


def hmac_sha256_hex(key: bytes, data: bytes) -> str:
    """Returns the lowercase hex-encoded HMAC-SHA256 tag of `data` under `key`."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def hmac_verify(key: bytes, data: bytes, expected_hex: str) -> bool:
    """
    Constant-time verification of an HMAC-SHA256 tag. Always use this (never
    a plain `==` string comparison) to avoid leaking timing information about
    how many leading bytes of the tag matched.
    """
    computed = hmac.new(key, data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, expected_hex)


def aes_gcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> tuple[bytes, bytes]:
    """
    Encrypts `plaintext` with AES-256-GCM under a freshly generated random
    nonce. Returns (nonce, ciphertext_with_tag). The nonce MUST be stored
    alongside the ciphertext (it is not secret) and MUST NOT be reused for
    another encryption with the same key; a fresh
    os.urandom(12) nonce is generated on every call specifically to prevent
    nonce reuse, which would catastrophically break GCM's security guarantees.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(AES_NONCE_BYTES)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
    """
    Decrypts and authenticates `ciphertext`. Raises
    cryptography.exceptions.InvalidTag (a subclass of Exception) if the
    ciphertext or associated data has been tampered with, or if the wrong
    key/nonce is supplied. Callers that need to detect tampering (see
    gateway/evidence_store.py) should catch a broad Exception around this
    call and treat any failure as "integrity check failed", not just
    InvalidTag specifically, since malformed/corrupted input can also raise
    ValueError from the underlying library.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)


def canonical_json(obj: dict) -> bytes:
    """
    Deterministic JSON serialization (sorted keys, no whitespace) used
    everywhere a byte-exact, reproducible representation of a dict is
    required for hashing or signing.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
