# WaterGuard GUI v3: implemented additions

This is an upgrade of the supplied `WaterGuard_Updated_v2_Windows_Fixed.zip`.
It keeps the original Python security gateway, controller simulator, CLI,
cryptography, SQLite schema, and capture/export workflow.

| Agreed addition | Implemented behavior | Main files |
|---|---|---|
| 1. Device A operator application | Local browser forms send signed chlorine/valve requests. Real ALLOW/BLOCK/error result, reason, event ID. Human ppm converts to raw x100 without clipping unsafe values. | `device_a/app.py`, `device_a/operations.py`, `ui/operator.*` |
| 2. Separate security demonstrations | Selected scenario or complete 19-case suite; identity, signature, replay, stale time, read-only register, unsafe value, raw Modbus, malformed JSON, normal boundary cases. | `device_a/operations.py` |
| 3. Windows plant visualization | Chlorine/valve/flow read from controller registers; valve illustration follows the actual value; live status; stale telemetry is cleared on failure. Tank level is explicitly schematic. | `dashboard/app.py`, `ui/dashboard.*` |
| 4. Cleaner dashboard | Tabs, filtered authenticated event feed, separate packet observations, readable reasons and event selection. | `ui/dashboard.*`, `ui/style.css` |
| 5. Live command checking view | Recorded PASS/FAIL/SKIPPED for schema, source, freshness, HMAC, nonce, access, range, controller forwarding. No assumed pass for a later check. | `gateway/waterguard_gateway.py` |
| 6. Encryption and decryption proof | Actual stored canonical bytes, SHA-256, separate evidence HMAC, random AES nonce, ciphertext/tag, GCM decryption, recomputed checks, clear-column cross-check. Secret keys omitted. | `gateway/evidence_proof.py`, `gateway/evidence_store.py`, `shared/crypto_utils.py` |
| 7. Safe tamper demonstration | SQLite backup including WAL; single-bit mutation of selected ciphertext only in copy; failed verification; original row byte comparison and fresh verification. | `gateway/evidence_proof.py` |
| 8. Readiness and health | Observed client source, configured IP mapping, authenticated report, command fingerprint, evidence-key configuration, clock difference, launcher/capture heartbeat. | `dashboard/presentation_api.py`, `device_a/app.py`, `run_waterguard.py` |
| 9. Measured test summary | Actual expected-versus-observed outcomes, legitimate rejections, operational errors, WCP event IDs verified against protected SQLite records. No hardcoded zero false-positive claim. | `device_a/operations.py`, `dashboard/presentation_api.py`, `ui/common.js` |
| 10. Easier startup and presentation | Native Windows launcher, scoped firewall helper, environment reuse, Ubuntu client-only ZIP export, Ubuntu menu shortcut, practice mode, installation verification button, complete Action/Show/Say script. | `tools/launch_windows.py`, `tools/bootstrap_windows.py`, `tools/export_device_a_bundle.py`, `START_DEVICE_A.sh`, `ui/guide.html` |

The built-in SQLite explorer is included with the evidence presentation.
An external DB Browser installation is optional.

## Deployment

Windows hosts the gateway, controller, SQLite, and HTTPS dashboard. The
controller stays bound to `127.0.0.1:5502`. Ubuntu runs only Device A.
`Device_A_Only.zip` contains the command key and client modules; it excludes
the protected host's evidence keys, TLS private key, database, and server modules.
The exporter uses this Windows project's current command key when clicked.

The full ZIP keeps the original lab keys so it matches the already verified
installation. Keep it private. No old folder, database, or virtualenv is overwritten.
Historical copies previously transferred to Ubuntu do not disappear automatically.

## Security boundaries and limits

- Local proof/SQL reads require a loopback connection and a loopback Host header.
- Tamper-copy writes additionally require a local session token and matching Origin.
- Device A serves only on loopback and restricts Host headers. Browser JavaScript
  never contains secret keys. State changes still use the original WCP gateway.
- Device A reports use command-key HMAC, observed authorized source, fresh time,
  and an atomically claimed report nonce. WCP decisions are cross-checked against
  authentic event rows. A native Modbus exception has no WCP event ID.
- Network and controller failures are errors; a missing acknowledgement does not
  prove a security block or guarantee that no write reached the controller.
- AES protects detailed stored evidence. Indexable metadata stays readable.
  HMAC does not encrypt WCP; local Modbus also remains plaintext. The dashboard
  is HTTPS. The operator's Windows health/report connection relaxes certificate
  verification for this self-signed lab; it is not production TLS authentication.
- The process is simulated. Configured chlorine/valve ranges are prototype policy.
  Tank fill and pipe animation are visual aids. Flow uses the existing drift model.
- Replay cache state resets with the gateway. There is no immutable log chain,
  comprehensive DoS protection, or assurance after theft of all evidence keys.

See `VERIFICATION_REPORT.md` for execution evidence and remaining environment gates.
