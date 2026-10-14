> Historical report from the supplied ZIP. The October 6 update changes live analysis,
> controller binding, setup checks, and benchmark measurements. Read START_HERE.txt
> and UPDATE_NOTES.txt for current behavior and current verification limits.
> Earlier PASS/Complete labels are not a claim that this update was integration-tested on Windows.

# WaterGuard Synopsis Compliance Matrix

This matrix maps every implementation-bearing statement in `Sanjana_Project-Synopsis.pdf` to executable code in this release.

| Synopsis requirement | Implementation | Verification | Status |
|---|---|---|---|
| Simplified water controller/process with sensors and actuators | `controller/device_b_controller.py`: `_build_context`, `_process_simulation_loop`; `shared/config.py`: register map | Real-stack integration test reads/writes protected registers | Complete |
| Chlorine dosing and valve state | Holding registers 0 and 1 with startup values and policy bounds | Core and real-stack tests | Complete |
| Simulated live sensor | Read-only flow register 2 changes in the controller process loop | Dashboard state API and controller implementation | Complete |
| Device A unauthorized/unsafe Modbus activity | `attacker/device_a_attacker.py`: `attack_unauthenticated_modbus`, unsafe/replay/forgery/source scenarios | Core and real-stack tests; local nine-scenario proof | Complete |
| Device B protected controller | PyModbus TCP server in `controller/device_b_controller.py` | `tests/test_real_stack.py` | Complete |
| Inline security gateway | `gateway/waterguard_gateway.py`: WCP enforcement pipeline and fail-closed raw-Modbus intake | Allow/block isolation assertions | Complete |
| Capture before requests traverse the demo | `capture/managed_capture.py`; started before Device B by `run_waterguard.py` | Launcher ordering plus interface-parser tests | Complete |
| Wireshark/TShark network capture | Managed capture plus `capture/pcap_capture.py`; BPF covers ports 1502, 5502, and 6000 | Capture artifact generated on launcher run | Complete |
| Automatic PyShark analysis | `capture/pcap_analyzer.py`: source, raw-Modbus, bypass, replay, malformed indicators | Live ALERTs during capture; offline summary on shutdown | Complete |
| Source validation | Client-ID/IP registry and exact peer-IP comparison in gateway stage 1 | Unauthorized and spoofed-source attacks | Complete |
| HMAC-SHA256 command authentication | Canonical WCP payload and constant-time tag verification | Valid, forged, and corrupted command tests | Complete |
| Replay prevention | Timestamp window plus atomic authenticated-nonce cache | Immediate and aged replay scenarios | Complete |
| Register authorization | Writable and read-only register sets | Restricted-register scenario | Complete |
| Safety validation | Per-register minimum/maximum policy in `shared/config.py` | Unsafe chlorine scenario | Complete |
| Block before physical effect | Validation completes before `forwarder.write_register` | Exact forwarded-write lists asserted | Complete |
| Forward approved requests over Modbus | `RealModbusForwarder` uses PyModbus client API | Real controller/gateway integration test | Complete |
| Record every ALLOW/BLOCK terminal outcome | `_allow`, `_reject`, raw-Modbus handler, and internal-error handler | Evidence-row checks, including regression test for unexpected errors | Complete |
| SHA-256 security-event hash | `crypto_utils.sha256_hex` called by `evidence_store.record_event` | Recomputed during verification | Complete |
| HMAC-sign security events | Evidence HMAC over event hash | Correct and tampered records tested | Complete |
| AES-encrypt security events | AES-256-GCM encrypted canonical event payload | Decrypt/verify and tamper tests | Complete |
| SQLite evidence store | Versioned `security_events` schema and indexes | Database created automatically | Complete |
| Protected PCAP export | `tools/export_evidence_pcap.py`: hash, HMAC, AES-256-GCM, manifest | Round-trip and ciphertext-tamper test | Complete |
| Preserve original PCAP | Export reads and writes separate files | Source bytes asserted unchanged | Complete |
| HTTPS/TLS dashboard | FastAPI/Uvicorn with generated self-signed certificate | Actual HTTPS boot/API test | Complete |
| Live process state | `/api/state` reads Device B registers; browser polls every 1.5 seconds | Dashboard boot/API test | Complete |
| Live security events | `/api/events` returns decrypted, verified evidence only | Dashboard boot/API test and output escaping | Complete |
| Detection latency | Gateway records per-decision processing time | Benchmark report statistics | Complete |
| Gateway overhead | Verified internal processing-time samples | Min/mean/median/p95/p99/max/stdev report | Complete |
| False-positive rate | Legitimate signed in-bounds command batch | Count and percentage report | Complete |
| Normal-operation demonstration | Legitimate HMI commands in both launchers | ALLOW and controller mutation assertions | Complete |
| Live attack demonstration | Launcher seeds unauthorized, forged, unsafe, restricted, raw-Modbus, and replay traffic | Dashboard/evidence receives results | Complete |
| Deliberate tampering demonstration | Attacker flips encrypted evidence bytes; verifier isolates the record | Local proof: exactly one tampered row | Complete |
| Windows 10/11 and Linux | Windows batch and Debian/Ubuntu shell launchers | Python compilation and shell syntax checks | Complete |
| Intel i5/equivalent, 8 GB RAM, 100 GB storage, local network, no GPU | Exact hardware guidance and VM/PCAP rationale in `README.md` | Application has no GPU dependency | Documented and compatible |
| Python, PyModbus, PyShark, cryptography, FastAPI, SQLite, HTML/JS | Exact dependency manifest plus standard-library SQLite and browser UI | Import/dependency audit | Complete |
| Chrome/Firefox interface | Standards-based HTTPS HTML/JS dashboard | No browser-specific API dependency | Complete |
| Git/GitHub and VS Code | `.gitignore`, source-ready tree, and documented optional installation links | Does not affect runtime | Complete within distributable source scope |

## Explicit boundaries—not missing features

- The synopsis expressly limits the project to a controlled simulation. This release targets that lab scope; it is not certified or authorized for real water infrastructure.
- Self-signed TLS is the prototype mechanism explicitly permitted by the synopsis. A public production hostname would require a CA-issued certificate and site-specific key custody.
- Raw Modbus cannot carry an HMAC field. The untrusted Modbus listener therefore fails closed, while legitimate commands use an authenticated WCP envelope and are translated to Modbus only on the protected side of the gateway.
- Packet capture requires the operating system's TShark/Npcap or dumpcap permission. The default launcher now starts capture automatically and fails with an actionable message if this prerequisite is absent. `--no-capture` is an explicit operator override, not the default.
- No dashboard login roles are added because the synopsis defines system actors (attacker, gateway, controller, legitimate command source), not application user accounts or authorization roles.
- A GitHub remote cannot be provisioned without the owner's account and repository authorization. The package is Git-ready and runs without GitHub.
