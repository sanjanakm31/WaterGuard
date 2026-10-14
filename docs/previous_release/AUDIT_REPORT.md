> Historical report from the supplied ZIP. The October 6 update changes live analysis,
> controller binding, setup checks, and benchmark measurements. Read START_HERE.txt
> and UPDATE_NOTES.txt for current behavior and current verification limits.
> Earlier PASS/Complete labels are not a claim that this update was integration-tested on Windows.

# WaterGuard Codebase Audit

## Verdict

`waterguard_full_build_v2.zip` is the superior base. It cleanly separates the command protocol, inline gateway, controller, attacker, dashboard, capture, evidence and benchmarking layers. `WaterGuard_Codebase.zip` is a useful smaller prototype but does not provide the same complete, independently runnable OT pipeline.

The final package closes Version 2's material gaps: exact compatible dependency pins, current PyModbus APIs, one-command setup/launchers, ready local configuration, automated core and real-Modbus integration tests, database schema versioning, strict protocol validation, cache-poisoning protection, verified dashboard event data, browser-output escaping, capture-before-services ordering, complete terminal-decision evidence, and a fully authenticated forensic-export manifest.

## Material findings in the uploads

### Version A (`WaterGuard_Codebase.zip`)

- The FastAPI command endpoint and dashboard share port 8443 but the documented default is plain HTTP; TLS is deferred to another runbook step.
- The dashboard's `/api/process` reads an independent `WaterProcess` object rather than the protected controller state used by the gateway, so displayed state can diverge from Device B.
- Replay checking is a non-atomic database lookup followed by insertion only after controller forwarding. Two concurrent copies can both pass and reach Device B.
- PCAP protection encrypts only metadata; it does not AES-encrypt the exported capture bytes required by the synopsis.
- PyShark analysis only counts protocols and does not derive attack/detection indicators.
- Docker Compose contains fixed demonstration keys, exposes a command port the FastAPI implementation does not bind, and calls attacker CLI flags the parser does not support.
- No complete false-positive benchmark or deliberate tampering workflow is wired into the demo.

### Version B (`waterguard_full_build_v2.zip`)

- Its subsystem boundaries and inline enforcement path are substantially stronger than A.
- As uploaded, it had no tests, manually provisioned secrets/certificates, an old PyModbus range paired with APIs that have changed, and explicit unverified/next-phase caveats.
- Nonces were inserted before HMAC verification, permitting unauthenticated cache pollution.
- Dashboard HTML interpolated event data without escaping, and cleartext evidence columns were displayed without cross-checking them against the signed encrypted payload.
- Direct-Modbus PCAP detection compared source traffic to the controller destination setting rather than a configured trusted gateway source IP.

Those Version B issues are resolved in this final package. The final gateway also exposes a fail-closed native-Modbus intake so Device A can perform a genuine PyModbus attack against the inline gateway; this closes the synopsis wording gap created by using WCP as the authenticated client-side envelope.

## Strict gap analysis

| Synopsis requirement | Version A | Version B as uploaded | Final package |
|---|---|---|---|
| Water process/controller simulation | Basic process model and controller | Three live registers with simulated flow/chlorine drift | Complete; current PyModbus 3.15 API |
| Device A attack simulation | Small attack client | Broad WCP scenario suite, but the attacker-to-gateway leg was not native Modbus | Complete: broad suite plus genuine PyModbus write blocked at the gateway |
| Inline gateway | Present, coupled to web API | Dedicated WCP-to-Modbus protocol-break gateway | Complete; fail-closed |
| Source validation | Policy-level validation | Client/IP registry | Complete |
| HMAC-SHA256 command authentication | Present | Canonical authenticated command protocol | Complete; constant-time verification |
| Replay protection | Limited | Timestamp plus atomic nonce cache | Complete; unauthenticated traffic cannot poison cache |
| Register authorization/safety bounds | Present | Writable/read-only map and safe bounds | Complete |
| Block before controller mutation | Implemented in prototype flow | Explicit validate-then-forward path | Complete; integration-tested path included |
| SQLite evidence | Present | SQLite with encrypted payload and searchable metadata | Complete; schema version migration baseline added |
| SHA-256 + HMAC + AES event protection | Partial/smaller implementation | AES-256-GCM plus SHA-256 and HMAC | Complete; duplicate cleartext columns are cross-verified |
| PCAP capture with Wireshark/PyShark | Capture helper | Live capture module for both WCP and Modbus ports | Complete; launcher starts capture before services and finalizes it on shutdown |
| Programmatic PCAP analysis | Basic analyzer | Automated source/direct-Modbus/replay/malformed indicators | Complete |
| Protected PCAP export | Not complete end-to-end | Hash, HMAC, AES encrypted export and verification | Complete |
| HTTPS/TLS live dashboard | Basic static dashboard/API | FastAPI dashboard with self-signed TLS | Complete; verified evidence status and XSS-safe rendering |
| Detection latency/overhead/FPR benchmarks | Missing as a complete harness | Dedicated benchmark harness and JSON report | Complete |
| Normal, attack and tamper demo | Partial scripts | Full pipeline demo | Complete; one-command launcher also seeds live demo traffic |
| Automated tests | Three narrow unit tests | None | Core, protocol, gateway, evidence, export and real Modbus tests |
| Beginner deployment | Multi-step manual setup | Manual key/cert setup and “test it yourself” caveats | Windows and Linux setup launchers plus literal commands |
