# WaterGuard GUI Presentation Edition v3

Start with **START_HERE.txt**. On Windows double-click
**START_WINDOWS_OPERATIONS.bat**. Copy the exported **Device_A_Only.zip**
to your already working Ubuntu VM; run **bash START_DEVICE_A.sh** once.

The complete beginner Action / Show / Say script is **ui/guide.html**.
The feature list is **FEATURES_V3.md**. Current execution evidence and
limitations are **VERIFICATION_REPORT.md**. The GUI launcher's verification
button runs the full suite on your Windows installation.

Original commands and source modules below remain available. Earlier
reports are archived under **docs/previous_release** and do not establish
that this GUI release has passed a Windows/VirtualBox/browser integration run.

---

# WaterGuard — Complete Local OT IDS/IPS Simulation

**October 6 update:** Start with `START_HERE.txt`. No manual code replacements are needed.
`UPDATE_NOTES.txt` contains the exact change list and the tests actually run for this update.
The complete Windows/PyModbus/HTTPS/TShark integration still needs verification on your machine.

WaterGuard is an inline intrusion detection and prevention prototype for a simulated water-control process. An authenticated WaterGuard Command Protocol (WCP) message reaches the security gateway first; only commands that pass source, freshness, HMAC-SHA256, register-access and safety checks are forwarded to Device B over Modbus TCP. Every ALLOW and BLOCK decision is SHA-256 hashed, HMAC-signed, AES-256-GCM encrypted and stored in SQLite.

This package is intended for a controlled classroom/lab demonstration. It must never be connected to real water infrastructure or a production industrial-control network.

## What is included

- Simulated protected controller with chlorine dosing, valve position and live flow sensor registers.
- Inline protocol-break gateway that blocks before mutation.
- Legitimate HMI client and controlled attacker scenarios.
- Replay protection with timestamps and atomic nonces.
- Versioned SQLite evidence schema and cryptographic integrity verification.
- Launcher-managed TShark recording, live PyShark ALERT events, and offline forensic analysis.
- SHA-256, HMAC and AES protected PCAP export.
- FastAPI live dashboard served over HTTPS with a generated self-signed certificate.
- Latency, gateway-overhead and false-positive benchmarking.
- Deliberate evidence-tampering demonstration.
- Automated unit and real-Modbus integration tests.
- One-command Windows and Linux setup/launch scripts.

The original-codebase comparison is in `docs/previous_release/AUDIT_REPORT.md`; the requirement map is in `docs/previous_release/SYNOPSIS_COMPLIANCE_MATRIX.md`. Older verification claims do not establish that this update has passed a Windows integration run.

## Architecture

```text
Legitimate HMI -> WCP authenticated JSON :6000 ┐
                                                v
Device A -> native Modbus attack :1502 ------> WaterGuard gateway
                                                |  raw Modbus: BLOCK
                                                |  valid WCP: source -> freshness
                                                |  -> HMAC -> access -> safety
                                                v
                         native Modbus :5502 -> Device B controller

Gateway decisions -> SHA-256 + HMAC + AES-256-GCM -> SQLite
Dashboard :8443 HTTPS -> verified evidence + live Modbus telemetry
PyShark/TShark -> PCAP -> analyzer -> encrypted forensic export
```

## Register map

| Address | Meaning | Startup | Gateway policy |
|---:|---|---:|---|
| 0 | Chlorine dosing, hundredths of ppm | 150 (1.50 ppm) | Writable, safe 20–400 |
| 1 | Valve position, percent | 50 | Writable, safe 10–90 |
| 2 | Flow sensor, L/min | 120 | Read-only |

## Prerequisites

For the normal application you need:

1. **Python 3.12.10 (64-bit)** — https://www.python.org/downloads/release/python-31210/  
   On Windows, select **Add Python to PATH** in the installer.
2. **Wireshark with TShark and Npcap** — https://www.wireshark.org/download.html  
   The default launcher starts capture before any service. Keep the installer's default selections, including TShark and Npcap.
3. **Git (optional)** — https://git-scm.com/downloads  
   Git is not required when using the downloaded ZIP.
4. **Visual Studio Code (optional editor named in the synopsis)** — https://code.visualstudio.com/download
5. Chrome or Firefox for the dashboard.

No separate database installation is required: SQLite is built into Python. Node.js, Java and a GPU are not required.

The synopsis lists an Intel Core i5-class processor (or AMD equivalent), 8 GB RAM minimum (16 GB recommended), 100 GB available storage, and local networking. The localhost demonstration itself consumes only a small fraction of that storage; the larger allowance accommodates VM images and accumulated PCAP evidence.

The source tree is Git-ready through `.gitignore`. GitHub hosting is optional and requires the owner's GitHub account/repository authorization, so it is not needed to install or run this downloadable build.

## Windows 10/11: exact beginner steps

1. Download and extract the updated ZIP into a new folder.
2. Open the extracted `waterguard` folder.
3. Click the File Explorer address bar, type `cmd`, and press Enter.
4. Copy, paste and run this one command:

```bat
setup_windows.bat
```

The script creates an isolated Python environment, installs exact dependencies, runs all tests, starts capture before Device B, the gateway and HTTPS dashboard, sends normal and attack traffic, and opens the browser. Accept the expected self-signed-certificate warning for `https://localhost:8443`.

After the first setup, start the project on later days by double-clicking
`start_windows.bat`, or from PowerShell:

```powershell
.\start_windows.bat
```

Keep that terminal window open. The dashboard only exists while WaterGuard
is running; pressing Ctrl+C stops every service.

On later runs, open the same folder in Command Prompt and use:

```bat
.venv\Scripts\python.exe run_waterguard.py
```

Press Ctrl+C in the launcher window to stop all services. WaterGuard then closes the PCAP, analyzes it, and creates its encrypted export and signed manifest automatically under `data/captures/`.

## Ubuntu/Debian Linux: exact beginner steps

Open Terminal in the extracted `waterguard` folder and run:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip tshark wireshark
chmod +x setup_linux.sh
./setup_linux.sh
```

During the Wireshark prompt, allowing non-superusers to capture packets is convenient for this lab. If capture permission is denied later, run the capture command with `sudo` or follow your distribution's Wireshark-group instructions.

On later runs:

```bash
.venv/bin/python run_waterguard.py
```

Press Ctrl+C to stop all services and finalize the capture, analysis, and protected export.

## Manual commands

These are useful if you want separate terminals for a presentation. Run setup once first, then activate the environment.

Windows activation:

```bat
.venv\Scripts\activate.bat
```

Linux activation:

```bash
source .venv/bin/activate
```

Start one component per terminal, in this order:

```bash
python -m controller.device_b_controller
python -m gateway.waterguard_gateway
python -m dashboard.app
```

Open `https://localhost:8443`, then in another activated terminal run:

```bash
python -m client.legit_hmi_client --register 1 --value 55
python -m client.legit_hmi_client --register 0 --value 180
python -m attacker.device_a_attacker run-all
python -m attacker.device_a_attacker unauthenticated-modbus
python -m tools.verify_evidence_integrity
```

## Required demonstration workflows

### Fast self-test without a real Modbus process

```bash
python run_local_pipeline_demo.py
```

This runs legitimate commands, the complete authenticated-protocol attack suite (including the native unauthenticated Modbus/TCP block), evidence verification, deliberate ciphertext tampering and post-tamper detection. It exits with status 0 only if all expected outcomes pass.

### Deliberate tamper test

Use a disposable demo database because this intentionally corrupts its newest record:

```bash
python -m tools.verify_evidence_integrity
python -m attacker.device_a_attacker evidence-tampering
python -m tools.verify_evidence_integrity
```

The second verification must report exactly one `TAMPERED` record. Delete `data/waterguard_evidence.db` afterward if you want a fresh lab database; the application recreates it automatically.

### Benchmarking

With Device B and the gateway running:

```bash
python -m benchmarking.benchmark_gateway --iterations 300
```

The JSON result is written to `data/benchmark_report.json`. It includes end-to-end round-trip latency, verified gateway processing time and false-positive rate.

### PCAP capture and analysis

`run_waterguard.py` does this automatically and starts capture before any network service. It auto-selects the loopback interface on normal Windows and Linux installations. On shutdown it creates the original `.pcapng`, an `.analysis.json` report, an AES-encrypted `.export.enc` copy, and its signed manifest under `data/captures/`.

If automatic selection cannot identify a loopback adapter, list interfaces and pass the exact result:

```bash
tshark -D
python run_waterguard.py --capture-interface lo
```

Use `--no-capture` only when deliberately running without the synopsis-required PCAP evidence.

For a separate manual capture session, first list interfaces:

```bash
tshark -D
```

Linux loopback example (run while the demo/attacks execute in another terminal):

```bash
python -m capture.pcap_capture --interface lo --duration 30 --output data/captures/attack_run.pcap
python -m capture.pcap_analyzer --pcap data/captures/attack_run.pcap
python -m tools.export_evidence_pcap --file data/captures/attack_run.pcap
python -m tools.export_evidence_pcap --verify --file data/captures/attack_run.pcap.export.enc --manifest data/captures/attack_run.pcap.export.manifest.json
```

On Windows, replace `lo` with the interface number or name shown by `tshark -D` (usually the Npcap loopback adapter). The original PCAP remains unchanged; the export command creates an encrypted `.export.enc` file and signed manifest beside it.

## Configuration and secrets

The included `.env` is a ready-to-run local lab configuration. It contains unique prototype keys so the first run needs no manual editing. Before copying the project to another computer, committing it, or deploying across VMs, regenerate keys:

```bash
python -m tools.generate_secrets
```

Put the three printed values into `.env`. Do not commit `.env`, `tls/`, or `data/`. `.gitignore` already excludes them.

| Setting | Default | Purpose |
|---|---|---|
| `WG_AUTHORIZED_SOURCES` | `hmi-01=127.0.0.1` | Allowed client ID/IP pairs |
| `WG_CONTROLLER_HOST` | `127.0.0.1` | Device B address seen by gateway/dashboard |
| `WG_CONTROLLER_MODBUS_PORT` | `5502` | Protected Modbus port |
| `WG_GATEWAY_TRUSTED_IP` | `127.0.0.1` | Expected gateway source IP in PCAP analysis |
| `WG_GATEWAY_WCP_PORT` | `6000` | Authenticated command port |
| `WG_GATEWAY_MODBUS_PORT` | `1502` | Untrusted native-Modbus port; always fail-closed |
| `WG_DASHBOARD_PORT` | `8443` | HTTPS dashboard port |
| `WG_CAPTURE_INTERFACE` | `auto` | Launcher capture interface; auto-selects loopback |
| `WG_REPLAY_WINDOW_SECONDS` | `5.0` | Maximum command clock skew/age |

The launcher generates `tls/dashboard_cert.pem` and `tls/dashboard_key.pem` automatically if absent. The certificate is deliberately self-signed for this local prototype, so browsers show a warning.

## Multi-VM lab deployment

For two computers, use Laptop B for the gateway, dashboard, and controller; use
Laptop A for the clients. Device B now binds to `127.0.0.1` by default, so remote
clients cannot bypass the gateway by connecting directly to controller port 5502.
This does not isolate untrusted programs already running on Laptop B itself.
Use a LAN capture interface AND loopback when showing both network legs;
`--capture-interface` accepts comma-separated names (Linux can use `any`).
The exact two-device walkthrough is separate from this setup update.

The following optional THREE-VM layout needs an explicit controller bind address:

1. Put Device B on VM 1, the gateway/dashboard on VM 2, and HMI/attacker on VM 3.
2. Install the project dependencies on each VM.
3. Copy matching `WG_COMMAND_HMAC_KEY` values to gateway and legitimate HMI environments. Evidence keys stay on the gateway/dashboard VM.
4. On the gateway VM set `WG_CONTROLLER_HOST` to VM 1's IP.
5. Set `WG_AUTHORIZED_SOURCES=hmi-01=<VM 3 IP>` on the gateway VM.
6. Firewall VM 1 TCP/5502 so only VM 2 can connect. This prevents direct Modbus bypass.
7. Firewall VM 2 TCP/6000 and TCP/1502 to the lab subnet and TCP/8443 to dashboard viewers.
8. Start Device B with `--host <VM_1_LAN_IP>` only after the firewall rules are configured, then gateway, dashboard, and HMI/attacker.

Source-IP checks are a first-pass signal, not identity proof; HMAC is the actual command authentication mechanism. Modbus is deliberately confined to the trusted gateway-to-controller segment.

## Tests

```bash
python -m pytest -q
```

The suite covers strict WCP parsing, cryptography and tamper detection, inline gateway allow/block behavior, raw-Modbus blocking, encrypted SQLite evidence, encrypted PCAP-style export, the real PyModbus controller-to-gateway path, and actual HTTPS dashboard startup/API responses.

## Troubleshooting

- **`python` or `py` not found:** reinstall Python and enable **Add Python to PATH**.
- **Port already in use:** close old WaterGuard terminals, then rerun. Defaults are 1502, 5502, 6000 and 8443.
- **Dashboard certificate warning:** expected for the included self-signed local certificate; continue only for `localhost`/your controlled lab IP.
- **Browser says localhost refused to connect:** keep the WaterGuard terminal open and use the complete address `https://localhost:8443/` (HTTPS plus port 8443). Wait for `WATERGUARD IS READY` before opening it. If you already pressed Ctrl+C, start it again with `start_windows.bat`.
- **TShark not found:** reinstall Wireshark and ensure the TShark component is selected. On Windows its default path is `C:\Program Files\Wireshark`.
- **Capture permission denied:** use an Administrator terminal on Windows; on Linux configure Wireshark capture permissions or run only the capture command with `sudo`.
- **Tests fail after changing dependencies:** delete `.venv`, restore `requirements.txt`, and rerun the setup script. Dependency versions are intentionally pinned.

## Project layout

```text
waterguard/
├── run_waterguard.py             one-command real-stack launcher
├── run_local_pipeline_demo.py    deterministic full security proof
├── setup_windows.bat
├── setup_linux.sh
├── requirements.txt
├── .env / .env.example
├── SYNOPSIS_COMPLIANCE_MATRIX.md     exact synopsis-to-code mapping
├── shared/                       configuration, crypto, WCP
├── controller/                   Device B and Modbus forwarder
├── gateway/                      inline enforcement and evidence DB
├── client/                       legitimate HMI
├── attacker/                     controlled attack scenarios
├── capture/                      managed/manual PCAP capture and PyShark analyzer
├── dashboard/                    HTTPS live UI/API
├── benchmarking/                 latency/overhead/FPR report
├── tools/                        secrets, TLS, verification, export
└── tests/                        automated core and real-stack tests
```

## Safety and license

Run only on localhost or an isolated lab network you own or are authorized to test. The attacker module is for controlled academic demonstration. See `LICENSE` for software licensing terms.
