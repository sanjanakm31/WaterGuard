# WaterGuard GUI v3 verification — 2026-10-09

All ten agreed additions are implemented. This report distinguishes actual
executed checks from environment-dependent integration gates.

## Executed successfully for this release

Development runtime: Python 3.12.14, cryptography 50.0.1, Node 24.19.0.
The deployment requirements retain the versions that already passed on the
user's Windows installation, including cryptography 46.0.0. That pinned
full environment was not available in this workspace.

| Check | Actual result | Scope |
|---|---|---|
| `test_update_regressions.py` | 11 unittest tests passed | Live/ offline stream handling, encrypted alerts, benchmark event correlation, SQLite connection lifecycle. PyShark packet inputs are fixtures. |
| `test_presentation_core.py` | 11 unittest tests passed | Real TCP gateway listeners; real SQLite and AES/HMAC; actual trace; blocked-write invariants; native Modbus exception bytes; original-safe tamper copy; command-only ZIP; operator unit conversion. Controller writes use `LoopbackTestForwarder`. |
| Full operator scenarios inside the above suite | 19/19 cases matched | 11 ALLOW and 8 BLOCK, with 18 WCP event IDs verified against stored evidence; native Modbus has no WCP event ID. These are local TCP tests, not a Windows-to-VM run. |
| JavaScript logic smoke | Passed | Genuine gateway fixture values, mocked DOM/API: actual value rendering, stale-value removal, proof rendering, escaping, error accounting, automatic BLOCK/ALLOW output. |
| Python compilation | Passed | All project Python files compile. |
| Bash syntax | Passed | Device A launcher. |
| JavaScript syntax | Passed | Common, operator, dashboard, and optional smoke-test scripts. |
| HTML/asset checks | Passed | Unique IDs; referenced UI elements exist; local assets resolve. |
| Archive / role audit | Passed | No runtime database/certificate/virtualenv; Device A archive excludes real evidence keys and server modules. |

Reproduce the independently runnable checks from the project root:

```text
python -m unittest discover -s tests -p "test_update_regressions.py" -v
python -m unittest discover -s tests -p "test_presentation_core.py" -v
```

Optional JavaScript logic check, when Node is installed:

```text
python -m tests.create_ui_test_fixtures ui-fixtures.json
node tests/ui_logic_smoke.js ui-fixtures.json
```

The temporary fixture is supporting test data, not a generated evidence
database shipped with the project. Node is not required to run the app.

## Windows verification and regression correction — 2026-10-09

The user's Windows launcher log confirms that the installation/capture check
passed and that the full pytest run completed with 41 passed and one failed.
The only reported failure was `test_unexpected_gateway_error_is_recorded`:
it deliberately raises an exception before processing, but its old assertions
expected BLOCK instead of the documented v3 ERROR classification.

The corrected test checks ERROR in both the response and encrypted evidence,
the matching event ID, the internal stage, intact evidence, and no controller
writes from this injected pre-processing failure. Application behavior is
unchanged; no security checks were removed or weakened.

The exact corrected test function was executed successfully over actual TCP
and SQLite in an isolated harness, with its two function definitions loaded
from the test source using Python's AST. This is not a pytest execution: pytest
is unavailable in the development workspace. The two independent unittest
suites above were also rerun successfully: 11 + 11 tests passed.

The user subsequently reran this suite on Windows: 42 passed in 6.44 seconds,
with the installation/capture check also passing. The supplied dashboard
screenshot showed CONTROLLER LIVE and readable simulated process values.

## Windows live-status and export correction — 2026-10-09

After that test run, the user's live launcher failed with WinError 5 while
replacing presentation_runtime.tmp with presentation_runtime.json. Shutdown
finalized the PCAP, analysis, encrypted export, and signed manifest. The file
replacement failure does not establish which Windows process held the file;
an incompatible reader/scanner handle or permissions can cause denial.

The runtime publisher now closes a unique temporary file before replacement,
retries PermissionError up to six times (0.75 seconds total delay), and treats
snapshot I/O failure as nonfatal telemetry. It preserves the previous complete
snapshot, cleans up its temporary file when possible, and rate-limits warnings.
The existing health endpoint marks snapshots older than five seconds unknown;
this correction does not turn a missing/stale heartbeat into a healthy result.
Actual controller/capture failure checks remain unchanged.

Client export now runs outside the UI thread, visibly reports success/failure,
opens the containing folder on success, and attaches dialogs to the launcher.
EXPORT_UBUNTU_CLIENT.bat provides a one-click direct exporter fallback.

New runtime regressions: six passed in this workspace, one skipped because it
requires Windows. They cover actual capture state, shutdown state, transient
replacement locks, prolonged locks and recovery, directory I/O failure, and
real TCP command/evidence processing after a denied snapshot update. Controller
writes in that TCP regression use the in-memory test forwarder. The Windows-only
test deliberately holds a real file handle without FILE_SHARE_DELETE.

Both previous independent unittest suites were rerun: 22 passed. The real
client exporter produced a valid 21-entry ZIP, with command credentials only.
The one-click update was exercised on a staged installation and preserves
existing .env, database, and virtual-environment files.

The expanded suite contains 49 cases on Windows. A full Windows pytest run and
live rehearsal of this new correction remain required; no 49-pass result or
real Windows reader-lock result is claimed from this workspace.

## Gates that could not be executed in this workspace

The workspace lacked FastAPI, Starlette, Uvicorn, PyModbus, PyShark, pytest,
TShark/Npcap, and a Chromium browser binary. Attempts to install the missing
packages were unsuccessful under the available network configuration.
No full framework, real PyModbus controller, real browser screenshot, Windows
UAC/firewall, Npcap capture, or VirtualBox two-device result is claimed here.

The original Windows release previously passed 22 tests on the user's laptop,
and the user previously demonstrated network ALLOW/BLOCK results across the VM.
Those are earlier-version results, not a substitute for checking this upgrade.

Run the new launcher's **Verify this installation before presenting** button
on Windows. It executes the environment/capture check and the full pytest suite,
including the new framework access-control/report-authentication tests.
Then rehearse the GUI scenario flow between Windows and Ubuntu using
`ui/guide.html`, checking real controller state, packet capture, evidence,
and original-safe tamper verification.

Manual equivalents in the verified Windows environment:

```text
python -m tools.check_environment --capture-test
python -m pytest -q
```

## What the evidence proves

- A stored validation trace describes checks actually executed for that request.
- Detailed evidence is authenticated and decrypted from the SQLite BLOB.
- A one-bit mutation in a disposable SQLite copy fails integrity verification,
  while the original selected row is compared and independently verified.
- An operator suite reports observed outcomes, including errors and unexpected
  legitimate rejections. Passing this suite is not a universal false-positive guarantee.
- A forwarding error means acknowledgement was not confirmed; it does not prove
  that a write could not have reached the controller before the connection failed.

See `FEATURES_V3.md` for deployment boundaries and limitations.
