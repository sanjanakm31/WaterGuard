WATERGUARD WINDOWS LIVE-STATUS / EXPORT UPDATE

Your current project was reported at:
C:\Users\sanjana\Downloads\WaterGuard_Presentation_v3 (1)\waterguard

1. Wait until the old launcher has stopped, then close it.
2. Extract the new ZIP into any NEW folder. Open its waterguard folder.
3. Double-click FIX_WINDOWS_STATUS_AND_EXPORT.bat. Keep its window visible.
4. Check for UPDATE APPLIED. It prints the existing folder it updated.
5. Reopen START_WINDOWS_OPERATIONS.bat inside that EXISTING project folder.
6. Verify the installation, then Start WaterGuard with Ubuntu 192.168.0.190
   and capture 5,9 if those values are still current.
7. Click Export Ubuntu client ZIP. Success opens the containing folder.
   Alternatively double-click EXPORT_UBUNTU_CLIENT.bat in that project folder.

The update touches source/tests/documentation only. It preserves .env, the
SQLite database, packet captures, TLS files, settings, and Python environments.
Changed code is backed up under data/code-update-backups before replacement.
The updater refuses to change a project while the lab's service ports are in
use. It does not terminate processes or change administrator permissions.

The Windows snapshot error is now nonfatal telemetry with bounded retries.
System health still reports an old or missing status snapshot as unknown.
The new Windows pytest suite has 49 cases, including an actual file-lock test.
Development testing is described in VERIFICATION_REPORT.md; verify the final
result on Windows and rehearse the VM connection before presenting.
