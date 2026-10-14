"""Windows snapshot-lock regressions; no web framework is needed."""
import contextlib
import ctypes
import io
import json
import os
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import run_waterguard


class RuntimeStatusTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.root_patch = patch.object(run_waterguard, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.addCleanup(self.directory.cleanup)
        self.target = self.root / "data" / "presentation_runtime.json"
        self.capture = SimpleNamespace(
            _process=SimpleNamespace(poll=lambda: None),
            _monitor_process=SimpleNamespace(poll=lambda: None),
            interface="5,9", output_path=self.root / "capture.pcapng",
        )

    def seed_snapshot(self):
        self.target.parent.mkdir(parents=True, exist_ok=True)
        original = b'{"state":"running","updated_at":1}'
        self.target.write_bytes(original)
        return original

    def test_snapshot_reports_actual_capture_liveness(self):
        self.assertTrue(run_waterguard.write_runtime_status(self.capture, "running"))
        record = json.loads(self.target.read_text(encoding="utf-8"))
        self.assertTrue(record["capture_recorder_active"])
        self.assertTrue(record["capture_detector_active"])
        self.assertEqual(record["capture_interface"], "5,9")
        self.capture._monitor_process.poll = lambda: 1
        self.assertTrue(run_waterguard.write_runtime_status(self.capture, "running"))
        self.assertFalse(json.loads(self.target.read_text())["capture_detector_active"])
        self.assertEqual(list(self.target.parent.glob("*.tmp")), [])

    def test_shutdown_does_not_report_capture_as_active(self):
        self.assertTrue(run_waterguard.write_runtime_status(self.capture, "stopped"))
        record = json.loads(self.target.read_text())
        self.assertEqual(record["state"], "stopped")
        self.assertFalse(record["capture_recorder_active"])
        self.assertFalse(record["capture_detector_active"])

    def test_transient_replace_lock_is_retried_atomically(self):
        original = self.seed_snapshot()
        replace = Path.replace
        attempts = []

        def briefly_locked(source, target):
            attempts.append(source)
            if len(attempts) < 3:
                self.assertEqual(self.target.read_bytes(), original)
                raise PermissionError("simulated Windows sharing lock")
            return replace(source, target)

        with patch.object(Path, "replace", briefly_locked), patch.object(run_waterguard.time, "sleep") as sleep:
            self.assertTrue(run_waterguard.write_runtime_status(self.capture, "running"))
        self.assertEqual(len(attempts), 3)
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(len(set(attempts)), 1)
        self.assertEqual(json.loads(self.target.read_text())["state"], "running")
        self.assertEqual(list(self.target.parent.glob("*.tmp")), [])

    def test_long_lock_preserves_snapshot_and_next_heartbeat_recovers(self):
        original = self.seed_snapshot()
        with patch.object(Path, "replace", side_effect=PermissionError("locked")) as replace, \
                patch.object(run_waterguard.time, "sleep"), \
                patch.object(run_waterguard, "_runtime_warning_at", float("-inf")), \
                contextlib.redirect_stderr(io.StringIO()) as warning:
            self.assertFalse(run_waterguard.write_runtime_status(self.capture, "running"))
        self.assertEqual(replace.call_count, 6)
        self.assertIn("LIVE STATUS WARNING", warning.getvalue())
        self.assertEqual(self.target.read_bytes(), original)
        self.assertEqual(list(self.target.parent.glob("*.tmp")), [])
        self.assertTrue(run_waterguard.write_runtime_status(self.capture, "running"))
        self.assertGreater(json.loads(self.target.read_text())["updated_at"], 1)

    def test_status_directory_error_is_nonfatal_and_visible(self):
        self.target.parent.write_text("a file occupies the status directory")
        with patch.object(run_waterguard, "_runtime_warning_at", float("-inf")), \
                contextlib.redirect_stderr(io.StringIO()) as warning:
            self.assertFalse(run_waterguard.write_runtime_status(None, "running"))
        self.assertIn("LIVE STATUS WARNING", warning.getvalue())

    def test_snapshot_lock_does_not_disable_command_processing(self):
        from client.legit_hmi_client import build_signed_message, send_message
        from controller.modbus_forwarder import LoopbackTestForwarder
        from gateway import evidence_store
        from gateway.waterguard_gateway import WaterGuardGateway
        from shared import config

        def free_port():
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                return sock.getsockname()[1]

        port, native = free_port(), free_port()
        while port == native:
            native = free_port()
        forwarder = LoopbackTestForwarder()
        with patch.object(evidence_store, "DB_PATH", self.root / "evidence.db"), \
                patch.dict(config.AUTHORIZED_SOURCES, {"hmi-01": "127.0.0.1"}, clear=True):
            gateway = WaterGuardGateway(forwarder, host="127.0.0.1", port=port,
                                       modbus_intake_port=native)
            gateway.start(blocking=False)
            try:
                with patch.object(Path, "replace", side_effect=PermissionError("locked")), \
                        patch.object(run_waterguard.time, "sleep"), \
                        contextlib.redirect_stderr(io.StringIO()):
                    self.assertFalse(run_waterguard.write_runtime_status(self.capture, "running"))
                response = send_message(build_signed_message("hmi-01", 1, 70),
                                        gateway_host="127.0.0.1", gateway_port=port)
                self.assertEqual(response["decision"], "ALLOW")
                self.assertEqual(forwarder.written, [(1, 70)])
                self.assertEqual(evidence_store.fetch_recent_events()[0]["integrity_status"], "INTACT")
            finally:
                gateway.stop()

    @unittest.skipUnless(os.name == "nt", "Requires an actual Windows file handle")
    def test_real_windows_reader_lock_recovers_without_deleting_old_status(self):
        from ctypes import wintypes

        original = self.seed_snapshot()
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                      wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                                      wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        # Share read/write, but deliberately withhold FILE_SHARE_DELETE.
        handle = kernel.CreateFileW(str(self.target), 0x80000000, 1 | 2,
                                    None, 3, 0x80, None)
        self.assertNotEqual(handle, ctypes.c_void_p(-1).value,
                            f"CreateFileW failed: {ctypes.get_last_error()}")
        try:
            with patch.object(run_waterguard.time, "sleep"), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertFalse(run_waterguard.write_runtime_status(self.capture, "running"))
            self.assertEqual(self.target.read_bytes(), original)
        finally:
            kernel.CloseHandle(handle)
        self.assertTrue(run_waterguard.write_runtime_status(self.capture, "running"))
        self.assertGreater(json.loads(self.target.read_text())["updated_at"], 1)


if __name__ == "__main__":
    unittest.main()
