"""Regression tests runnable with unittest even when pytest is unavailable.

These exercise classification, TCP segmentation/retransmission handling,
encrypted live alerts, and benchmark-to-evidence correlation. They do NOT
substitute for actual TShark/Npcap, PyModbus, or HTTPS integration tests.
"""
from __future__ import annotations

import json
from pathlib import Path
import socket
import sqlite3
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from benchmarking.benchmark_gateway import run_benchmark
from capture.live_monitor import LineBuffer, LiveDetector, record_indicator
from client.legit_hmi_client import build_signed_message
from controller.modbus_forwarder import LoopbackTestForwarder
from gateway import evidence_store
from gateway.waterguard_gateway import WaterGuardGateway
from shared import config


def wire(message):
    return json.dumps(message, separators=(",", ":")).encode() + b"\n"


def packet(stream, sequence, payload=b"", *, syn=False, port=None):
    return SimpleNamespace(
        ip=SimpleNamespace(src="127.0.0.1"), sniff_timestamp=str(time.time()), number="1",
        tcp=SimpleNamespace(
            dstport=str(port or config.GATEWAY_WCP_PORT), stream=str(stream), seq=str(sequence),
            flags_syn="1" if syn else "0", flags_ack="0" if syn else "1",
            payload=payload.hex(":"),
        ),
    )


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class LiveDetectionTests(unittest.TestCase):
    def test_safe_signed_command_is_not_an_alert(self):
        detector = LiveDetector()
        message = build_signed_message("hmi-01", 0, 180)
        self.assertIsNone(detector.inspect_command(wire(message), "127.0.0.1", time.time()))

    def test_unsafe_forged_and_stale_messages(self):
        detector = LiveDetector()
        unsafe = build_signed_message("hmi-01", 0, 2500)
        self.assertEqual(detector.inspect_command(wire(unsafe), "127.0.0.1", time.time())["reason"], "pcap_unsafe_setpoint")
        forged = build_signed_message("hmi-01", 1, 50)
        forged["hmac"] = "00" * 32
        self.assertEqual(detector.inspect_command(wire(forged), "127.0.0.1", time.time())["reason"], "pcap_invalid_hmac")
        stale = build_signed_message("hmi-01", 1, 50, timestamp=time.time() - 60)
        self.assertEqual(detector.inspect_command(wire(stale), "127.0.0.1", time.time())["reason"], "pcap_replay_attack")

    def test_retransmission_is_not_a_replay_but_new_connection_is(self):
        detector = LiveDetector()
        data = wire(build_signed_message("hmi-01", 1, 50))
        self.assertEqual(detector.inspect_packet(packet(1, 0, syn=True)), [])
        self.assertEqual(detector.inspect_packet(packet(1, 1, data)), [])
        self.assertEqual(detector.inspect_packet(packet(1, 1, data)), [])
        detector.inspect_packet(packet(2, 0, syn=True))
        alerts = detector.inspect_packet(packet(2, 1, data))
        self.assertEqual([alert["reason"] for alert in alerts], ["pcap_replay_attack"])

    def test_out_of_order_fragments_produce_one_complete_alert(self):
        detector = LiveDetector()
        data = wire(build_signed_message("hmi-01", 0, 2500))
        cut = len(data) // 2
        detector.inspect_packet(packet(3, 0, syn=True))
        self.assertEqual(detector.inspect_packet(packet(3, 1 + cut, data[cut:])), [])
        alerts = detector.inspect_packet(packet(3, 1, data[:cut]))
        self.assertEqual([alert["reason"] for alert in alerts], ["pcap_unsafe_setpoint"])
        self.assertEqual(detector.inspect_packet(packet(3, 1, data)), [])

    def test_overlapping_segments_and_bounded_oversize(self):
        buffer = LineBuffer(expected=1)
        self.assertIsNone(buffer.feed(1, b"abcd"))
        self.assertEqual(buffer.feed(3, b"cdef\n"), b"abcdef")
        buffer = LineBuffer(expected=1)
        output = buffer.feed(1, b"x" * (config.MAX_WCP_MESSAGE_BYTES + 10))
        self.assertGreater(len(output), config.MAX_WCP_MESSAGE_BYTES)
        self.assertTrue(buffer.finished)

    def test_raw_modbus_payload_alerts_once_per_stream(self):
        detector = LiveDetector()
        attempt = packet(4, 1, b"\x00\x01\x00\x00", port=config.GATEWAY_MODBUS_PORT)
        self.assertEqual(detector.inspect_packet(attempt)[0]["reason"], "pcap_unauthenticated_modbus")
        self.assertEqual(detector.inspect_packet(attempt), [])


class EvidenceAndBenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wg_update_tests_")
        self.patch = patch.object(evidence_store, "DB_PATH", Path(self.temp.name) / "evidence.db")
        self.patch.start()
        evidence_store.init_db()

    def tearDown(self):
        self.patch.stop()
        self.temp.cleanup()

    def test_live_alert_is_encrypted_and_verified(self):
        record_indicator({"peer_ip": "127.0.0.1", "reason": "pcap_invalid_hmac",
                          "captured_at": time.time(), "frame": "5", "stream": "1"})
        raw = evidence_store.fetch_all_raw_rows()[0]
        ok, record, _ = evidence_store.decrypt_and_verify_event(raw)
        self.assertTrue(ok)
        self.assertEqual(record["decision"], "ALERT")
        self.assertEqual(record["stage"], "live_pcap_analysis")
        self.assertNotIn(b"pcap_invalid_hmac", raw["encrypted_payload"])

    def test_benchmark_uses_exact_events_and_reports_each_attack(self):
        record_indicator({"peer_ip": "127.0.0.1", "reason": "unrelated_alert",
                          "captured_at": time.time(), "frame": "5", "stream": "1"})
        port, modbus_port = free_port(), free_port()
        while modbus_port == port:
            modbus_port = free_port()
        forwarder = LoopbackTestForwarder()
        gateway = WaterGuardGateway(forwarder, host="127.0.0.1", port=port, modbus_intake_port=modbus_port)
        gateway.start(blocking=False)
        try:
            report = run_benchmark(2, "127.0.0.1", port, forwarder)
        finally:
            gateway.stop()
        self.assertEqual(report["legitimate"]["false_positive_rate_pct"], 0)
        self.assertEqual(report["direct_modbus"]["round_trip_ms"]["count"], 2)
        self.assertEqual(report["paired_gateway_minus_direct_round_trip_ms"]["count"], 2)
        self.assertEqual(report["internal_timings"]["verified_event_count"], 12)
        self.assertEqual(report["internal_timings"]["validation_before_forward_ms"]["count"], 2)
        self.assertEqual(report["internal_timings"]["complete_message_to_block_before_evidence_ms"]["count"], 10)
        for result in report["attacks"].values():
            self.assertEqual(result["correct_blocks"], 2)
            self.assertEqual(result["unexpected_allows"], 0)
            self.assertEqual(result["operational_errors"], 0)


class EvidenceConnectionLifecycleTests(unittest.TestCase):
    def test_every_store_operation_closes_its_sqlite_connection(self):
        with tempfile.TemporaryDirectory(prefix="wg_connection_tests_") as folder:
            opened = []
            original_connect = evidence_store._connect

            def tracked_connect():
                connection = original_connect()
                opened.append(connection)
                return connection

            with (
                patch.object(evidence_store, "DB_PATH", Path(folder) / "evidence.db"),
                patch.object(evidence_store, "_connect", side_effect=tracked_connect),
            ):
                evidence_store.init_db()
                evidence_store.record_event(
                    client_id="hmi-01", peer_ip="127.0.0.1", register=1, value=55,
                    stage="test", decision="ALLOW", reason="connection_lifecycle_test",
                )
                self.assertEqual(len(evidence_store.fetch_recent_events()), 1)
                self.assertEqual(len(evidence_store.fetch_all_raw_rows()), 1)

            self.assertGreaterEqual(len(opened), 4)
            for connection in opened:
                with self.assertRaises(sqlite3.ProgrammingError):
                    connection.execute("SELECT 1")


class OfflineAnalysisTests(unittest.TestCase):
    def analyze(self, packets):
        from capture.pcap_analyzer import analyze_pcap
        class Capture(list):
            def close(self): pass
        wrapper=SimpleNamespace(FileCapture=lambda *args,**kwargs:Capture(packets))
        with patch.dict('sys.modules', {'pyshark':wrapper}):
            return analyze_pcap(Path('fixture-only.pcapng'))

    def test_offline_fragments_and_retransmissions_do_not_create_false_indicators(self):
        data=wire(build_signed_message('hmi-01',1,70));cut=len(data)//2
        report=self.analyze([packet(1,0,syn=True),packet(1,1,data[:cut]),packet(1,1+cut,data[cut:]),packet(1,1,data)])
        self.assertEqual(report['summary']['replay_indicators'],0)
        self.assertEqual(report['summary']['malformed_request_indicators'],0)

    def test_offline_true_replay_is_one_indicator_on_a_new_stream(self):
        data=wire(build_signed_message('hmi-01',1,70))
        report=self.analyze([packet(1,0,syn=True),packet(1,1,data),packet(2,0,syn=True),packet(2,1,data)])
        self.assertEqual(report['summary']['replay_indicators'],1)
        self.assertEqual(report['summary']['malformed_request_indicators'],0)


if __name__ == "__main__":
    unittest.main()
