"""Measure legitimate RTT, attack blocking latency, and a direct-Modbus baseline.

Run ON THE GATEWAY/CONTROLLER COMPUTER in the two-computer layout, with a
locally authorized HMI identity. Device B remains bound to localhost; there
is no need to expose its port to the attacker to collect a baseline.

Client RTT includes connect, receive, checks, forwarding (if allowed),
evidence persistence and response. The paired RTT difference is measured
end-to-end overhead, NOT pure CPU cost. Internal times are read only from
the exact event IDs returned by this benchmark, excluding live ALERTs and
unrelated traffic. Missing local evidence is reported as unavailable.
"""
from __future__ import annotations

import argparse
import datetime
import json
from pathlib import Path
import statistics
import time

from client.legit_hmi_client import build_signed_message, send_command, send_message
from controller.modbus_forwarder import RealModbusForwarder
from gateway import evidence_store
from shared import config


def _percentile(values: list[float], pct: float) -> float:
    position = (len(values) - 1) * pct / 100
    low = int(position)
    high = min(low + 1, len(values) - 1)
    return values[low] + (values[high] - values[low]) * (position - low)


def _stats_block(values: list[float]) -> dict:
    if not values:
        return {"count": 0, "status": "unavailable"}
    values = sorted(values)
    return {
        "count": len(values), "min": round(values[0], 4),
        "mean": round(statistics.mean(values), 4),
        "median": round(statistics.median(values), 4),
        "p95": round(_percentile(values, 95), 4),
        "p99": round(_percentile(values, 99), 4),
        "max": round(values[-1], 4), "stdev": round(statistics.pstdev(values), 4),
    }


def _timed(call):
    started = time.perf_counter()
    try:
        response = call()
    except Exception as exc:
        response = {"decision": "ERROR", "error": repr(exc)}
    return (time.perf_counter() - started) * 1000, response


def _operational_error(response: dict) -> bool:
    return response.get("decision") not in {"ALLOW", "BLOCK"} or response.get("reason") in {
        "controller_unreachable", "internal_error",
    }


def collect_internal_timings(event_ids: set[str]) -> dict:
    matched = 0
    invalid = 0
    validation = []
    forwarding = []
    block_detection = []
    if not evidence_store.DB_PATH.exists():
        return {"status": "unavailable", "reason": "run on the gateway host to access its evidence DB"}
    for row in evidence_store.fetch_all_raw_rows():
        if row["event_id"] not in event_ids:
            continue
        intact, record, _detail = evidence_store.decrypt_and_verify_event(row)
        if not intact or record is None:
            invalid += 1
            continue
        matched += 1
        extra = record.get("extra", {})
        if record["decision"] == "ALLOW":
            if "validation_time_ms" in extra:
                validation.append(extra["validation_time_ms"])
            if "modbus_forward_time_ms" in extra:
                forwarding.append(extra["modbus_forward_time_ms"])
        elif record["decision"] == "BLOCK" and record["stage"] != "forwarding":
            if "processing_time_ms" in extra:
                block_detection.append(extra["processing_time_ms"])
    return {
        "expected_event_count": len(event_ids), "verified_event_count": matched,
        "invalid_event_count": invalid, "unmatched_event_count": len(event_ids) - matched - invalid,
        "validation_before_forward_ms": _stats_block(validation),
        "modbus_forward_ms": _stats_block(forwarding),
        "complete_message_to_block_before_evidence_ms": _stats_block(block_detection),
    }


def run_benchmark(iterations: int, host: str, port: int, forwarder, client_id: str = "hmi-01") -> dict:
    if iterations < 1:
        raise ValueError("iterations must be positive")
    send = lambda message: send_message(message, gateway_host=host, gateway_port=port)
    warmup = send_command(client_id, 1, 50, gateway_host=host, gateway_port=port)
    if warmup.get("decision") != "ALLOW":
        raise RuntimeError(f"Warm-up was not ALLOW: {warmup}. Check source-IP/key/controller configuration.")
    forwarder.read_registers(0, 3)  # baseline must be a reachable controller
    direct_times, gateway_times, paired_overhead = [], [], []
    event_ids: set[str] = set()
    false_positives = operational_errors = baseline_errors = 0
    evaluable_legitimate = 0

    for index in range(iterations):
        register = 1 if index % 2 == 0 else 0
        value = 40 + index % 21 if register == 1 else 150 + index % 51

        def direct_call():
            forwarder.write_register(register, value)
            return {"decision": "ALLOW"}

        def gateway_call():
            return send_command(client_id, register, value, gateway_host=host, gateway_port=port)

        # Alternate order to reduce fixed ordering bias; both write the same
        # safe value. This intentionally measures the complete network routes.
        if index % 2 == 0:
            direct_ms, direct = _timed(direct_call)
            gateway_ms, response = _timed(gateway_call)
        else:
            gateway_ms, response = _timed(gateway_call)
            direct_ms, direct = _timed(direct_call)
        if direct.get("decision") == "ALLOW":
            direct_times.append(direct_ms)
        else:
            baseline_errors += 1
        if response.get("event_id"):
            event_ids.add(response["event_id"])
        if _operational_error(response):
            operational_errors += 1
        else:
            evaluable_legitimate += 1
            false_positives += response.get("decision") == "BLOCK"
            gateway_times.append(gateway_ms)
        if direct.get("decision") == "ALLOW" and response.get("decision") == "ALLOW":
            paired_overhead.append(gateway_ms - direct_ms)

    attack_results = {}
    for scenario, expected in [
        ("forged_hmac", "invalid_hmac"),
        ("unsafe_value", "unsafe_setpoint"),
        ("restricted_register", "restricted_register"),
        ("stale_command", "replay_attack"),
        ("replayed_command", "replay_attack"),
    ]:
        times = []
        correct_blocks = unexpected_allows = wrong_reasons = errors = 0
        for _ in range(iterations):
            register = 2 if scenario == "restricted_register" else 0
            value = 2500 if scenario == "unsafe_value" else (999 if register == 2 else 180)
            timestamp = time.time() - config.REPLAY_WINDOW_SECONDS - 30 if scenario == "stale_command" else None
            message = build_signed_message(client_id, register, value, timestamp=timestamp)
            if scenario == "forged_hmac":
                message["hmac"] = "00" * 32
            if scenario == "replayed_command":
                _first_ms, first = _timed(lambda: send(message))
                if first.get("decision") != "ALLOW":
                    errors += 1
                    continue
            elapsed, response = _timed(lambda: send(message))
            if response.get("event_id"):
                event_ids.add(response["event_id"])
            if _operational_error(response):
                errors += 1
                continue
            if response.get("decision") == "ALLOW":
                unexpected_allows += 1
            elif response.get("reason") != expected:
                wrong_reasons += 1
            else:
                correct_blocks += 1
                times.append(elapsed)
        attack_results[scenario] = {
            "attempts": iterations, "expected_reason": expected,
            "correct_blocks": correct_blocks, "unexpected_allows": unexpected_allows,
            "wrong_block_reasons": wrong_reasons, "operational_errors": errors,
            "successful_block_round_trip_ms": _stats_block(times),
        }

    return {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "forwarder_type": type(forwarder).__name__,
        "legitimate": {
            "attempts": iterations, "evaluable_requests": evaluable_legitimate,
            "false_positives": false_positives, "operational_errors": operational_errors,
            "false_positive_rate_pct": round(100 * false_positives / evaluable_legitimate, 4) if evaluable_legitimate else None,
            "gateway_round_trip_ms": _stats_block(gateway_times),
        },
        "direct_modbus": {"operational_errors": baseline_errors, "round_trip_ms": _stats_block(direct_times)},
        "paired_gateway_minus_direct_round_trip_ms": _stats_block(paired_overhead),
        "attacks": attack_results,
        "internal_timings": collect_internal_timings(event_ids),
        "measured_event_ids": sorted(event_ids),
        "interpretation": [
            "RTT includes connection setup, network, processing, evidence storage and response.",
            "Paired RTT difference includes the extra network hop and is not pure CPU cost; noise can make samples negative.",
            "Internal timing begins after the complete WCP message is received and excludes evidence persistence.",
            "Operational failures are reported separately from security false positives.",
            "Only measured event IDs are used; background PCAP ALERT events are excluded.",
            "Use RealModbusForwarder on the actual demo machines for reportable performance results.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="WaterGuard controlled-lab benchmark")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=config.GATEWAY_WCP_PORT)
    parser.add_argument("--controller-host", default=config.CONTROLLER_HOST)
    parser.add_argument("--controller-port", type=int, default=config.CONTROLLER_MODBUS_PORT)
    parser.add_argument("--client-id", default="hmi-01")
    parser.add_argument("--iterations", type=int, default=100)
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error("--iterations must be at least 1")
    forwarder = RealModbusForwarder(args.controller_host, args.controller_port)
    report = run_benchmark(args.iterations, args.host, args.port, forwarder, args.client_id)
    output = Path(__file__).resolve().parent.parent / "data" / "benchmark_report.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    summary = {key: value for key, value in report.items() if key != "measured_event_ids"}
    print(json.dumps(summary, indent=2))
    print(f"Report with exact measured event IDs: {output}")


if __name__ == "__main__":
    main()
