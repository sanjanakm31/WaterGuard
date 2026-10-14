"""Read-only status and authenticated Device A demonstration receipts."""
import hashlib
import math
import os
import platform
import socket
import threading
import time
from pathlib import Path
from fastapi import APIRouter, HTTPException, Request
from gateway import evidence_store
from gateway.evidence_proof import show_proof, tamper_copy, raw_row
from gateway.nonce_cache import NonceCache
from shared import config, crypto_utils
from shared.ui_security import LOCAL_TOKEN, require_local, require_local_write

router = APIRouter()
_report_nonces = NonceCache(120)
_last_report = None
_report_lock = threading.Lock()

def fingerprint(key):
    return hashlib.sha256(key).hexdigest()[:12] if key else None

@router.get('/api/session')
def session(request: Request):
    require_local(request)
    return {'token': LOCAL_TOKEN}

@router.get('/api/health')
def health():
    with _report_lock:
        recent = _last_report
    try:
        addresses = sorted({v[4][0] for v in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)})
    except OSError:
        addresses = []
    captures = Path(evidence_store.DB_PATH).parent / 'captures'
    files = sorted((p for p in captures.glob('*.pcap*') if p.suffix in ('.pcap','.pcapng')), key=lambda p: p.stat().st_mtime, reverse=True) if captures.exists() else []
    try:
        import json
        runtime = json.loads((Path(evidence_store.DB_PATH).parent / 'presentation_runtime.json').read_text())
        if time.time() - runtime.get('updated_at', 0) > 5:
            runtime = {'state': 'unknown', 'detail': 'Launcher status is stale'}
    except (OSError, ValueError, TypeError):
        runtime = {'state': 'unknown', 'detail': 'No launcher status available'}
    return {'project': 'WaterGuard', 'edition': 'GUI v3', 'hostname': socket.gethostname(),
        'platform': platform.system(), 'ipv4_addresses': addresses, 'server_time': time.time(),
        'gateway_port': config.GATEWAY_WCP_PORT, 'modbus_reject_port': config.GATEWAY_MODBUS_PORT,
        'dashboard_port': config.DASHBOARD_PORT, 'controller_host': config.CONTROLLER_HOST,
        'controller_port': config.CONTROLLER_MODBUS_PORT, 'authorized_sources': config.AUTHORIZED_SOURCES,
        'command_fingerprint': fingerprint(config.COMMAND_HMAC_KEY),
        'evidence_keys_present': bool(config.EVIDENCE_AES_KEY and config.EVIDENCE_HMAC_KEY),
        'capture_required': os.environ.get('WG_CAPTURE_REQUIRED') == '1',
        'runtime': runtime,
        'capture_files': [{'name': p.name, 'bytes': p.stat().st_size} for p in files[:5]],
        'last_device_a_report': recent,
        'database': str(evidence_store.DB_PATH), 'table': 'security_events'}

@router.get('/api/proof/{event_id}')
def proof(event_id: str, request: Request):
    require_local(request)
    try:
        return show_proof(event_id)
    except KeyError:
        raise HTTPException(404, 'Event not found')

@router.post('/api/proof/{event_id}/tamper-copy')
def demonstrate_tampering(event_id: str, request: Request):
    require_local_write(request)
    try:
        return tamper_copy(event_id)
    except KeyError:
        raise HTTPException(404, 'Event not found')
    except ValueError as exc:
        raise HTTPException(409, str(exc))

@router.get('/api/sql')
def sql_view(request: Request, limit: int = 50):
    require_local(request)
    limit = max(1, min(limit, 200))
    with evidence_store._lock, evidence_store._connection() as conn:
        import sqlite3
        conn.row_factory = sqlite3.Row
        rows = conn.execute('SELECT id,event_id,ts,client_id,peer_ip,decision,reason,stage,payload_hash,hash_hmac,lower(hex(aes_nonce)) AS aes_nonce_hex,lower(hex(encrypted_payload)) AS encrypted_payload_hex FROM security_events ORDER BY id DESC LIMIT ?', (limit,)).fetchall()
    return {'database': str(evidence_store.DB_PATH), 'table': 'security_events',
        'query': 'SELECT id, event_id, decision, reason, hex(aes_nonce), hex(encrypted_payload) FROM security_events ORDER BY id DESC;',
        'rows': [dict(row) for row in rows], 'notice': 'Raw database columns; integrity is checked in the Evidence screen.'}

@router.post('/api/device-a-report')
async def receive_report(request: Request):
    global _last_report
    body = await request.body()
    if len(body) > 65536:
        raise HTTPException(413, 'Report too large')
    try:
        import json
        message = json.loads(body)
        tag = message.pop('hmac')
        valid = crypto_utils.hmac_verify(config.COMMAND_HMAC_KEY, crypto_utils.canonical_json(message), tag)
        client = message['client_id']
        expected_ip = config.AUTHORIZED_SOURCES.get(client)
        if not valid or expected_ip != request.client.host:
            raise ValueError('Untrusted report')
        timestamp = message['timestamp']
        if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)) or not math.isfinite(timestamp) or abs(time.time() - timestamp) > 5:
            raise ValueError('Stale report')
        nonce = message['nonce']
        if not isinstance(nonce, str) or len(nonce) != 32 or any(c not in '0123456789abcdef' for c in nonce):
            raise ValueError('Invalid nonce')
        if _report_nonces.seen_before(client, nonce):
            raise ValueError('Repeated report')
        rows = message.get('results', [])
        if not isinstance(rows, list) or len(rows) > 100:
            raise ValueError('Invalid results')
        verified = []
        for entry in rows:
            entry = dict(entry)
            entry['gateway_verified'] = False
            if entry.get('event_id'):
                sql_row = raw_row(entry['event_id'])
                intact, record, _ = evidence_store.decrypt_and_verify_event(sql_row)
                if intact and record['peer_ip'] == request.client.host:
                    entry['gateway_verified'] = record['decision'] == entry.get('decision') and record['reason'] == entry.get('reason')
            verified.append(entry)
        recent = {'received_at': time.time(), 'peer_ip': request.client.host, 'client_id': client,
            'command_key_match': message.get('command_fingerprint') == fingerprint(config.COMMAND_HMAC_KEY),
            'device_a_evidence_keys_present': bool(message.get('evidence_keys_present')),
            'clock_difference_seconds': round(abs(time.time() - timestamp), 3),
            'results': verified, 'label': message.get('label', 'Device A session')[:120]}
        with _report_lock:
            _last_report = recent
        # The report is supporting evidence, not a network attack/decision.
        evidence_store.record_event(client_id=client, peer_ip=request.client.host, register=None, value=None,
            stage='presentation_report', decision='INFO', reason='device_a_report', extra=recent)
        return {'accepted': True, 'verified_event_count': sum(r['gateway_verified'] for r in verified)}
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(403, 'Device A report failed authentication or validation') from exc
