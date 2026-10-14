"""Framework security gates. Run with pytest on the installed Windows host."""
import asyncio
import hashlib
import json
import secrets
import time
from pathlib import Path
from unittest.mock import patch
import pytest
from fastapi import HTTPException
from starlette.requests import Request
from gateway import evidence_store
from shared import config, crypto_utils
from shared.ui_security import LOCAL_TOKEN, require_local, require_local_write
from dashboard.presentation_api import receive_report, proof

def request(host='127.0.0.1',headers=None,body=b''):
    scope={'type':'http','method':'POST','path':'/api/device-a-report','query_string':b'',
        'scheme':'https','server':('localhost',8443),'client':(host,50100),
        'headers':[(k.encode(),v.encode()) for k,v in (headers or {'host':'localhost:8443'}).items()]}
    async def receive():return {'type':'http.request','body':body,'more_body':False}
    return Request(scope,receive)

def signed(body):
    body['hmac']=crypto_utils.hmac_sha256_hex(config.COMMAND_HMAC_KEY,crypto_utils.canonical_json(body))
    return json.dumps(body).encode()

def report():
    return {'client_id':'hmi-01','timestamp':time.time(),'nonce':secrets.token_hex(16),
        'command_fingerprint':hashlib.sha256(config.COMMAND_HMAC_KEY).hexdigest()[:12],
        'evidence_keys_present':False,'label':'framework test','results':[]}

def test_remote_clients_cannot_open_encryption_proof():
    with pytest.raises(HTTPException) as result:proof('any-event',request('192.168.0.190'))
    assert result.value.status_code==403

def test_dns_rebinding_host_is_refused_even_on_loopback():
    with pytest.raises(HTTPException):require_local(request(headers={'host':'evil.example:8443'}))

def test_tamper_requires_session_token_and_rejects_foreign_origin():
    with pytest.raises(HTTPException):require_local_write(request())
    with pytest.raises(HTTPException):require_local_write(request(headers={'host':'localhost:8443','x-waterguard-token':LOCAL_TOKEN,'origin':'https://evil.example'}))
    require_local_write(request(headers={'host':'localhost:8443','x-waterguard-token':LOCAL_TOKEN,'origin':'https://localhost:8443'}))

def test_authenticated_report_is_accepted_once_and_replay_rejected(tmp_path,monkeypatch):
    monkeypatch.setattr(evidence_store,'DB_PATH',tmp_path/'report.db');evidence_store.init_db()
    payload=signed(report());assert asyncio.run(receive_report(request(body=payload)))['accepted']
    with pytest.raises(HTTPException):asyncio.run(receive_report(request(body=payload)))

@pytest.mark.parametrize('change', ['wrong-source','wrong-key','nan-time'])
def test_invalid_reports_cannot_publish_results(change,tmp_path,monkeypatch):
    monkeypatch.setattr(evidence_store,'DB_PATH',tmp_path/'invalid.db');evidence_store.init_db()
    message=report();host='127.0.0.1'
    if change=='nan-time':message['timestamp']=float('nan')
    payload=signed(message)
    if change=='wrong-source':host='192.168.0.190'
    if change=='wrong-key':
        decoded=json.loads(payload);decoded['hmac']='0'*64;payload=json.dumps(decoded).encode()
    with pytest.raises(HTTPException):asyncio.run(receive_report(request(host,body=payload)))
    assert evidence_store.fetch_all_raw_rows()==[]
