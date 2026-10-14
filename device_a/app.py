"""Device A browser GUI with a loopback-only backend holding the command key."""
import os
os.environ['WG_ROLE'] = 'device-a'
import argparse
import hashlib
import ipaddress
import json
import secrets
import socket
import ssl
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from client.legit_hmi_client import build_signed_message, send_message
from shared import config, crypto_utils
from shared.ui_security import LOCAL_TOKEN, require_local, require_local_write, validate_ipv4

ROOT = Path(__file__).resolve().parent.parent
app = FastAPI(title='WaterGuard Device A Operator', docs_url=None, redoc_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=['localhost', '127.0.0.1', '[::1]'])
app.mount('/assets', StaticFiles(directory=ROOT / 'ui'), name='assets')
_settings_file = ROOT / 'data' / 'device_a_settings.json'
_host = ''
if _settings_file.exists():
    try:
        _host = validate_ipv4(json.loads(_settings_file.read_text())['gateway_host'])
    except Exception:
        pass
_lock = threading.Lock()
from device_a.operations import Operations, encode_setpoint
_operations = Operations(_host)
_history = _operations.history
_tls = ssl._create_unverified_context()  # lab self-signed HTTPS, explained in guide

def server_json(path, data=None):
    if not _host:
        raise HTTPException(409, 'Connect to the Windows laptop first')
    req = urllib.request.Request(f'https://{_host}:{config.DASHBOARD_PORT}{path}',
        data=json.dumps(data).encode() if data is not None else None,
        headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, context=_tls, timeout=4) as response:
        return json.load(response)

def send_case(label, msg, decision, reason):
    return _operations.send_case(label, msg, decision, reason)

def send_report(label):
    message = {'client_id': 'hmi-01', 'timestamp': time.time(), 'nonce': secrets.token_hex(16),
        'command_fingerprint': hashlib.sha256(config.COMMAND_HMAC_KEY).hexdigest()[:12],
        'evidence_keys_present': bool(config.EVIDENCE_AES_KEY or config.EVIDENCE_HMAC_KEY), 'label': label,
        'results': [{k: r[k] for k in ('label','decision','reason','event_id','expected_decision','expected_reason','matched')} for r in _history]}
    message['hmac'] = crypto_utils.hmac_sha256_hex(config.COMMAND_HMAC_KEY, crypto_utils.canonical_json(message))
    try:
        return server_json('/api/device-a-report', message)
    except Exception as exc:
        return {'accepted': False, 'detail': 'Commands ran, but the Windows report could not be updated: ' + str(exc)}

def run_test(name):
    try:
        return _operations.run_test(name)
    except ValueError as exc:
        raise HTTPException(422, str(exc))

def check_connection():
    try:
        health = server_json('/api/health')
    except Exception as exc:
        raise HTTPException(503, f'Windows dashboard is unreachable. Start Windows WaterGuard, check its IP and firewall: {exc}')
    if health.get('project') != 'WaterGuard' or health.get('command_fingerprint') != hashlib.sha256(config.COMMAND_HMAC_KEY).hexdigest()[:12]:
        raise HTTPException(409, 'Wrong WaterGuard host or mismatched command key. Use the Device A ZIP exported by your Windows launcher.')
    # Determine the REAL local route's source, without sending a fake WCP packet.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
        route.connect((_host, config.GATEWAY_WCP_PORT))
        source_ip = route.getsockname()[0]
    health['device_a_source_ip'] = source_ip
    health['source_authorized'] = health['authorized_sources'].get('hmi-01') == source_ip
    health['clock_difference_seconds'] = round(abs(time.time()-health['server_time']), 3)
    return health

@app.get('/', response_class=HTMLResponse)
def index():
    return (ROOT/'ui'/'operator.html').read_text(encoding='utf-8')

@app.get('/api/session')
def session(request: Request):
    require_local(request)
    return {'token': LOCAL_TOKEN, 'gateway_host': _host}

@app.post('/api/connect')
def connect(request: Request, settings: dict):
    global _host
    require_local_write(request)
    if not _lock.acquire(False):
        raise HTTPException(409,'A demonstration is running')
    try:
        _host = validate_ipv4(str(settings.get('gateway_host', '')))
        _operations.host = _host
        health = check_connection()
        _settings_file.parent.mkdir(parents=True,exist_ok=True)
        _settings_file.write_text(json.dumps({'gateway_host':_host}))
        report = send_report('Device A connected')
        return {'health':health,'report':report}
    finally:
        _lock.release()

@app.get('/api/history')
def history(request: Request):
    require_local(request)
    return {'history':list(reversed(_history))}

@app.post('/api/command')
def command(request: Request, body: dict):
    require_local_write(request)
    if not _lock.acquire(False):
        raise HTTPException(409,'A demonstration is running; wait for it to finish')
    try:
        check_connection()
        register = body.get('register')
        if type(register) is not int or register not in (0,1):
            raise HTTPException(422,'Choose chlorine or valve')
        try:
            value = encode_setpoint(register, body.get('value'))
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        expected = 'ALLOW' if config.SAFETY_BOUNDS[register][0] <= value <= config.SAFETY_BOUNDS[register][1] else 'BLOCK'
        reason = 'all_checks_passed' if expected == 'ALLOW' else 'unsafe_setpoint'
        entry = send_case('Operator chlorine' if register == 0 else 'Operator valve', build_signed_message('hmi-01',register,value),expected,reason)
        return {'result':entry, 'report':send_report('Operator session')}
    finally:
        _lock.release()

@app.post('/api/test')
def test(request: Request, body: dict):
    require_local_write(request)
    if not _lock.acquire(False):
        raise HTTPException(409,'A demonstration is already running')
    try:
        health = check_connection()
        if not health['source_authorized'] or health['clock_difference_seconds'] > 4:
            raise HTTPException(409,'Fix the source-IP registry or synchronize clocks before running controlled tests')
        name = body.get('scenario')
        names = ['normal-series','unauthorized-source','forged-hmac','replay','restricted-register','unsafe-setpoint','unauthenticated-modbus','malformed-request'] if name == 'all' else [name]
        results = []
        for scenario in names:
            results.extend(run_test(scenario))
        return {'results':results,'report':send_report('Controlled demonstration')}
    finally:
        _lock.release()

def main():
    import uvicorn
    parser=argparse.ArgumentParser(description='Start Device A operator UI on this machine only')
    parser.add_argument('--port',type=int,default=8080)
    args=parser.parse_args()
    uvicorn.run(app,host='127.0.0.1',port=args.port)

if __name__=='__main__':
    main()
