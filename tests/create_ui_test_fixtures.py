"""Optional JS logic fixtures from REAL gateway TCP decisions; not browser QA."""
import hashlib
import json
from pathlib import Path
import socket
import sys
import tempfile
from client.legit_hmi_client import build_signed_message, send_message
from controller.modbus_forwarder import LoopbackTestForwarder
from gateway import evidence_store
from gateway.evidence_proof import show_proof
from gateway.waterguard_gateway import WaterGuardGateway
from shared import config

def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]

def main():
    with tempfile.TemporaryDirectory() as directory:
        evidence_store.DB_PATH=Path(directory)/'fixtures.db'
        p,n=port(),port()
        while p==n:n=port()
        f=LoopbackTestForwarder();g=WaterGuardGateway(f,host='127.0.0.1',port=p,modbus_intake_port=n)
        g.start(blocking=False)
        try:
            records=[]
            for register,value in [(0,180),(1,70),(0,2500)]:
                message=build_signed_message('hmi-01',register,value)
                response=send_message(message,gateway_host='127.0.0.1',gateway_port=p)
                records.append({'time':0,'label':'Operator test','decision':response['decision'],'reason':response['reason'],
                    'event_id':response['event_id'],'response':response,'command':message,
                    'expected_decision':response['decision'],'expected_reason':response['reason'],'matched':True})
            events=evidence_store.fetch_recent_events()
            proofs={r['event_id']:show_proof(r['event_id']) for r in records}
            state={'registers':[{'address':r,'name':['Chlorine dosing','Valve position','Flow sensor'][r],
                'raw_value':raw,'display_value':raw/100 if r==0 else raw,'unit':['ppm','%','L/min'][r],
                'writable':r<2,'safe_bound_raw':config.SAFETY_BOUNDS.get(r),'in_bounds':True} for r,raw in enumerate(f.read_registers(0,3))]}
            health={'hostname':'test-protected-host','platform':'Test fixture','ipv4_addresses':['127.0.0.1'],
                'authorized_sources':{'hmi-01':'127.0.0.1'},'gateway_port':6000,'modbus_reject_port':1502,
                'controller_host':'127.0.0.1','controller_port':5502,'command_fingerprint':hashlib.sha256(config.COMMAND_HMAC_KEY).hexdigest()[:12],
                'evidence_keys_present':True,'capture_required':False,'capture_files':[],
                'last_device_a_report':None,'runtime':{'state':'unknown'}}
            Path(sys.argv[1]).write_text(json.dumps({'records':records,'events':events,'proofs':proofs,'state':state,'health':health}))
        finally:g.stop()

if __name__=='__main__':main()
