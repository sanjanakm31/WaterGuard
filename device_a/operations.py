"""Framework-independent operator actions; test real TCP without a browser."""
import socket
import struct
import time
from decimal import Decimal, DecimalException
from client.legit_hmi_client import build_signed_message, send_message
from shared import config

def encode_setpoint(register, value):
    if type(register) is not int or register not in (0,1):
        raise ValueError('Choose chlorine or valve')
    try:
        numeric=Decimal(str(value))
        raw=numeric*(100 if register==0 else 1)
        if not numeric.is_finite() or raw != raw.to_integral_value() or not 0 <= raw <= 65535:
            raise ValueError()
        return int(raw)
    except (ValueError, DecimalException) as exc:
        raise ValueError('Use non-negative chlorine with at most two decimal places or a whole valve percent, within the 16-bit wire range') from exc

class Operations:
    def __init__(self,host='',wcp_port=None,native_port=None):
        self.host=host;self.wcp_port=wcp_port or config.GATEWAY_WCP_PORT
        self.native_port=native_port or config.GATEWAY_MODBUS_PORT;self.history=[]

    def remember(self,label,response,decision,reason,message=None):
        entry={'time':time.time(),'label':label,'decision':response.get('decision','ERROR'),
            'reason':response.get('reason','missing_response'),'event_id':response.get('event_id'),
            'expected_decision':decision,'expected_reason':reason,
            'matched':response.get('decision')==decision and response.get('reason')==reason,
            'response':response,'command':message}
        self.history.append(entry);del self.history[:-100];return entry

    def send_case(self,label,msg,decision,reason):
        try:response=send_message(msg,gateway_host=self.host,gateway_port=self.wcp_port)
        except Exception as exc:response={'decision':'ERROR','reason':type(exc).__name__+': '+str(exc)}
        return self.remember(label,response,decision,reason,msg)

    def native_request(self):
        # A real Modbus TCP write-single-register frame, with an exact
        # exception check. A refusal/timeout is ERROR, never proof of BLOCK.
        transaction=7
        with socket.create_connection((self.host,self.native_port),timeout=3) as sock:
            sock.sendall(struct.pack('>HHHBBHH',transaction,0,6,1,6,0,2500))
            raw=b''
            while len(raw)<9:
                chunk=sock.recv(9-len(raw))
                if not chunk:break
                raw+=chunk
        expected=struct.pack('>HHHBBB',transaction,0,3,1,134,1)
        if raw==expected:return {'decision':'BLOCK','reason':'unauthenticated_modbus','modbus_response_hex':raw.hex()}
        return {'decision':'ERROR','reason':'Unexpected native Modbus response','modbus_response_hex':raw.hex()}

    def run_test(self,name):
        send=self.send_case
        if name=='unauthorized-source':
            return [send('Unknown client identity',build_signed_message('rogue-engineering-laptop',1,50),'BLOCK','unauthorized_source')]
        if name=='forged-hmac':
            msg=build_signed_message('hmi-01',0,250);msg['hmac']='0'*64 if msg['hmac']!='0'*64 else '1'*64
            return [send('Forged command HMAC',msg,'BLOCK','invalid_hmac')]
        if name=='restricted-register':
            return [send('Read-only flow sensor write',build_signed_message('hmi-01',2,999),'BLOCK','restricted_register')]
        if name=='replay':
            captured=build_signed_message('hmi-01',1,60)
            return [send('Replay baseline (original)',captured,'ALLOW','all_checks_passed'),
                send('Identical nonce replay',dict(captured),'BLOCK','replay_attack'),
                send('Correctly signed stale timestamp',build_signed_message('hmi-01',1,60,timestamp=time.time()-35),'BLOCK','replay_attack')]
        if name=='unauthenticated-modbus':
            try:response=self.native_request()
            except Exception as exc:response={'decision':'ERROR','reason':str(exc)}
            return [self.remember('Unauthenticated native Modbus',response,'BLOCK','unauthenticated_modbus')]
        if name=='malformed-request':
            from attacker.device_a_attacker import _send_raw
            try:response=_send_raw(b'{broken json',self.host,self.wcp_port)
            except Exception as exc:response={'decision':'ERROR','reason':str(exc)}
            return [self.remember('Malformed JSON',response,'BLOCK','malformed_request')]
        if name=='normal-series':
            return [send(f'Normal valve {v}%',build_signed_message('hmi-01',1,v),'ALLOW','all_checks_passed') for v in (10,30,50,70,90)]+[send(f'Normal chlorine {v/100:.2f} ppm',build_signed_message('hmi-01',0,v),'ALLOW','all_checks_passed') for v in (20,100,180,300,400)]
        if name=='unsafe-setpoint':
            return [send('Authenticated chlorine 25.00 ppm',build_signed_message('hmi-01',0,2500),'BLOCK','unsafe_setpoint')]
        raise ValueError('Unknown demonstration')
