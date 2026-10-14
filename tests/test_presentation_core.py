"""Meaningful upgrade regressions runnable without pytest or web packages."""
import json
from pathlib import Path
import socket
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from client.legit_hmi_client import build_signed_message, send_message
from controller.modbus_forwarder import LoopbackTestForwarder
from gateway import evidence_store
from gateway.evidence_proof import raw_row, show_proof, tamper_copy
from gateway.waterguard_gateway import WaterGuardGateway
from shared import config
from tools.export_device_a_bundle import export

def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));return sock.getsockname()[1]

class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.patcher=patch.object(evidence_store,'DB_PATH',Path(self.temp.name)/'evidence.db');self.patcher.start()
        self.forwarder=LoopbackTestForwarder()
        self.port=free_port();self.native=free_port()
        while self.native==self.port:self.native=free_port()
        self.gateway=WaterGuardGateway(self.forwarder,host='127.0.0.1',port=self.port,modbus_intake_port=self.native)
        self.gateway.start(blocking=False)

    def tearDown(self):
        self.gateway.stop();self.patcher.stop();self.temp.cleanup()

    def send(self,msg):
        return send_message(msg,gateway_host='127.0.0.1',gateway_port=self.port)

    def test_allow_has_eight_real_passes_and_verified_command(self):
        msg=build_signed_message('hmi-01',1,70);r=self.send(msg);self.assertEqual(r['decision'],'ALLOW')
        proof=show_proof(r['event_id'])
        self.assertEqual(proof['status'],'INTACT');self.assertTrue(all(proof['checks'].values()))
        self.assertEqual(proof['command_proof']['json'],msg);self.assertTrue(proof['command_proof']['hmac_valid'])
        self.assertEqual([t['status'] for t in proof['record']['extra']['validation_trace']],['PASS']*8)
        self.assertEqual(self.forwarder.read_registers(1,1),[70])

    def test_forged_hmac_skips_later_checks_and_never_changes_state(self):
        before=self.forwarder.read_registers(1,1)
        msg=build_signed_message('hmi-01',1,80);msg['hmac']='0'*64
        r=self.send(msg);p=show_proof(r['event_id'])
        self.assertEqual(r['reason'],'invalid_hmac')
        self.assertEqual([t['status'] for t in p['record']['extra']['validation_trace']],['PASS']*3+['FAIL']+['SKIPPED']*4)
        self.assertFalse(p['command_proof']['hmac_valid']);self.assertEqual(self.forwarder.read_registers(1,1),before)

    def test_policy_block_is_authenticated_and_not_forwarded(self):
        r=self.send(build_signed_message('hmi-01',0,2500));p=show_proof(r['event_id'])
        self.assertEqual(r['reason'],'unsafe_setpoint');self.assertTrue(p['command_proof']['hmac_valid'])
        self.assertEqual([t['status'] for t in p['record']['extra']['validation_trace']],['PASS']*6+['FAIL','SKIPPED'])
        self.assertFalse(p['record']['extra']['controller_forwarded'])

    def test_nonce_repeat_fails_only_after_authentication(self):
        msg=build_signed_message('hmi-01',1,60);self.assertEqual(self.send(msg)['decision'],'ALLOW')
        r=self.send(msg);p=show_proof(r['event_id'])
        self.assertEqual(r['reason'],'replay_attack');self.assertEqual(p['record']['extra']['validation_trace'][4]['status'],'FAIL')

    def test_one_bit_copy_tamper_keeps_entire_original_row(self):
        r=self.send(build_signed_message('hmi-01',1,70));before=raw_row(r['event_id'])
        demo=tamper_copy(r['event_id'])
        self.assertEqual(demo['before'],'INTACT');self.assertEqual(demo['after'],'TAMPERED')
        self.assertTrue(demo['original_unchanged']);self.assertTrue(demo['original_intact'])
        self.assertEqual(before,raw_row(r['event_id']))

    def test_changed_metadata_never_exposes_unverified_plaintext(self):
        r=self.send(build_signed_message('hmi-01',1,70))
        with evidence_store._connection() as conn:conn.execute('UPDATE security_events SET decision=? WHERE event_id=?',('BLOCK',r['event_id']))
        p=show_proof(r['event_id']);self.assertEqual(p['status'],'TAMPERED');self.assertNotIn('plaintext',p)

    def test_native_modbus_returns_actual_protocol_exception(self):
        with socket.create_connection(('127.0.0.1',self.native),timeout=3) as sock:
            sock.sendall(struct.pack('>HHHBBHH',123,0,6,1,6,0,2500))
            received=b''
            while len(received)<9:received+=sock.recv(9-len(received))
        self.assertEqual(received,struct.pack('>HHHBBB',123,0,3,1,134,1))
        self.assertEqual(evidence_store.fetch_recent_events()[0]['reason'],'unauthenticated_modbus')

    def test_controller_error_is_not_claimed_as_successful_security_block(self):
        with patch.object(self.forwarder,'write_register',side_effect=OSError('no controller acknowledgement')):
            r=self.send(build_signed_message('hmi-01',1,70))
        self.assertEqual(r['decision'],'ERROR');p=show_proof(r['event_id'])
        self.assertIsNone(p['record']['extra']['controller_forwarded'])

    def test_export_contains_no_real_evidence_keys_or_server_modules(self):
        output=export(Path(self.temp.name)/'client.zip')
        with zipfile.ZipFile(output) as archive:
            names=archive.namelist();env=archive.read('waterguard-device-a/.env')
            self.assertIn(b'WG_ROLE=device-a',env);self.assertNotIn(b'EVIDENCE',env)
            for name in names:
                self.assertFalse('/gateway/' in name or '/controller/' in name or '/dashboard/' in name)
                data=archive.read(name)
                self.assertNotIn(config.EVIDENCE_AES_KEY.hex().encode(),data)
                self.assertNotIn(config.EVIDENCE_HMAC_KEY.hex().encode(),data)

    def test_entire_operator_suite_measures_real_tcp_decisions(self):
        from device_a.operations import Operations
        operator=Operations('127.0.0.1',self.port,self.native)
        results=[]
        for name in ('normal-series','unauthorized-source','forged-hmac','replay','restricted-register','unsafe-setpoint','unauthenticated-modbus','malformed-request'):
            results.extend(operator.run_test(name))
        self.assertEqual(len(results),19)
        self.assertTrue(all(r['matched'] for r in results))
        self.assertEqual(sum(r['decision']=='ALLOW' for r in results),11)
        self.assertEqual(sum(r['decision']=='BLOCK' for r in results),8)
        for result in results:
            if result['event_id']:
                proof=show_proof(result['event_id']);self.assertEqual(proof['status'],'INTACT')
                self.assertEqual(proof['record']['decision'],result['decision'])

    def test_operator_unit_conversion_preserves_unsafe_values_for_gateway_check(self):
        from device_a.operations import encode_setpoint
        self.assertEqual(encode_setpoint(0,'1.80'),180)
        self.assertEqual(encode_setpoint(0,'25.00'),2500)
        self.assertEqual(encode_setpoint(1,'70'),70)
        for register,value in [(1,'70.1'),(0,'1.234'),(0,'nan'),(0,'Infinity'),(0,'-1'),(0,'655.36')]:
            with self.assertRaises(ValueError):encode_setpoint(register,value)

if __name__=='__main__':unittest.main()
