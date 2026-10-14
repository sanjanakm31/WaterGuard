"""Small native launch window; security and plant changes stay in the backend."""
import base64
import ctypes
import ipaddress
import json
import os
import queue
import re
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk
import urllib.request
import webbrowser
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
SETTINGS=ROOT/'data'/'presentation_settings.json'

def ps_quote(value):
    return "'"+str(value).replace("'","''")+"'"

def firewall_script(address, result_file):
    # Address is parsed as IPv4 before this function is called.
    lines=["$ErrorActionPreference='Stop'",'try {']
    for name,port in [('Commands',6000),('Reject Modbus',1502),('Dashboard',8443)]:
        label='WaterGuard GUI '+name
        lines.append(f"Get-NetFirewallRule -DisplayName {ps_quote(label)} -ErrorAction SilentlyContinue | Remove-NetFirewallRule")
        lines.append(f"New-NetFirewallRule -DisplayName {ps_quote(label)} -Direction Inbound -Action Allow -Protocol TCP -LocalPort {port} -RemoteAddress {ps_quote(address)} -Profile Any | Out-Null")
    lines.extend(["@{success=$true} | ConvertTo-Json | Set-Content -Encoding UTF8 "+ps_quote(result_file),
        '} catch {',"@{success=$false;detail=$_.Exception.Message} | ConvertTo-Json | Set-Content -Encoding UTF8 "+ps_quote(result_file),'}'])
    return '\n'.join(lines)

class Launcher:
    def __init__(self):
        self.window=tk.Tk();self.window.title('WaterGuard · Presentation launcher');self.window.geometry('790x660')
        self.window.minsize(720,570)
        self.process=None;self.client=None;self.events=queue.Queue();self.log_handle=None;self.verifying=False;self.exporting=False
        try:self.saved=json.loads(SETTINGS.read_text())
        except (OSError,ValueError):self.saved={}
        style=ttk.Style();style.theme_use('clam');style.configure('TButton',padding=9);style.configure('TLabel',font=('Segoe UI',10))
        outer=ttk.Frame(self.window,padding=24);outer.pack(fill='both',expand=True)
        ttk.Label(outer,text='WaterGuard',font=('Segoe UI',25,'bold')).pack(anchor='w')
        ttk.Label(outer,text='Windows hosts the gateway, protected controller, and dashboard.').pack(anchor='w',pady=(4,16))
        form=ttk.Frame(outer);form.pack(fill='x')
        ttk.Label(form,text='Presentation mode').grid(row=0,column=0,sticky='w',pady=7)
        self.mode=tk.StringVar(value=self.saved.get('mode','Ubuntu VM + Windows'))
        ttk.Combobox(form,textvariable=self.mode,values=['Ubuntu VM + Windows','One-laptop practice'],state='readonly',width=32).grid(row=0,column=1,sticky='ew',padx=14)
        ttk.Label(form,text='Ubuntu bridged IPv4 address').grid(row=1,column=0,sticky='w',pady=7)
        self.vm_ip=tk.StringVar(value=self.saved.get('vm_ip','192.168.0.190'))
        ttk.Entry(form,textvariable=self.vm_ip,width=34).grid(row=1,column=1,sticky='ew',padx=14)
        ttk.Label(form,text='Capture interface numbers').grid(row=2,column=0,sticky='w',pady=7)
        self.interfaces=tk.StringVar(value=self.saved.get('interfaces','5,9'))
        ttk.Entry(form,textvariable=self.interfaces,width=34).grid(row=2,column=1,sticky='ew',padx=14)
        ttk.Button(form,text='Detect capture adapters',command=self.detect_adapters).grid(row=2,column=2)
        ttk.Label(outer,text='For your two-device setup, select Wi-Fi + loopback. Adapter numbers may change.',wraplength=730).pack(anchor='w',pady=(8,10))
        self.address_label=tk.StringVar(value='Windows IPv4: detecting…')
        ttk.Label(outer,textvariable=self.address_label,font=('Segoe UI',11,'bold')).pack(anchor='w',pady=5)
        buttons=ttk.Frame(outer);buttons.pack(fill='x',pady=10)
        self.start_button=ttk.Button(buttons,text='Start WaterGuard',command=self.start);self.start_button.pack(side='left',padx=(0,8))
        self.stop_button=ttk.Button(buttons,text='Stop safely',command=self.stop,state='disabled');self.stop_button.pack(side='left',padx=5)
        ttk.Button(buttons,text='Open dashboard',command=lambda:webbrowser.open('https://localhost:8443/')).pack(side='left',padx=5)
        next_row=ttk.Frame(outer);next_row.pack(fill='x',pady=4)
        ttk.Button(next_row,text='Allow this VM through firewall',command=self.firewall).pack(side='left',padx=(0,8))
        self.export_button=ttk.Button(next_row,text='Export Ubuntu client ZIP',command=self.export_client)
        self.export_button.pack(side='left',padx=5)
        ttk.Button(next_row,text='Open practice operator',command=self.practice).pack(side='left',padx=5)
        ttk.Button(outer,text='Verify this installation before presenting',command=self.verify).pack(anchor='w',pady=(8,0))
        self.status=tk.StringVar(value='Ready to start. Your previous installation and evidence are kept in their old folder.')
        ttk.Label(outer,textvariable=self.status,wraplength=720).pack(anchor='w',pady=10)
        self.log=tk.Text(outer,height=13,bg='#102638',fg='#d3e5f0',font=('Consolas',9),wrap='word');self.log.pack(fill='both',expand=True)
        ttk.Button(outer,text='Open beginner guide',command=lambda:webbrowser.open((ROOT/'ui'/'guide.html').as_uri())).pack(anchor='w',pady=(10,0))
        self.window.protocol('WM_DELETE_WINDOW',self.close)
        self.window.after(200,self.drain)
        self.detect_addresses();self.detect_adapters()

    def drain(self):
        while not self.events.empty():
            kind,value=self.events.get_nowait()
            if kind=='log':self.log.insert('end',value+'\n');self.log.see('end')
            elif kind=='status':self.status.set(value)
            elif kind=='ready':self.status.set('WATERGUARD READY · Open the Windows dashboard, then connect the Ubuntu operator.');webbrowser.open('https://localhost:8443/')
            elif kind=='adapters':
                self.log.insert('end',value['text']+'\n');self.log.see('end')
                if value['numbers']:self.interfaces.set(','.join(value['numbers']))
            elif kind=='addresses':self.address_label.set('Windows IPv4: '+value)
            elif kind=='stopped':
                self.start_button.config(state='normal');self.stop_button.config(state='disabled');self.process=None
                self.status.set('Stopped. Capture finalization finished.' if value==0 else 'Stopped with an error. Read the startup/capture log below.')
                if self.log_handle:self.log_handle.close();self.log_handle=None
            elif kind=='checks_done':
                self.verifying=False;self.status.set(value)
            elif kind=='export_done':
                self.exporting=False;self.export_button.config(state='normal')
                self.status.set('Ubuntu package ready: '+str(value))
                self.log.insert('end','Ubuntu client ZIP exported: '+str(value)+'\n');self.log.see('end')
                try:os.startfile(str(value.parent))
                except OSError as exc:self.log.insert('end','Open the project folder to find the ZIP: '+str(exc)+'\n')
                messagebox.showinfo('Ubuntu package ready','File Explorer has been opened. Copy Device_A_Only.zip to Ubuntu:\n'+str(value)+'\n\nWindows evidence keys are excluded.',parent=self.window)
            elif kind=='export_failed':
                self.exporting=False;self.export_button.config(state='normal')
                self.status.set('Ubuntu export failed: '+value)
                self.log.insert('end','EXPORT ERROR: '+value+'\n');self.log.see('end')
                messagebox.showerror('Export failed',value,parent=self.window)
        self.window.after(200,self.drain)

    def detect_addresses(self):
        def work():
            try:
                text=subprocess.check_output(['ipconfig'],text=True,errors='replace')
                ips=re.findall(r'IPv4[^:]*:\s*(\d+\.\d+\.\d+\.\d+)',text)
                self.events.put(('addresses',', '.join(ips) or 'Run ipconfig to find your Wi-Fi address'))
            except Exception as exc:self.events.put(('addresses',str(exc)))
        threading.Thread(target=work,daemon=True).start()

    def detect_adapters(self):
        def work():
            tshark=Path(os.environ.get('ProgramFiles','C:\\Program Files'))/'Wireshark'/'tshark.exe'
            try:
                text=subprocess.check_output([str(tshark),'-D'],text=True,errors='replace',timeout=8)
                rows=text.splitlines();found=[]
                for needle in ('(Wi-Fi)','NPF_Loopback'):
                    for row in rows:
                        if needle.lower() in row.lower():found.append(row.split('.',1)[0]);break
                self.events.put(('adapters',{'text':text,'numbers':found}))
            except Exception as exc:self.events.put(('log','TShark adapter detection failed: '+str(exc)+'. Install Wireshark with Npcap.'))
        threading.Thread(target=work,daemon=True).start()

    def address(self):
        try:
            address=ipaddress.IPv4Address(self.vm_ip.get().strip())
            if address.is_unspecified or address.is_multicast or address.is_loopback:raise ValueError()
            return str(address)
        except ValueError:
            messagebox.showerror('Ubuntu IP needed','Enter the Ubuntu bridged IPv4 address, for example 192.168.0.190.');return None

    def start(self):
        if self.process:return
        for port in (6000,1502,5502,8443):
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.2):
                    messagebox.showerror('Another service is running',f'Port {port} is already in use. Stop your previous WaterGuard copy before starting this one.')
                    return
            except OSError:
                pass
        two_device=self.mode.get()=='Ubuntu VM + Windows'
        address=self.address() if two_device else '127.0.0.1'
        if not address:return
        interfaces=self.interfaces.get().strip() if two_device else 'auto'
        if not re.fullmatch(r'auto|[0-9]+(?:,[0-9]+)*',interfaces):
            messagebox.showerror('Capture adapters','Enter adapter numbers like 5,9, or auto for practice.');return
        SETTINGS.parent.mkdir(parents=True,exist_ok=True)
        SETTINGS.write_text(json.dumps({'mode':self.mode.get(),'vm_ip':self.vm_ip.get(),'interfaces':self.interfaces.get()}))
        env=os.environ.copy();env.pop('WG_ROLE',None)
        env['WG_AUTHORIZED_SOURCES']=f'hmi-01={address},hmi-local=127.0.0.1'
        env['WG_CONTROLLER_HOST']='127.0.0.1';env['WG_GATEWAY_TRUSTED_IP']='127.0.0.1';env['WG_CAPTURE_REQUIRED']='1'
        self.log_handle=(ROOT/'data'/'presentation-startup.log').open('a',encoding='utf-8')
        self.process=subprocess.Popen([sys.executable,'-u','run_waterguard.py','--no-demo','--no-browser','--capture-interface',interfaces],cwd=ROOT,env=env,
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding='utf-8',errors='replace',bufsize=1,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name=='nt' else 0)
        process=self.process
        self.start_button.config(state='disabled');self.stop_button.config(state='normal');self.status.set('Starting controller, gateway, capture, and HTTPS dashboard…')
        def read():
            for line in process.stdout:
                self.events.put(('log',line.rstrip()))
                if self.log_handle:self.log_handle.write(line);self.log_handle.flush()
                if 'WATERGUARD IS READY' in line:self.events.put(('ready',None))
            self.events.put(('stopped',process.wait()))
        threading.Thread(target=read,daemon=True).start()

    def stop(self):
        if self.process and self.process.poll() is None:
            self.status.set('Stopping safely and finalizing the packet capture. Please wait…');self.stop_button.config(state='disabled')
            self.process.send_signal(signal.CTRL_BREAK_EVENT if os.name=='nt' else signal.SIGINT)

    def export_client(self):
        if self.exporting:return
        self.exporting=True;self.export_button.config(state='disabled')
        self.status.set('Creating the Ubuntu client ZIP. Please wait…')
        def work():
            try:
                from run_waterguard import ensure_configuration
                ensure_configuration()
                from tools.export_device_a_bundle import export
                self.events.put(('export_done',export()))
            except Exception as exc:self.events.put(('export_failed',str(exc)))
        threading.Thread(target=work,daemon=True).start()

    def verify(self):
        if self.verifying:
            messagebox.showinfo('Checks are running','Wait for the current installation check to finish.');return
        self.verifying=True
        self.status.set('Running dependency, capture and regression checks. Results will appear in this window.')
        def work():
            env=os.environ.copy();env.pop('WG_ROLE',None);env['WG_AUTHORIZED_SOURCES']='hmi-01=127.0.0.1'
            for arguments in (['-m','tools.check_environment','--capture-test'],['-m','pytest','-q']):
                process=subprocess.Popen([sys.executable,*arguments],cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding='utf-8',errors='replace')
                for line in process.stdout:self.events.put(('log',line.rstrip()))
                if process.wait()!=0:
                    self.events.put(('checks_done','Verification failed. Read the error above; do not claim the installation passed.'));return
            self.events.put(('checks_done','INSTALLATION CHECKS PASSED. Rehearse the two-device GUI demonstration before evaluation.'))
        threading.Thread(target=work,daemon=True).start()

    def firewall(self):
        address=self.address()
        if not address:return
        directory=ROOT/'data';directory.mkdir(exist_ok=True)
        result=directory/'firewall-status.json'
        if result.exists():result.unlink()
        script=firewall_script(address,result)
        encoded=base64.b64encode(script.encode('utf-16le')).decode('ascii')
        status=ctypes.windll.shell32.ShellExecuteW(None,'runas','powershell.exe','-NoProfile -EncodedCommand '+encoded,None,1)
        if status<=32:self.status.set('Windows did not apply the firewall rules. Accept the administrator prompt or use the manual commands in the guide.');return
        self.status.set('Accept the Windows administrator prompt. Rules open only ports 6000, 1502, 8443 to this VM IP.')
        def check():
            for _ in range(60):
                if result.exists():
                    try:
                        answer=json.loads(result.read_text(encoding='utf-8-sig'))
                        self.events.put(('status','Firewall rules applied for '+address if answer.get('success') else 'Firewall error: '+answer.get('detail','unknown')));return
                    except (OSError,ValueError):pass
                time.sleep(.5)
            self.events.put(('status','No firewall result yet. Check the Windows administrator prompt.'))
        threading.Thread(target=check,daemon=True).start()

    def practice(self):
        if self.mode.get()!='One-laptop practice':messagebox.showinfo('Practice mode','Use this button only for practice on one laptop. In the graded demo, open the operator in Ubuntu.');return
        if self.client and self.client.poll() is None:webbrowser.open('http://127.0.0.1:8080/');return
        try:
            with socket.create_connection(('127.0.0.1',8080),timeout=.2):
                messagebox.showerror('Operator port is in use','Stop your previous operator service on port 8080 before opening a practice operator.');return
        except OSError:
            pass
        env=os.environ.copy();env['WG_ROLE']='device-a'
        self.client=subprocess.Popen([sys.executable,'-m','device_a.app'],cwd=ROOT,env=env)
        def open_ready():
            for _ in range(40):
                try:
                    urllib.request.urlopen('http://127.0.0.1:8080/',timeout=.3).close();webbrowser.open('http://127.0.0.1:8080/');return
                except OSError:time.sleep(.25)
            self.events.put(('status','Practice operator did not start. Read its error or check port 8080.'))
        threading.Thread(target=open_ready,daemon=True).start()

    def close(self):
        if self.process and self.process.poll() is None:
            self.stop();messagebox.showinfo('Stopping safely','Wait until the status says Stopped, then close this window. This preserves the final PCAP export.');return
        if self.client and self.client.poll() is None:self.client.terminate()
        self.window.destroy()

def main():
    if os.name!='nt':raise SystemExit('Use START_DEVICE_A.sh in Ubuntu; this launcher is for Windows.')
    Launcher().window.mainloop()

if __name__=='__main__':main()
