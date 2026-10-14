"""Install a per-user Ubuntu menu shortcut after the first launch."""
from pathlib import Path
import os

def install():
    root=Path(__file__).resolve().parent.parent
    applications=Path.home()/'.local'/'share'/'applications'
    applications.mkdir(parents=True,exist_ok=True)
    script=str(root/'START_DEVICE_A.sh').replace('\\','\\\\').replace('"','\\"').replace('%','%%').replace('$','\\$').replace('`','\\`')
    entry=applications/'waterguard-device-a.desktop'
    entry.write_text('[Desktop Entry]\nType=Application\nName=WaterGuard Device A\nComment=Operator controls and security demonstrations\nExec=/usr/bin/env bash "'+script+'"\nTerminal=true\nCategories=Education;Development;\n',encoding='utf-8')
    entry.chmod(0o755)
    print('Ubuntu menu shortcut installed: search for WaterGuard Device A in Applications.')

if __name__=='__main__':install()
