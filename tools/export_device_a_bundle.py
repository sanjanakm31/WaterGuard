"""Build a client-only ZIP using this host's command key, never evidence keys."""
from pathlib import Path
import zipfile
from shared import config

ROOT = Path(__file__).resolve().parent.parent
def export(destination=None):
    destination = Path(destination or ROOT/'Device_A_Only.zip')
    directories = ('shared','client','attacker','device_a','ui')
    members = []
    for directory in directories:
        members.extend(p for p in (ROOT/directory).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    with zipfile.ZipFile(destination,'w',zipfile.ZIP_DEFLATED) as archive:
        for p in members:
            # Device A needs only its own screens, not Windows proof pages.
            if p.parent.name == 'ui' and p.name not in ('operator.html','operator.js','style.css','common.js'):
                continue
            archive.write(p,Path('waterguard-device-a')/p.relative_to(ROOT))
        for name in ('START_DEVICE_A.sh','requirements_device_a.txt','DEVICE_A_README.txt'):
            archive.write(ROOT/name,Path('waterguard-device-a')/name)
        archive.writestr('waterguard-device-a/.env', 'WG_ROLE=device-a\nWG_COMMAND_HMAC_KEY='+config.COMMAND_HMAC_KEY.hex()+'\n')
    return destination

if __name__=='__main__':
    print('Client-only package exported:',export())
