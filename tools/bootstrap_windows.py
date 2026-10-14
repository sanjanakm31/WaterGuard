"""Reuse the user's verified Python environment, or install into a new venv."""
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
def ready(executable):
    return subprocess.run([str(executable),'-c','import pymodbus, cryptography, fastapi, uvicorn, pyshark'],
                          stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0

def main():
    candidates=[ROOT/'.venv'/'Scripts'/'python.exe',Path(sys.executable)]
    old=Path.home()/'Downloads'/'WaterGuard_Updated_v2_Windows_Fixed'/'waterguard'/'.venv'/'Scripts'/'python.exe'
    candidates.append(old)
    for candidate in candidates:
        if candidate.exists() and ready(candidate):
            return subprocess.call([str(candidate),'-m','tools.launch_windows'],cwd=ROOT)
    print('First-time setup: creating a Python environment and installing dependencies. Internet is required once.')
    subprocess.run([sys.executable,'-m','venv',str(ROOT/'.venv')],check=True)
    executable=ROOT/'.venv'/'Scripts'/'python.exe'
    subprocess.run([str(executable),'-m','pip','install','-r',str(ROOT/'requirements.txt')],check=True)
    return subprocess.call([str(executable),'-m','tools.launch_windows'],cwd=ROOT)

if __name__=='__main__':
    raise SystemExit(main())
