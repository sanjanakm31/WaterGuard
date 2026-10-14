WATERGUARD DEVICE A - UBUNTU OPERATOR APPLICATION

1. Extract Device_A_Only.zip in Ubuntu. Open the waterguard-device-a folder.
2. Right-click inside that folder > Open in Terminal.
3. Type: bash START_DEVICE_A.sh
4. Firefox opens http://127.0.0.1:8080/.
5. In Connection setup, enter your WINDOWS laptop's Wi-Fi IPv4 address.
6. Click Connect. Send chlorine/valve commands using the forms.
7. Use Security demonstrations for the other controlled cases.

The launcher automatically reuses your existing verified environment at
~/WaterGuardVM/waterguard/.venv, if available. Otherwise first-time setup
needs Python 3, python3-venv, and internet to install the listed packages.
Keep its terminal open. Ctrl+C stops the local operator service.
After the first launch, Ubuntu Applications > search WaterGuard Device A
opens the launcher through the installed per-user shortcut.

This package carries only the command HMAC key. It excludes the Windows
evidence AES/HMAC keys and the controller/gateway/dashboard server modules.
Keep this lab package private. It has permission to issue commands in YOUR lab.
The key is in the local backend, not embedded in browser JavaScript.

If your previous Ubuntu folder or downloaded full ZIP contained evidence
keys, those older copies do not vanish when you use this new package.
Do not claim that changing .env removed every historical key copy.
For a clean role demonstration, use only this package in Device A.

This is the user interface for your EXISTING VirtualBox Ubuntu VM.
It is not an Ubuntu virtual disk and does not install/change VirtualBox.
Keep the VM's working NAT + bridged adapter configuration.
