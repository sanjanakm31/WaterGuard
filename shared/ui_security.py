"""Loopback UI protections; no arbitrary targets or permissive CORS."""
import hmac
import ipaddress
import secrets
from urllib.parse import urlsplit
from fastapi import HTTPException, Request

LOCAL_TOKEN = secrets.token_urlsafe(32)

def require_local(request: Request) -> None:
    try:
        local = ipaddress.ip_address(request.client.host).is_loopback
        hostname = urlsplit('https://' + request.headers.get('host', '')).hostname
        if hostname != 'localhost':
            local = local and ipaddress.ip_address(hostname or '').is_loopback
    except (ValueError, AttributeError):
        local = False
    if not local:
        raise HTTPException(403, "Open this protected screen on Windows at https://localhost:8443/")

def require_local_write(request: Request) -> None:
    require_local(request)
    if not hmac.compare_digest(request.headers.get("x-waterguard-token", ""), LOCAL_TOKEN):
        raise HTTPException(403, "Local session token required; reload the page")
    origin = request.headers.get("origin")
    if origin and urlsplit(origin).netloc != request.headers.get("host"):
        raise HTTPException(403, "Cross-origin requests are refused")

def validate_ipv4(value: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
        if address.is_unspecified or address.is_multicast or str(address) == "255.255.255.255":
            raise ValueError()
        return str(address)
    except ValueError:
        raise HTTPException(422, "Enter the Windows laptop's IPv4 address, for example 192.168.0.167")
