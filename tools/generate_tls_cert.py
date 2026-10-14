"""
tools/generate_tls_cert.py

Generates a self-signed TLS certificate + private key for the dashboard's
HTTPS listener, using the `cryptography` package (already a project
dependency for AES-256-GCM, so this adds no new dependency).

A self-signed certificate is explicitly appropriate here and should be
described as such in the report -- it is standard practice for an internal
prototype/lab dashboard (the synopsis specifies "self-signed certificate
for prototype use"), NOT for any public-facing deployment, where a
CA-issued certificate would be required instead.

Usage:
    python3 -m tools.generate_tls_cert
    # writes tls/dashboard_cert.pem and tls/dashboard_key.pem
"""

from __future__ import annotations

import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

TLS_DIR = Path(__file__).resolve().parent.parent / "tls"
CERT_PATH = TLS_DIR / "dashboard_cert.pem"
KEY_PATH = TLS_DIR / "dashboard_key.pem"


def generate(common_name: str = "waterguard-dashboard.local", valid_days: int = 825) -> None:
    TLS_DIR.mkdir(parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Karnataka"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Manipal"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "WaterGuard Capstone Project"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )
    certificate = cert_builder.sign(private_key, hashes.SHA256())

    KEY_PATH.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    CERT_PATH.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

    print(f"Wrote {CERT_PATH}")
    print(f"Wrote {KEY_PATH}")
    print(
        f"\nSelf-signed certificate valid for {valid_days} days, CN={common_name}.\n"
        f"Your browser will show a 'not secure' / 'self-signed certificate' warning when "
        f"you open the dashboard -- this is EXPECTED for a self-signed prototype cert "
        f"(the synopsis specifies this explicitly) and is safe to click through for your "
        f"local lab demo. Do not reuse this certificate outside this project."
    )


if __name__ == "__main__":
    generate()
