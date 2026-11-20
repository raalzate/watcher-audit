# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography>=42"]
# ///
"""Genera una CA propia y el certificado TLS del repositorio Watcher. Sin openssl: uv trae la dependencia.

    uv run --script deploy/gen_cert.py --out DIR [--name repo.empresa.local] [--ip 10.0.0.5]

Escribe en DIR:
  ca.pem    -> se copia a cada equipo auditado (install.ps1 -CaFile ca.pem / install.sh ... ca.pem)
  cert.pem  -> certificado del servidor (watcher-server --tls-cert)
  key.pem   -> clave privada del servidor (watcher-server --tls-key). No sale de este equipo.

La clave de la CA no se guarda: sirve solo para firmar este certificado. Renovar = generar de nuevo
y redistribuir ca.pem.
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import socket
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _usage(**on: bool) -> x509.KeyUsage:
    keys = ("digital_signature", "content_commitment", "key_encipherment", "data_encipherment",
            "key_agreement", "key_cert_sign", "crl_sign", "encipher_only", "decipher_only")
    return x509.KeyUsage(**{k: on.get(k, False) for k in keys})


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", required=True, help="carpeta de salida")
    p.add_argument("--name", action="append", default=[], help="nombre DNS del repositorio (repetible)")
    p.add_argument("--ip", action="append", default=[], help="IP del repositorio (repetible)")
    args = p.parse_args(argv)

    names = list(dict.fromkeys([*(args.name or [socket.gethostname()]), "localhost"]))
    ips = list(dict.fromkeys([*args.ip, "127.0.0.1"]))
    now = dt.datetime.now(dt.timezone.utc)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Watcher CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(hours=1)).not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_usage(key_cert_sign=True, crl_sign=True), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    key = ec.generate_private_key(ec.SECP256R1())
    san = [x509.DNSName(n) for n in names] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
        .issuer_name(ca_name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(hours=1)).not_valid_after(now + dt.timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_usage(digital_signature=True), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (out / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (out / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                    serialization.NoEncryption()))
    print(f"certificado para: {', '.join(names + ips)}")
    print(f"escrito en      : {out.resolve()}  (ca.pem, cert.pem, key.pem)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
