
from datetime import datetime, timedelta, timezone
from pathlib import Path
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


CERT_DIR = Path(__file__).resolve().parent / "certs" #path to the directory where the generated certificates will be stored
CERT_DIR.mkdir(parents=True, exist_ok=True)

now = datetime.now(timezone.utc) #initializing the current date and time in UTC timezone for certificate validity period


ca_key = rsa.generate_private_key(public_exponent=65537,key_size=3072) #generates RSA private key for root CA 

ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"SecureChat Test Root CA")]) #creates a name for the root CA certificate with the common name "SecureChat Test Root CA"


ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - timedelta(days=1))
    .not_valid_after(now + timedelta(days=365))
    .add_extension(
        x509.BasicConstraints(
            ca=True,
            path_length=0
        ),
        critical=True
    ) #
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    ) #adding key usage extension to the root CA certificate
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(
            ca_key.public_key()
        ),
        critical=False
    ) #adding subject key identifier extension to the root CA certificate
    .add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(
            ca_key.public_key()
        ),
        critical=False
    )
    .sign(ca_key, hashes.SHA256())
) #signing the root CA certificate with its own private key using SHA256 hashing algorithm


server_key = rsa.generate_private_key(public_exponent=65537,key_size=3072) #generates RSA private key for the server certificate

server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"localhost")]) #creates a name for the server certificate with the common name "localhost"

server_cert = (
    x509.CertificateBuilder()
    .subject_name(server_name)
    .issuer_name(ca_name)
    .public_key(server_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - timedelta(days=1))
    .not_valid_after(now + timedelta(days=365))
    .add_extension(
        x509.BasicConstraints(
            ca=False,
            path_length=None
        ),
        critical=True
    )
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(
                ipaddress.ip_address("127.0.0.1")
            )
        ]),
        critical=False
    ) #adding subject alternative name extension to the server certificate for localhost
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )
    .add_extension(
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH
        ]),
        critical=False
    ) #adding extended key usage extension to the server certificate for server authentication
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(
            server_key.public_key()
        ),
        critical=False
    ) #adding subject key identifier extension to the server certificate
    .add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(
            ca_key.public_key()
        ),
        critical=False
    )
    .sign(ca_key, hashes.SHA256())
) #signing the server certificate with the root CA's private key using SHA256 hashing algorithm



(CERT_DIR / "ca.crt").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM)) #writing the root CA certificate to a file in PEM format

(CERT_DIR / "server.crt").write_bytes(server_cert.public_bytes(serialization.Encoding.PEM)) #writing the server certificate to a file in PEM format

(CERT_DIR / "server.key").write_bytes(
    server_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())) #writing the server private key to a file in PEM format without encryption


from cryptography.hazmat.primitives.asymmetric import padding

ca_key.public_key().verify(server_cert.signature,server_cert.tbs_certificate_bytes,
    padding.PKCS1v15(),server_cert.signature_hash_algorithm) #verifying the server's certificate signature


print("\n========================================")
print(" SecureChat TLS Certificate Generator")
print("========================================")

print("\n[OK] Root CA certificate generated")
print("[OK] Server private key generated")
print("[OK] Server certificate generated")
print("[OK] Certificate signature verified")

print("\nCertificate directory:")
print(CERT_DIR)

print("\nGenerated files:")
print(" - ca.crt")
print(" - server.crt")
print(" - server.key")

print("\nServer certificate valid for:")
print(" - localhost")
print(" - 127.0.0.1")

print("\nTLS certificates generated successfully!")
print("========================================\n")
