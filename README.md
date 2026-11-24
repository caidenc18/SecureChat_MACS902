
# SecureChat

A Python-based secure messaging prototype
SecureChat demonstrates authenticated user access, public-key cryptography, encrypted message exchange, digital signatures, trusted public-key fingerprints, and encrypted local private-key storage, and HTTPS/TLS transport security.

## Features

- User registration and authentication.
- Password hashing using Argon2id.
- X25519 key agreement for deriving shared secrets.
- HKDF-SHA256 for deriving message-encryption keys.
- AES-256-GCM authenticated encryption for messages.
- Ed25519 digital signatures for message authenticity and integrity.
- SHA-256 fingerprints for identifying and verifying public keys.
- Scrypt-based key derivation and AES-GCM encryption for locally stored private keys.
- SQLite database for user records and encrypted message envelopes.
- Message acknowledgment and pending-message tracking.
- HTTPS/TLS with a locally generated CA-signed server certificate and client-side certificate verification.
- Tkinter graphical interface and command-line interface.
- Automated tests for cryptographic operations, authentication, key trust, and message delivery.

## Architecture

The application consists of two main components:

### Client

The Python client provides both a Tkinter graphical interface (`client/gui.py`) and a command-line interface (`client/cli.py`). It handles message encryption and decryption, digital-signature verification, public-key fingerprint verification, and local private-key storage. HTTPS requests verify the server certificate using `certs/ca.crt`.

Private keys are encrypted before being stored in local files.

### Server

The Flask server provides REST API endpoints for registration, login, public-key retrieval, message submission, inbox retrieval, message acknowledgment, and logout.

The server stores user records and routes encrypted message envelopes. It does not decrypt message contents.

SQLite is used as the database. The Flask server serves HTTPS on port 5000 using `certs/server.crt` and `certs/server.key`.

## Cryptographic Algorithms

| Purpose | Algorithm |
|---|---|
| Key agreement | X25519 |
| Key derivation for messages | HKDF-SHA256 |
| Message encryption | AES-256-GCM |
| Digital signatures | Ed25519 |
| Public-key fingerprints | SHA-256 |
| Password hashing | Argon2id |
| Client–server transport | HTTPS/TLS (TLS 1.2 minimum) |
| Private-key storage key derivation | Scrypt |
| Private-key file encryption | AES-GCM |

### Message encryption

The sender creates an ephemeral X25519 key pair and derives a shared secret with the recipient's public encryption key. HKDF-SHA256 derives a symmetric encryption key, which is used with AES-256-GCM to encrypt the message.

The sender signs the message envelope with their Ed25519 private signing key. The recipient verifies the signature and decrypts the message using their private encryption key.

### Private-key storage

The client's private keys are serialized and encrypted using AES-GCM. Scrypt derives the storage-encryption key from the user's passphrase. A random salt and nonce are generated for each saved key file.

### Public-key trust

The client calculates a fingerprint from a user's public encryption and signing keys. On first contact, the user is asked to verify and trust the fingerprint. A changed fingerprint is rejected so the user can investigate a possible key substitution.

## Installation

Requirements:

- Python 3.13 or a compatible Python version
- pip

### 1. Create and activate a virtual environment

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

## TLS Certificate Setup

The project uses a local test certificate authority (CA) to issue the server's TLS certificate. From the project root, generate the certificates if they are not already present:

```powershell
python generate_certs.py
```

This creates:

- `certs/ca.crt` — local CA certificate used by the client to verify the server.
- `certs/server.crt` — CA-signed server certificate valid for `localhost` and `127.0.0.1`.
- `certs/server.key` — server private key; keep it confidential.

The client connects to `https://127.0.0.1:5000` and uses `certs/ca.crt` for certificate verification. The Flask server loads the server certificate and private key and requires TLS 1.2 or later. Do not disable certificate verification or share the private key. Regenerating certificates replaces the existing test CA and server credentials; clients must use the matching new `ca.crt`.

These certificates are intended for local testing, not public production deployment.

## Running the Application

Start the Flask server from the project root:

```powershell
python -m server.app
```

The server listens on port `5000` using HTTPS. The client connects to `https://127.0.0.1:5000`.

Open a second PowerShell terminal, activate the virtual environment, and run the graphical client:

```powershell
python -m client.gui
```

Alternatively, run the command-line client:

```powershell
python -m client.cli
```

Register users, log in, verify contact fingerprints through a separate trusted channel, send encrypted messages, check the inbox, and log out. For a local two-user demonstration, launch two separate client instances. Private keys and trusted fingerprints are stored locally under `data/<username>/`.

## Running Tests

Run the complete automated test suite from the project root:

```powershell
python -m pytest -v
```

The project has 19 reported passing automated tests covering:

- Message encryption and decryption.
- Tampered ciphertext rejection.
- Invalid digital-signature rejection.
- Wrong-recipient rejection.
- Public-key fingerprint trust and mismatch detection.
- Wrong-passphrase rejection for private-key files.
- User registration and login validation.
- Authentication and recipient authorization.
- Pending-message retrieval and delivery acknowledgment.

The listed automated tests do not by themselves demonstrate TLS certificate validation. Verify HTTPS operation separately with the running server and client.

## Security Limitations

This project is an educational prototype and is not intended for production deployment.

- HTTPS/TLS is implemented for client–server communication, but the included test CA and certificates are intended for local demonstrations rather than production deployment.
- The application implements client-side message encryption, but it is an educational prototype rather than a production-ready end-to-end encrypted messaging system. Public-key trust, session management, deployment security, and operational safeguards require further work.
- The server cannot independently verify that a recipient actually decrypted a message; it relies on the authenticated client to acknowledge delivery.
- User and message metadata, including sender, recipient, and timestamps, may be visible to the server.
- Sessions are held in memory and are invalidated when the server restarts.
- Rate limiting, persistent session management, key revocation, and account recovery require further development.
- Fingerprint verification depends on users comparing fingerprints through a trusted, separate channel.

## Future Improvements

- Harden TLS configuration and certificate management for deployment beyond the local test environment.
- Implement stronger session management, expiration, and rate limiting.
- Add key revocation and identity-key rotation.
- Improve delivery receipts and multi-device support.
- Expand automated security tests, including TLS certificate-validation tests, and conduct a structured threat assessment.
- Add secure deployment configuration and operational logging.
- Multi-factor authentication (MFA) can help provide an additional layer of authentication to protect accounts from being compromised from credential theft. 

