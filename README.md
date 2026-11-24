# SecureChat

SecureChat is a Python-based secure messaging application. It supports encrypted messaging, user authentication, digital signatures, public-key fingerprint verification and encrypted private-key storage.

## Features

- Graphical user interface (GUI) and command-line interface (CLI).
- X25519 key agreement and HKDF-SHA256 key derivation.
- AES-256-GCM message encryption.
- Ed25519 digital signatures.
- Argon2id password hashing.
- SHA-256 public-key fingerprint verification.
- Private-key storage using Scrypt and AES-GCM.
- HTTPS/TLS communication.
- Flask backend and SQLite database.

## Requirements

- Python 3.13 or a compatible version
- pip

## Installation

Open the project folder in VS Code and execute the following commands in the terminal.

### 1. Create and activate a virtual environment

python -m venv .venv
.\.venv\Scripts\Activate.ps1

### 2. Install dependencies

python -m pip install -r requirements.txt

### 3. Generate TLS certificates

python generate_certs.py

This generates the CA certificate, server certificate and server private key required for HTTPS communication.

### 4. Initialize the database

python -c "from server.database import initialize_database; initialize_database()"

## Running the Application

### 1. Start the server

python -m server.app

The server runs at https://127.0.0.1:5000.

### 2. Start the client

Open a new terminal, activate the virtual environment and run:

python -m client.gui

to use the command-line interface, run:

python -m client.cli

### 3. Send and receive messages

- Register two users.
- Open two separate client instances.
- Log in using the registered accounts.
- Verify contact fingerprints through a trusted channel.
- Send and receive messages.

## Attack Simulation

Run the following command to simulate a public-key substitution attack:

python attack_sim.py

There are three options:

1. Replace a user's public encryption key.
2. Restore the original public key.
3. Check active attacks.

This demonstrates how SecureChat detects changes to previously trusted public keys and blocks message transmission when a fingerprint mismatch occurs.

## Running Tests

run:

python -m pytest -v