
import base64
import json
import os
import hashlib

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (Ed25519PrivateKey,Ed25519PublicKey,) #importing Ed25519 keys for digitally signing messages
from cryptography.hazmat.primitives.asymmetric.x25519 import (X25519PrivateKey,X25519PublicKey) #importing X25519 keys for key exchange and encryption
from cryptography.hazmat.primitives.ciphers.aead import AESGCM #importing AES-GCM for symmetric encryption
from cryptography.hazmat.primitives.kdf.hkdf import HKDF   #importing HKDF for key derivation


def encode_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8") #converting bytes to base64 string


def decode_bytes(data: str) -> bytes:
    return base64.b64decode(data, validate=True) #converting base64 string back to bytes


def raw_public_key(key) -> bytes:
    return key.public_bytes(encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,) #exporting public key in raw byte format


def generate_identity():
    encryption_private = X25519PrivateKey.generate() #generating X25519 private key
    signing_private = Ed25519PrivateKey.generate() #generating Ed25519 private key
    identity = {"encryption_private": encryption_private,"signing_private": signing_private,"encryption_public": raw_public_key(encryption_private.public_key()),
        "signing_public": raw_public_key(signing_private.public_key())} #storing the generated X25519 and Ed25519 private and public keys of the user
    return identity


def derive_message_key(shared_secret: bytes, salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(),length=32,salt=salt,info=b"SecureChatCLI message encryption v1",).derive(shared_secret) #deriving the message key using the shared secret


def encrypt_message(plaintext: str,recipient_encryption_public: bytes,sender_signing_private: Ed25519PrivateKey,sender_username: str,recipient_username: str,) -> dict:
    ephemeral_private = X25519PrivateKey.generate() #generating one time private key
    recipient_public = X25519PublicKey.from_public_bytes(recipient_encryption_public) #receipients X25519 public key
    shared_secret = ephemeral_private.exchange(recipient_public) #one time private key and receipients public key are used to derive a shared secret
    salt = os.urandom(16) #
    message_key = derive_message_key(shared_secret, salt) #deriving the message key using the computed shared secret and random salt
    nonce = os.urandom(12)
    aad = json.dumps({"sender": sender_username,"recipient": recipient_username,}, sort_keys=True,separators=(",", ":"),).encode("utf-8")
    ciphertext = AESGCM(message_key).encrypt(nonce, plaintext.encode("utf-8"), aad) #encrypting the messaging using AES-GCM with the message key, nonce and aad

    envelope = {"version": 1, "sender": sender_username,"recipient": recipient_username,"ephemeral_public": encode_bytes(raw_public_key(ephemeral_private.public_key())),
        "salt": encode_bytes(salt),"nonce": encode_bytes(nonce),"ciphertext": encode_bytes(ciphertext),} #message envelope containing ciphertext, one time public key, sender and receipient usernames

    signed_data = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8") 
    signature = sender_signing_private.sign(signed_data) #signing the message envelope using the senders Ed25519 private key
    envelope["signature"] = encode_bytes(signature)
    print("Message encrypted and signed successfully!")
    return envelope


def decrypt_message(envelope: dict,recipient_encryption_private: X25519PrivateKey,sender_signing_public: bytes,expected_sender: str,expected_recipient: str,) -> str:
    if envelope.get("version") != 1:
        raise ValueError("Unsupported message version.")

    if envelope.get("sender") != expected_sender: #verifies the sender of the message, otherwise raises an error
        raise ValueError("Unexpected sender.")

    if envelope.get("recipient") != expected_recipient: #verifies the recipient of the message, otherwise raises an error
        raise ValueError("Unexpected recipient.")

    unsigned_envelope = {key: value for key, value in envelope.items() if key != "signature"}
    signed_data = json.dumps(unsigned_envelope, sort_keys=True, separators=(",", ":")).encode("utf-8") 
    try:
        Ed25519PublicKey.from_public_bytes(sender_signing_public).verify(decode_bytes(envelope["signature"]), signed_data) #verifies the signature using the senders Ed25519 public key
        print("Message signature verified successfully!")
    except (InvalidSignature, ValueError, KeyError) as e:
        raise ValueError("Message signature verification failed.") from e #raises an error if the signature verification fails

    ephemeral_public = X25519PublicKey.from_public_bytes(decode_bytes(envelope["ephemeral_public"])) #extracts the one time public key from the message envelope
    shared_secret = recipient_encryption_private.exchange(ephemeral_public) #computes the shared secret using the recipients X25519 private key and one time public key
    message_key = derive_message_key(shared_secret, decode_bytes(envelope["salt"])) #derives the message key using the computed shared secret and salt from the message envelope

    aad = json.dumps({"sender": expected_sender,"recipient": expected_recipient,},
        sort_keys=True,separators=(",", ":"),).encode("utf-8")
    
    try:
        plaintext = AESGCM(message_key).decrypt(decode_bytes(envelope["nonce"]),
            decode_bytes(envelope["ciphertext"]),aad,) #decrypts the ciphertext using AES-GCM with the derived message key
        print("Message decrypted successfully!")
    except (InvalidTag, ValueError) as e:
        raise ValueError("Message decryption or authentication failed.") from e #raises an error if the decryption or authentication fails

    return plaintext.decode("utf-8")

def export_public_bundle(identity: dict) -> dict:
    return {"encryption_public_key": encode_bytes(identity["encryption_public"]),
        "signing_public_key": encode_bytes(identity["signing_public"]),} 

def public_key_fingerprint(encryption_public: bytes,signing_public: bytes,) -> str:
    combined = (b"SecureChatCLI fingerprint v1"+ encryption_public+ signing_public) #combining the X25519 and Ed25519 public keys with a prefix to create a unique fingerprint
    digest = hashlib.sha256(combined).hexdigest().upper() #creating a hash of the fingerprint

    return " ".join(digest[index:index + 4]for index in range(0, len(digest), 4))
