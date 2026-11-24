
import json
import re
import ssl
import secrets
import sqlite3 
import base64
import binascii
from pathlib import Path
from functools import wraps

from argon2 import PasswordHasher #importing PasswordHasher from argon2 for hashing and verifying passwords
from argon2.exceptions import (InvalidHash,VerificationError,VerifyMismatchError,)
from flask import Flask, g, jsonify, request #importing Flask and its modules for creating the web application and handling requests and responses

from server.database import get_connection, initialize_database #importing functions from the database.py file

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 1_000_000 #limits incoming HTTP request bodies to 1 MB.

password_hasher = PasswordHasher()

sessions = {}


def valid_username(username):
    return (isinstance(username, str)and re.fullmatch(r"[a-zA-Z0-9_]{3,32}", username) is not None) #checks if the username is a string and matches the regex pattern

def valid_public_key(value):
    if not isinstance(value, str) or not value:
        return False

    try:
        decoded = base64.b64decode(value, validate=True) #decodes the base64-encoded public key and checks if it is valid
    except (ValueError, binascii.Error):
        return False

    return len(decoded) == 32 

def require_auth(view):
    @wraps(view) 
    def wrapped(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")

        if scheme.lower() != "bearer" or not token:
            return jsonify(error="Authentication required."), 401

        username = sessions.get(token)
        if username is None:
            return jsonify(error="Invalid or expired session."), 401

        g.username = username
        return view(*args, **kwargs)

    return wrapped


def read_json():
    data = request.get_json(silent=True) #gets the JSON data from the request body
    if not isinstance(data, dict):
        return None
    return data


@app.post("/register") #endpoint for user registration
def register():
    data = read_json()
    if data is None:
        return jsonify(error="A JSON object is required."), 400

    username = data.get("username") #gets the username from the JSON data
    password = data.get("password") #gets the password from the JSON data
    encryption_key = data.get("encryption_public_key") #gets the encryption public key from the JSON data
    signing_key = data.get("signing_public_key") #gets the signing public key from the JSON data

    if not valid_username(username):
        return jsonify(error="Username must be 3-32 letters, digits, or underscores."), 400 #returns an error if the username is not valid

    if not isinstance(password, str) or len(password) < 12:
        return jsonify(error="Password must be at least 12 characters."), 400 #returns an error if the password is not valid

       
    if not (valid_public_key(encryption_key)and valid_public_key(signing_key)): 
        return jsonify(error="Valid public keys are required."), 400 #returns an error if the encryption and signing public keys are not valid

    password_hash = password_hasher.hash(password) #hashes the password using password_hasher

    try:
        with get_connection() as connection:
            connection.execute(
                """INSERT INTO users (username, password_hash,encryption_public_key, signing_public_key) VALUES (?, ?, ?, ?)""",
                (username, password_hash, encryption_key, signing_key),) #inserts the new user into the database with hashed password and public keys
    except sqlite3.IntegrityError:
        return jsonify(error="Username already exists."), 409 #returns an error if the username already exists

    return jsonify(message="Registration successful."), 201


@app.post("/login") #endpoint for user login
def login():
    data = read_json()
    if data is None:
        return jsonify(error="A JSON object is required."), 400

    username = data.get("username") #gets the username from the JSON data
    password = data.get("password") #gets the password from the JSON data

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="Username and password are required."), 400 #returns an error if the username and password are not inputted 

    with get_connection() as connection:
        user = connection.execute("SELECT password_hash FROM users WHERE username = ?",
            (username,)).fetchone() #fetches the hashed password from the database using the provided username

    if user is None:
        return jsonify(error="Invalid username or password."), 401 #returns an error if the username does not exist in the database

    try:
        password_hasher.verify(user["password_hash"], password) #verifies the provided password against the stored hashed password using password_hasher
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return jsonify(error="Invalid username or password."), 401

    token = secrets.token_urlsafe(32)
    sessions[token] = username

    return jsonify(token=token), 200


@app.get("/users/<username>/public-key")
@require_auth
def public_key(username):
    with get_connection() as connection:
        user = connection.execute("""SELECT username, encryption_public_key, signing_public_key
            FROM users WHERE username = ?""",(username,),).fetchone()

    if user is None:
        return jsonify(error="User not found."), 404

    return jsonify(username=user["username"],encryption_public_key=user["encryption_public_key"],
        signing_public_key=user["signing_public_key"],)

@app.post("/messages") #endpoint for sending messages
@require_auth
def send_message():
    data = read_json()
    if data is None:
        return jsonify(error="A JSON object is required."), 400

    recipient = data.get("recipient") #gets the recipient username from the JSON data
    envelope = data.get("envelope") #gets the message envelope from the JSON data

    if not isinstance(recipient, str) or not isinstance(envelope, dict):
        return jsonify(error="Recipient and envelope are required."), 400 #returns an error if the recipient and envelope are not inputted

    if envelope.get("sender") != g.username:
        return jsonify(error="Envelope sender does not match login."), 400 #returns an error if the sender in the envelope does not match the logged-in user

    if envelope.get("recipient") != recipient:
        return jsonify(error="Envelope recipient does not match request."), 400 #returns an error if the envelope recipient does not match the requested recipient

    if len(json.dumps(envelope)) > 100_000:
        return jsonify(error="Message envelope is too large."), 413

    with get_connection() as connection:
        sender = connection.execute("SELECT id FROM users WHERE username = ?",(g.username,),).fetchone() #fetches the sender's user ID from the database
        target = connection.execute( "SELECT id FROM users WHERE username = ?",(recipient,),).fetchone() #fetches the recipient's user ID from the database

        if target is None:
            return jsonify(error="Recipient not found."), 404

        cursor = connection.execute("""
            INSERT INTO messages (sender_id, recipient_id, envelope)VALUES (?, ?, ?)""",
            (sender["id"], target["id"], json.dumps(envelope)),) #inserts the message into the database with the sender ID, recipient ID, and message envelope

        message_id = cursor.lastrowid 

    return jsonify(message="Encrypted message queued.", id=message_id), 201


@app.get("/messages") #endpoint for receiving messages
@require_auth
def receive_messages():
    # Fetch pending messages without changing their status.
    # The client acknowledges each message after successful decryption.
    with get_connection() as connection:
        user = connection.execute("SELECT id FROM users WHERE username = ?",
            (g.username,),).fetchone() #fetches the logged-in user's ID from the database

        messages = connection.execute("""
            SELECT m.id, sender.username AS sender, m.envelope, m.created_at
            FROM messages AS m
            JOIN users AS sender ON sender.id = m.sender_id
            WHERE m.recipient_id = ? AND m.status = 'pending'
            ORDER BY m.id""",(user["id"],),).fetchall() #fetches all pending messages for the logged in user from the database

    return jsonify(messages=[ {
            "id": message["id"],
            "sender": message["sender"],
            "envelope": json.loads(message["envelope"]),
            "created_at": message["created_at"],} 
        for message in messages
    ])


@app.post("/messages/<int:message_id>/ack") #endpoint for acknowledging a message
@require_auth
def acknowledge_message(message_id):
    # Only the authenticated recipient can acknowledge the message.
    with get_connection() as connection:
        user = connection.execute("SELECT id FROM users WHERE username = ?",
            (g.username,),).fetchone() #fetches the logged-in user's ID from the database

        cursor = connection.execute("""
            UPDATE messages
            SET status = 'delivered'
            WHERE id = ?
              AND recipient_id = ?
              AND status = 'pending'
            """,(message_id, user["id"]),) #updates the status of the message to "delivered" in the database if the message ID, recipient ID, and status match

        if cursor.rowcount == 1:
            return jsonify(
                message="Message acknowledged.",
                id=message_id,
                status="delivered",
            ), 200
        return jsonify(
            error="Pending message not found for this recipient."
        ), 404


@app.post("/logout") #endpoint for logging out
@require_auth
def logout():
    header = request.headers.get("Authorization", "")
    token = header.partition(" ")[2]
    sessions.pop(token, None) #removes the session token from the sessions dictionary
    return jsonify(message="Logged out.")


if __name__ == "__main__":
    initialize_database()

    project_root = Path(__file__).resolve().parent.parent # Gets the root directory of the project

    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) #creates an SSL context for the server using TLS protocol
    tls_context.minimum_version = ssl.TLSVersion.TLSv1_2 #uses TLS version 1.2 
    tls_context.load_cert_chain(certfile=str(project_root / "certs" / "server.crt"),
        keyfile=str(project_root / "certs" / "server.key"),) #loads the server's SSL certificate and private key from the specified files

    app.run(host="0.0.0.0",port=5000,
        debug=False,ssl_context=tls_context,) #runs the Flask application on all available network interfaces at port 5000 with SSL context