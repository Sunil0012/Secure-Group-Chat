"""Secure, persistent WebSocket group chat server.

SQLite stores only AES-GCM ciphertext. Ed25519 keys are generated per account;
the private key is encrypted at rest with the application master key. Every
message is signed before storage and verified after decryption and on history
replay. The server also serves the browser client.
"""

import base64
import hashlib
import json
import os
import re
import secrets
import socket
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


HOST = "0.0.0.0"
PORT = 8000
ROOM_ID = "main-room"
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
PBKDF2_ITERATIONS = 210_000
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "chat.db"
MASTER_KEY_PATH = BASE_DIR / "chat_master.key"

clients = set()
clients_lock = threading.Lock()
db_lock = threading.RLock()


class TamperedMessage(Exception):
    """Raised when authenticated decryption or signature verification fails."""


class ChatClient:
    def __init__(self, connection, address):
        self.connection = connection
        self.address = address
        self.name = f"guest-{address[1]}"
        self.user_id = None
        self.user = None
        self.authenticated = False
        self.send_lock = threading.Lock()


def b64(data):
    return base64.urlsafe_b64encode(data).decode("ascii")


def unb64(value):
    return base64.urlsafe_b64decode(value.encode("ascii"))


def load_master_key():
    """Load CHAT_MASTER_KEY or create a local key ignored by version control."""
    configured = os.environ.get("CHAT_MASTER_KEY", "").strip()
    if configured:
        key = unb64(configured)
        if len(key) != 32:
            raise ValueError("CHAT_MASTER_KEY must decode to exactly 32 bytes")
        return key
    if MASTER_KEY_PATH.exists():
        key = MASTER_KEY_PATH.read_bytes()
        if len(key) != 32:
            raise ValueError(f"Invalid master key file: {MASTER_KEY_PATH}")
        return key
    key = secrets.token_bytes(32)
    MASTER_KEY_PATH.write_bytes(key)
    try:
        os.chmod(MASTER_KEY_PATH, 0o600)
    except OSError:
        pass
    return key


MASTER_KEY = load_master_key()


def db_connection():
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def initialise_database():
    with db_lock, db_connection() as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                public_key BLOB NOT NULL,
                private_key_nonce BLOB NOT NULL,
                private_key_ciphertext BLOB NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                room_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                sender TEXT NOT NULL,
                ciphertext BLOB NOT NULL,
                nonce BLOB NOT NULL,
                signature BLOB NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY(sender_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                detected_at TEXT NOT NULL
            );
            """
        )


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def password_hash(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )


def validate_username(username):
    username = str(username or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
        raise ValueError("Username must be 3-32 letters, digits, _, ., or -")
    return username


def load_private_key(row, username):
    try:
        raw = AESGCM(MASTER_KEY).decrypt(
            bytes(row["private_key_nonce"]),
            bytes(row["private_key_ciphertext"]),
            username.encode("utf-8"),
        )
        return Ed25519PrivateKey.from_private_bytes(raw)
    except (InvalidTag, ValueError) as error:
        raise ValueError("Stored signing key could not be unlocked") from error


def register_or_login(mode, username, password):
    username = validate_username(username)
    if not isinstance(password, str) or len(password) < 6 or len(password) > 128:
        raise ValueError("Password must contain 6-128 characters")

    with db_lock, db_connection() as connection:
        row = connection.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if mode == "register":
            if row:
                raise ValueError("Username already exists; choose Login")
            user_id = uuid.uuid4().hex
            salt = os.urandom(16)
            private_key = Ed25519PrivateKey.generate()
            public_key = private_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            private_raw = private_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            key_nonce = os.urandom(12)
            private_ciphertext = AESGCM(MASTER_KEY).encrypt(
                key_nonce, private_raw, username.encode("utf-8")
            )
            connection.execute(
                """
                INSERT INTO users
                (id, username, password_salt, password_hash, public_key,
                 private_key_nonce, private_key_ciphertext, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (user_id, username, salt, password_hash(password, salt), public_key,
                 key_nonce, private_ciphertext, utc_now()),
            )
            row = connection.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        elif mode == "login":
            if not row:
                raise ValueError("Unknown username or password")
            expected = bytes(row["password_hash"])
            actual = password_hash(password, bytes(row["password_salt"]))
            if not secrets.compare_digest(expected, actual):
                raise ValueError("Unknown username or password")
        else:
            raise ValueError("Authentication mode must be register or login")

        private_key = load_private_key(row, row["username"])
        public_key = bytes(row["public_key"])
        return {
            "id": row["id"],
            "username": row["username"],
            "private_key": private_key,
            "public_key": public_key,
            "fingerprint": hashlib.sha256(public_key).hexdigest()[:16],
        }


def signing_payload(message_id, room_id, sender_id, sender, timestamp, text):
    return json.dumps(
        {"id": message_id, "room_id": room_id, "sender_id": sender_id,
         "sender": sender, "timestamp": timestamp, "text": text},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def encryption_aad(message_id, room_id, sender_id, sender, timestamp):
    return signing_payload(message_id, room_id, sender_id, sender, timestamp, "")


def save_signed_message(user, text):
    message_id = uuid.uuid4().hex
    timestamp = utc_now()
    sender = user["username"]
    aad = encryption_aad(message_id, ROOM_ID, user["id"], sender, timestamp)
    nonce = os.urandom(12)
    ciphertext = AESGCM(MASTER_KEY).encrypt(nonce, text.encode("utf-8"), aad)
    signature = user["private_key"].sign(
        signing_payload(message_id, ROOM_ID, user["id"], sender, timestamp, text)
    )
    with db_lock, db_connection() as connection:
        connection.execute(
            """
            INSERT INTO messages
            (id, room_id, sender_id, sender, ciphertext, nonce, signature, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (message_id, ROOM_ID, user["id"], sender, ciphertext, nonce, signature, timestamp),
        )
    return {
        "type": "message", "id": message_id, "name": sender, "text": text,
        "time": timestamp, "signature": b64(signature),
        "key_fingerprint": user["fingerprint"], "verified": True, "persisted": True,
    }


def decode_and_verify(row):
    message_id = row["id"]
    aad = encryption_aad(message_id, row["room_id"], row["sender_id"],
                         row["sender"], row["timestamp"])
    try:
        plaintext = AESGCM(MASTER_KEY).decrypt(
            bytes(row["nonce"]), bytes(row["ciphertext"]), aad
        ).decode("utf-8")
    except (InvalidTag, UnicodeDecodeError) as error:
        raise TamperedMessage("AES-GCM authentication failed") from error

    with db_lock, db_connection() as connection:
        user = connection.execute(
            "SELECT public_key FROM users WHERE id = ?", (row["sender_id"],)
        ).fetchone()
    if not user:
        raise TamperedMessage("Sender public key is missing")
    try:
        Ed25519PublicKey.from_public_bytes(bytes(user["public_key"])).verify(
            bytes(row["signature"]),
            signing_payload(message_id, row["room_id"], row["sender_id"],
                            row["sender"], row["timestamp"], plaintext),
        )
    except (InvalidSignature, ValueError) as error:
        raise TamperedMessage("Ed25519 signature verification failed") from error

    public_key = bytes(user["public_key"])
    return {
        "type": "message", "id": message_id, "name": row["sender"],
        "text": plaintext, "time": row["timestamp"],
        "signature": b64(bytes(row["signature"])),
        "key_fingerprint": hashlib.sha256(public_key).hexdigest()[:16],
        "verified": True, "persisted": True,
    }


def record_security_event(message_id, reason):
    with db_lock, db_connection() as connection:
        connection.execute(
            "INSERT INTO security_events(message_id, reason, detected_at) VALUES (?, ?, ?)",
            (message_id, reason, utc_now()),
        )


def history_events():
    with db_lock, db_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM messages WHERE room_id = ? ORDER BY timestamp, id",
            (ROOM_ID,),
        ).fetchall()
    events = []
    for row in rows:
        try:
            events.append(decode_and_verify(row))
        except TamperedMessage as error:
            reason = str(error)
            record_security_event(row["id"], reason)
            events.append({
                "type": "security", "message_id": row["id"],
                "text": f"Message {row['id'][:10]} rejected: {reason}",
                "verified": False,
            })
    return events


def read_http_request(connection):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = connection.recv(1024)
        if not chunk:
            return "", {}, b""
        data += chunk
        if len(data) > 64 * 1024:
            raise ValueError("HTTP headers too large")
    header_data, remaining = data.split(b"\r\n\r\n", 1)
    lines = header_data.decode("utf-8", errors="replace").split("\r\n")
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return lines[0], headers, remaining


def send_http_response(connection, status, content_type, body):
    if isinstance(body, str):
        body = body.encode("utf-8")
    response = (
        f"HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode("utf-8") + body
    connection.sendall(response)


def websocket_accept_value(key):
    raw = (key + WEBSOCKET_GUID).encode("utf-8")
    return base64.b64encode(hashlib.sha1(raw).digest()).decode("utf-8")


def upgrade_to_websocket(connection, headers):
    key = headers.get("sec-websocket-key")
    if not key:
        send_http_response(connection, "400 Bad Request", "text/plain", "Missing WebSocket key")
        return False
    response = (
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {websocket_accept_value(key)}\r\n\r\n"
    )
    connection.sendall(response.encode("utf-8"))
    return True


def receive_exact(connection, size):
    data = b""
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Client disconnected")
        data += chunk
    return data


def read_websocket_frame(connection):
    first_byte, second_byte = receive_exact(connection, 2)
    opcode = first_byte & 0x0F
    masked = bool(second_byte & 0x80)
    payload_length = second_byte & 0x7F
    if payload_length == 126:
        payload_length = int.from_bytes(receive_exact(connection, 2), "big")
    elif payload_length == 127:
        payload_length = int.from_bytes(receive_exact(connection, 8), "big")
    if payload_length > 2 * 1024 * 1024:
        raise ValueError("WebSocket frame too large")
    mask = receive_exact(connection, 4) if masked else b""
    payload = receive_exact(connection, payload_length) if payload_length else b""
    if masked:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return opcode, payload


def send_websocket_frame(connection, opcode, payload=b""):
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    header = bytearray([0x80 | opcode])
    length = len(payload)
    if length < 126:
        header.append(length)
    elif length < 65536:
        header.append(126)
        header.extend(length.to_bytes(2, "big"))
    else:
        header.append(127)
        header.extend(length.to_bytes(8, "big"))
    connection.sendall(bytes(header) + payload)


def send_json(client, message):
    with client.send_lock:
        send_websocket_frame(client.connection, 0x1, json.dumps(message, ensure_ascii=False))


def broadcast(message):
    with clients_lock:
        current_clients = list(clients)
        online_count = len(current_clients)
    outgoing = dict(message)
    outgoing.setdefault("online", online_count)
    dead_clients = []
    for client in current_clients:
        try:
            send_json(client, outgoing)
        except OSError:
            dead_clients.append(client)
    if dead_clients:
        with clients_lock:
            for client in dead_clients:
                clients.discard(client)


def send_history(client):
    events = history_events()
    for event in events:
        send_json(client, event)
    send_json(client, {"type": "history_complete", "count": len(events)})


def handle_chat_client(connection, address):
    client = ChatClient(connection, address)
    try:
        send_json(client, {"type": "hello", "text": "Secure chat connection established."})
        while True:
            opcode, payload = read_websocket_frame(connection)
            if opcode == 0x8:
                break
            if opcode == 0x9:
                with client.send_lock:
                    send_websocket_frame(client.connection, 0xA, payload)
                continue
            if opcode != 0x1:
                continue

            data = json.loads(payload.decode("utf-8"))
            if not isinstance(data, dict):
                continue

            if not client.authenticated:
                if data.get("type") != "auth":
                    send_json(client, {"type": "auth_result", "ok": False, "error": "Login required"})
                    continue
                try:
                    user = register_or_login(
                        data.get("mode"), data.get("username"), data.get("password")
                    )
                    client.user_id = user["id"]
                    client.name = user["username"]
                    client.user = user
                    client.authenticated = True
                    send_json(client, {
                        "type": "auth_result", "ok": True, "username": client.name,
                        "key_fingerprint": user["fingerprint"],
                    })
                    send_history(client)
                    with clients_lock:
                        clients.add(client)
                        online_count = len(clients)
                    broadcast({
                        "type": "system", "text": f"{client.name} joined the secure room.",
                        "time": utc_now(), "online": online_count,
                    })
                except (ValueError, sqlite3.Error) as error:
                    send_json(client, {"type": "auth_result", "ok": False, "error": str(error)})
                continue

            if data.get("type") == "message":
                text = str(data.get("text", "")).strip()[:1000]
                if text:
                    broadcast(save_signed_message(client.user, text))

    except (ConnectionError, OSError, ValueError, json.JSONDecodeError):
        pass
    finally:
        with clients_lock:
            was_present = client in clients
            clients.discard(client)
            online_count = len(clients)
        try:
            connection.close()
        except OSError:
            pass
        if was_present:
            broadcast({
                "type": "system", "text": f"{client.name} left the secure room.",
                "time": utc_now(), "online": online_count,
            })


def handle_connection(connection, address):
    try:
        request_line, headers, _ = read_http_request(connection)
        if not request_line:
            connection.close()
            return
        method, raw_path, _ = request_line.split(" ", 2)
        path = urlsplit(raw_path).path
        wants_websocket = headers.get("upgrade", "").lower() == "websocket"
        if method == "GET" and path == "/chat" and wants_websocket:
            if upgrade_to_websocket(connection, headers):
                handle_chat_client(connection, address)
        elif method == "GET" and path in ("/", "/index.html"):
            send_http_response(
                connection, "200 OK", "text/html; charset=utf-8",
                (BASE_DIR / "index.html").read_text(encoding="utf-8"),
            )
            connection.close()
        elif method == "GET" and path == "/health":
            send_http_response(connection, "200 OK", "application/json", json.dumps({"ok": True}))
            connection.close()
        else:
            send_http_response(connection, "404 Not Found", "text/plain", "Not found")
            connection.close()
    except Exception as error:
        print(f"Error handling {address}: {error}")
        try:
            connection.close()
        except OSError:
            pass


def main():
    initialise_database()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"Secure chat server running on port {PORT}")
        print(f"Client URL: http://localhost:{PORT}")
        print(f"Database: {DB_PATH}")
        while True:
            connection, address = server_socket.accept()
            threading.Thread(
                target=handle_connection, args=(connection, address), daemon=True
            ).start()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nServer stopped.")
