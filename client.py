"""Optional terminal client for the secure WebSocket chat."""

import base64
import hashlib
import json
import getpass
import os
import secrets
import socket
import struct
import sys
import threading


PORT = 8000
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def receive_exact(connection, size):
    data = b""
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Server disconnected")
        data += chunk
    return data


def read_http_headers(connection):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = connection.recv(1024)
        if not chunk:
            raise ConnectionError("Server closed during handshake")
        data += chunk
    lines = data.split(b"\r\n\r\n", 1)[0].decode("utf-8", errors="replace").split("\r\n")
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return lines[0], headers


def connect_to_server(server_host):
    connection = socket.create_connection((server_host, PORT), timeout=10)
    connection.settimeout(None)
    websocket_key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        f"GET /chat HTTP/1.1\r\nHost: {server_host}:{PORT}\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {websocket_key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    connection.sendall(request.encode("ascii"))
    status, headers = read_http_headers(connection)
    expected = base64.b64encode(hashlib.sha1((websocket_key + WEBSOCKET_GUID).encode()).digest()).decode()
    if not status.startswith("HTTP/1.1 101") or headers.get("sec-websocket-accept") != expected:
        connection.close()
        raise ConnectionError("WebSocket handshake failed")
    return connection


def send_frame(connection, opcode, payload=b""):
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    mask = secrets.token_bytes(4)
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    length = len(masked)
    if length < 126:
        header = struct.pack("!BB", 0x80 | opcode, 0x80 | length)
    elif length < 65536:
        header = struct.pack("!BBH", 0x80 | opcode, 0x80 | 126, length)
    else:
        header = struct.pack("!BBQ", 0x80 | opcode, 0x80 | 127, length)
    connection.sendall(header + mask + masked)


def read_frame(connection):
    first, second = receive_exact(connection, 2)
    opcode, length = first & 0x0F, second & 0x7F
    if length == 126:
        length = struct.unpack("!H", receive_exact(connection, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", receive_exact(connection, 8))[0]
    mask = receive_exact(connection, 4) if second & 0x80 else b""
    payload = receive_exact(connection, length) if length else b""
    if mask:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return opcode, payload


def send_json(connection, message):
    send_frame(connection, 0x1, json.dumps(message))


def receive_messages(connection, stop_event):
    try:
        while not stop_event.is_set():
            opcode, payload = read_frame(connection)
            if opcode == 0x8:
                break
            if opcode == 0x9:
                send_frame(connection, 0xA, payload)
                continue
            if opcode != 0x1:
                continue
            message = json.loads(payload.decode("utf-8"))
            if message.get("type") == "message":
                state = "verified" if message.get("verified") else "UNVERIFIED"
                prefix = "[history] " if message.get("persisted") else ""
                print(f"\n[{message['time']}] {prefix}{message['name']}: {message['text']} ({state})")
            elif message.get("type") == "security":
                print(f"\n[SECURITY ALERT] {message['text']}")
            elif message.get("type") == "system":
                print(f"\n[{message.get('time', '--')}] {message.get('text', '')}")
            elif message.get("type") == "history_complete":
                print(f"\nLoaded {message['count']} verified historical messages.")
            print("> ", end="", flush=True)
    except (ConnectionError, OSError, json.JSONDecodeError):
        if not stop_event.is_set():
            print("\nConnection to server was lost.")
    finally:
        stop_event.set()


def main():
    server_host = sys.argv[1] if len(sys.argv) > 1 else input("Server IP address: ").strip()
    if not server_host:
        print("A server IP address is required.")
        return 1
    mode = "register" if input("Create a new account? [y/N]: ").strip().lower() == "y" else "login"
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    try:
        connection = connect_to_server(server_host)
    except (OSError, ConnectionError) as error:
        print(f"Could not connect to {server_host}:{PORT}: {error}")
        return 1

    stop_event = threading.Event()
    send_json(connection, {"type": "auth", "mode": mode, "username": username, "password": password})
    threading.Thread(target=receive_messages, args=(connection, stop_event), daemon=True).start()
    print("Connected. Type messages and press Enter. Type /quit to exit.")
    try:
        while not stop_event.is_set():
            text = input("> ").strip()
            if text == "/quit":
                break
            if text:
                send_json(connection, {"type": "message", "text": text})
    except (EOFError, KeyboardInterrupt, OSError):
        pass
    finally:
        stop_event.set()
        try:
            send_frame(connection, 0x8)
            connection.close()
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
