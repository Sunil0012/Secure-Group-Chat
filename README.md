# Secure Persistent Group Chat — Lab 4

This project extends the earlier WebSocket group chat with authentication,
SQLite persistence, AES-GCM encryption, tamper detection, and Ed25519 digital
signatures.

## Mandatory requirements

| Requirement | Implementation |
|---|---|
| Database storage | SQLite `chat.db`, with a `messages` table |
| Previous history | Verified history is sent immediately after login |
| No plaintext storage | Message text is encrypted using AES-256-GCM before `INSERT` |
| Modification detection | AES-GCM authentication tag detects ciphertext/AAD changes; a security event is shown |
| Signing key pair | Ed25519 pair generated for every registered user |
| Signature verification | Signature is checked after decryption, before display/broadcast |

Passwords are protected using PBKDF2-HMAC-SHA256. A user's private signing key
is encrypted at rest. The local `chat_master.key` is generated on first run and
ignored by git; production deployment should provide `CHAT_MASTER_KEY` as a
base64-encoded 32-byte secret.

## Run

Install the one dependency and start the server:

```text
python -m pip install -r requirements.txt
python server.py
```

Open `http://SERVER_IP:8000` on each laboratory machine. Create an account on
the first visit; use Login on later visits to receive the stored history.
The current server-machine URL for TA testing is:

```text
http://10.50.20.162:8000
```

If the network changes, run `ipconfig` on the server machine and replace the
address with its active IPv4 address. Allow inbound TCP port 8000 through the
server machine's firewall.

## Tamper-detection demonstration

1. Send a message and confirm it appears with the `signature verified` badge.
2. Stop the server and back up `chat.db`.
3. Open SQLite and modify one byte in a row's `ciphertext` or `signature`.
4. Restart the server and log in again.
5. The history loader rejects the record and displays a red security alert;
   the altered plaintext is never displayed.

The report includes the database schema, message flow, screenshots, test
results, complete source listings, and the four-member contribution report.
