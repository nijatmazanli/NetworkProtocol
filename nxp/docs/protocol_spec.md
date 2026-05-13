# NXP Protocol Specification
## Network eXchange Protocol — Technical Reference

**Version:** 1.0
**Implementation:** `protocol.py`, `crypto.py`, `server.py`, `client.py`
**Transport:** TCP over IPv4

---

## 1. Protocol Overview

### Goals

NXP is an application-layer chat protocol with three design objectives:

1. **Message framing** — TCP is a byte stream with no notion of where one message ends and the next begins. NXP solves this with an explicit `LENGTH` field in every message header, so both sides always agree on message boundaries.
2. **Access control** — Only clients who know the room password may join. The password is never sent over the wire; a challenge-response scheme proves knowledge of it.
3. **End-to-end confidentiality** — Message content is encrypted on the client before transmission. The server forwards ciphertext it cannot decrypt.

### Design decisions

**Why TCP?** TCP guarantees in-order, lossless delivery, which simplifies the protocol: NXP does not need sequence numbers, retransmission logic, or duplicate detection. The OS kernel handles all of that transparently.

**Why a custom protocol instead of HTTP/WebSocket?** The project requirement is to demonstrate OS-level socket programming. Using raw TCP with a hand-written framing layer exposes `socket()`, `bind()`, `listen()`, `accept()`, and `recv()` directly, making each kernel interaction visible and annotatable.

**Why standard library only?** To demonstrate that cryptographically sound constructions (PBKDF2, HMAC-CTR, challenge-response) can be built from primitives that ship with every Python installation — `hashlib`, `hmac`, `os.urandom`, `secrets`.

---

## 2. Transport

### Endpoint

- Default port: **9090** (TCP)
- Default bind address: **0.0.0.0** (all interfaces)
- Both are overridable via `--port` and `--host` on server startup.

### Connection lifecycle

```
TCP connect
    │
    ▼
Server sends auth signal (CHALLENGE or OPEN)
    │
    ▼
Client sends JOIN (with or without token)
    │
    ├─ auth fails ──► Server sends ERROR ──► Server closes socket
    │
    └─ auth passes ──► Server sends ACK welcome
                            │
                            ▼
                       Chat loop (SEND / ACK alternation)
                            │
                       Client sends LEAVE
                       or TCP connection drops
                            │
                            ▼
                       Server closes socket, broadcasts departure
```

### Concurrency

The server accepts connections on the main thread and submits each to a `ThreadPoolExecutor(max_workers=200)`. Each client handler runs in its own OS thread, blocking on `recv_message()` while idle. The shared client registry (`dict[username → socket]`) is protected by a `threading.Lock`.

---

## 3. Message Format

### Byte-level structure

```
┌────────────────────────────────┐
│  COMMAND SP LENGTH CR LF       │  ← header line
├────────────────────────────────┤
│  PAYLOAD bytes (LENGTH octets) │  ← payload
├────────────────────────────────┤
│  CR LF                         │  ← trailing delimiter
└────────────────────────────────┘
```

- `COMMAND` — ASCII uppercase word; one of `JOIN`, `SEND`, `ACK`, `ERROR`, `LEAVE`
- `SP` — a single ASCII space (0x20)
- `LENGTH` — decimal ASCII integer, the byte count of `PAYLOAD` encoded as UTF-8
- `CR LF` — bytes `0x0D 0x0A` (the constant `CRLF` in `protocol.py`)
- `PAYLOAD` — UTF-8 text; may be zero bytes if LENGTH is 0

### LENGTH field semantics

LENGTH counts **bytes**, not characters. A payload containing emoji or non-ASCII characters will have a LENGTH larger than its character count. The sender calls `payload.encode("utf-8")` and uses `len(payload_bytes)` as LENGTH.

### Framing and recv_message()

`recv_message(sock)` in `protocol.py` reads the wire in two phases:

**Phase 1 — header:** reads one byte at a time from `sock.recv(1)` and accumulates bytes until the buffer ends with `\r\n`. This is deliberately byte-by-byte so that if the OS delivers two messages in a single TCP segment (which Nagle's algorithm can cause), the function stops exactly at the first `\r\n` and does not consume bytes from the next message.

**Phase 2 — payload:** calls `sock.recv(payload_len - len(accumulated))` in a loop until exactly `LENGTH` bytes are read. Then reads a final 2-byte trailing `\r\n` and discards it.

Any deviation — unknown command, non-integer length, negative length, mismatched byte count — raises `NXPProtocolError`.

---

## 4. Command Reference

### JOIN

| Field | Value |
|-------|-------|
| Direction | Client → Server |
| Payload (open room) | `username` |
| Payload (password room) | `username\|<64-char-hex-HMAC-token>` |

**Success path:** Server verifies the token (or accepts unconditionally for open rooms), calls `_register_user()`, adds the username to the shared `_clients` dict under `_lock`, sends `ACK Welcome, <username>!`, then broadcasts `<username> has joined the chat.` to all other connected clients.

**Error path:**
- Missing `|` separator in a password-protected room → `ERROR Auth required — client missing room password`
- HMAC token mismatch → `ERROR Authentication failed — wrong password` → connection closed
- Empty username → `ERROR Username cannot be empty`
- Duplicate username → `ERROR Username '<name>' already taken`

**Wire example (open room):**
```
JOIN 5\r\nalice\r\n
```

**Wire example (password room, 64-hex token):**
```
JOIN 133\r\nalice|a3f8c1d2e4b5...64hexchars\r\n
```

---

### SEND

| Field | Value |
|-------|-------|
| Direction | Client → Server |
| Payload | Plaintext string, or `ENC:<base64>` token if encrypted |

**Success path:** Server prepends `[sender] ` to the payload, sends `ACK Message delivered` to the sender, then broadcasts the prefixed message as a SEND frame to every other registered client.

**Error path:**
- Client has not completed JOIN → `ERROR Must JOIN before SEND`
- Any other unexpected command instead → `ERROR Unexpected command: <cmd>`

**Wire example (plaintext, open room):**
```
SEND 12\r\nHello world!\r\n
```

**Wire example (encrypted):**
```
SEND 108\r\nENC:abc123...base64payload==\r\n
```

**Broadcast the server forwards to other clients:**
```
SEND 20\r\n[alice] Hello world!\r\n
```

---

### ACK

| Field | Value |
|-------|-------|
| Direction | Server → Client |
| Payload | Human-readable status text |

The server sends ACK in four situations:

| Payload content | When sent |
|-----------------|-----------|
| `CHALLENGE:<32-char-hex>` | Immediately after TCP connect, password room |
| `OPEN` | Immediately after TCP connect, open room |
| `Welcome, <username>!` | After successful JOIN |
| `Message delivered` | After processing a SEND |

**Wire example:**
```
ACK 2\r\nOK\r\n
ACK 42\r\nCHALLENGE:9a85f9114e8f06eb0c7bded2924de3e1\r\n
ACK 15\r\nWelcome, alice!\r\n
ACK 17\r\nMessage delivered\r\n
```

---

### ERROR

| Field | Value |
|-------|-------|
| Direction | Server → Client |
| Payload | Error description string |

The server always sends ERROR before closing a connection during the auth phase. After the chat loop begins, ERROR is sent for unexpected commands but the connection is not closed.

**Wire example:**
```
ERROR 42\r\nAuthentication failed — wrong password\r\n
```

---

### LEAVE

| Field | Value |
|-------|-------|
| Direction | Client → Server |
| Payload | *(empty — LENGTH must be 0)* |

**Success path:** Server calls `_handle_leave()`, removes the username from `_clients`, broadcasts `<username> has left the chat.` to remaining clients, then the `finally` block closes the socket.

**Wire example:**
```
LEAVE 0\r\n\r\n
```

---

## 5. Authentication Protocol

### Overview

When the server is started with `--room-password` or `--random-password`, every new TCP connection must pass challenge-response authentication before JOIN is accepted. The password never appears on the wire.

### Cryptographic details

The challenge is 16 bytes from `os.urandom()` — the OS CSPRNG (`getrandom(2)` on Linux). It is hex-encoded (32 characters) and sent as the payload of the first ACK.

The client's response token is:

```
token = HMAC-SHA256(password.encode("utf-8"), challenge_bytes).hexdigest()
```

This is `make_auth_token(password, challenge)` in `crypto.py`. The result is 64 lowercase hex characters.

The server computes the same expression using its stored `room_password` and compares with `hmac.compare_digest(expected, received)`. This comparison runs in **constant time** regardless of where the strings first differ, preventing a timing side-channel attack where an attacker incrementally determines the correct token by measuring response latency.

### Why the auth token does not reveal the message key

Auth uses `HMAC(password, challenge)`. Message encryption uses `PBKDF2(password, salt, 260_000)`. These are computationally independent: given the 64-char hex auth token and the challenge, an attacker cannot derive the 32-byte encryption key without performing 260,000 PBKDF2 iterations per password guess.

### Full handshake byte sequence

```
← ACK 42\r\nCHALLENGE:9a85f9114e8f06eb0c7bded2924de3e1\r\n

→ JOIN 133\r\nalice|a3f8c1d2e4b5f6a7b8c9d0e1f2a3b4c5
              d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3\r\n

← ACK 15\r\nWelcome, alice!\r\n
```

### Token replay protection

Each challenge is 16 bytes of fresh randomness, making the probability of reuse negligible (birthday bound at 2^64 challenges). A captured token for session N cannot be replayed in session N+1 because the server generates a new challenge for every TCP connection.

---

## 6. Encryption

### ENC token format

When a client has a room password, `_do_send()` in `client.py` calls `crypto.encrypt(key, text)` before sending. The result is a string starting with `ENC:` followed by a base64-encoded blob:

```
ENC: base64( nonce[16] | tag[16] | ciphertext[N] )
```

| Field | Size | Description |
|-------|------|-------------|
| `nonce` | 16 bytes | Random per message; `os.urandom(16)` |
| `tag` | 16 bytes | `HMAC-SHA256(key, nonce ‖ ciphertext)[:16]` |
| `ciphertext` | N bytes | `plaintext XOR keystream` |

The keystream is generated by `_keystream(key, nonce, length)`:

```python
block_i = HMAC-SHA256(key, nonce + i.to_bytes(8, "big")).digest()
# concatenate blocks, truncate to length
```

This is HMAC-SHA256 in CTR (counter) mode. Because HMAC with a secret key is a PRF (Pseudo-Random Function), its output is computationally indistinguishable from a random byte string, satisfying the security requirement of a stream cipher.

### Decryption and failure handling

`crypto.decrypt(key, token)` performs these steps in order:

1. Checks that the string starts with `ENC:` — returns `None` if not.
2. Attempts `base64.b64decode` — returns `None` on failure.
3. Checks total length ≥ 32 bytes (nonce + tag minimum) — returns `None` if shorter.
4. Recomputes the expected tag and compares with `hmac.compare_digest()` — returns `None` on mismatch.
5. Only if the tag matches: generates the keystream and XORs with ciphertext.

Step 4 happens **before** any decryption attempt. This is the Encrypt-then-MAC construction: authentication is verified before the ciphertext is touched, preventing chosen-ciphertext attacks.

### Client display states

The receiver thread in `client.py` calls `_format_chat(text, key)`, which displays one of four states:

| Condition | Display |
|-----------|---------|
| Body starts with `ENC:`, key is set, tag verifies | `[username][enc] plaintext message` |
| Body starts with `ENC:`, no key | `[username] [encrypted — join with the room password]` |
| Body starts with `ENC:`, key set but tag fails | `[username] [wrong password — cannot decrypt]` |
| Body does not start with `ENC:`, key is set | `[username] [unencrypted] body` |
| Body does not start with `ENC:`, no key | `[username] body` |

---

## 7. Edge Cases

### Unknown command received

If the client sends a command other than `SEND` or `LEAVE` during the chat loop (e.g., `JOIN` again, or a raw string), the server sends:

```
ERROR <N>\r\nUnexpected command: <CMD>\r\n
```

The connection is **not** closed. The chat loop continues.

### Client disconnects without LEAVE

If `recv_message()` raises `ConnectionError` (empty read from a closed socket) or `NXPProtocolError` (corrupt data), the `except` block in `_handle_client` breaks out of the chat loop. The `finally` block checks whether `username` is still set; if so, it calls `_remove_client(username)` and broadcasts `<username> has left the chat.` exactly as it would for a clean LEAVE. The socket is then closed on the server side.

### Duplicate username

After successful auth, `_register_user()` acquires `_lock` and checks whether the requested name is already in `_clients`. If it is:

```
ERROR <N>\r\nUsername '<name>' already taken\r\n
```

The connection is closed. The client must reconnect and choose a different name; there is no rename command.

### Auth token mismatch

If the HMAC token in the JOIN payload does not match what the server computes:

```
ERROR 42\r\nAuthentication failed — wrong password\r\n
```

The handler returns immediately after sending ERROR. No retry is offered. The TCP connection is closed by the server's `finally` block. There is no rate limiting in the current implementation — each new TCP connection gets exactly one attempt.

### Missing auth token in password room

If the JOIN payload does not contain the `|` separator (e.g., a client built against an older protocol version sends `JOIN alice` to a password-protected server):

```
ERROR <N>\r\nAuth required — client missing room password\r\n
```

The connection is closed. The server logs a warning identifying the source address as a possible old or unauthenticated client.

### Empty payload on LEAVE

LEAVE must have LENGTH = 0. The wire form is:

```
LEAVE 0\r\n\r\n
```

`build_message("LEAVE", "")` produces exactly this. `recv_message()` reads the header, finds `payload_len = 0`, skips Phase 2 (no bytes to read), consumes the trailing `\r\n`, and returns `NXPMessage(command="LEAVE", payload="")`. The server then calls `_handle_leave()`.

### Empty username

If the JOIN payload is whitespace-only or empty after stripping:

```
ERROR 26\r\nUsername cannot be empty\r\n
```

The connection is closed. This is checked inside `_register_user()` after auth passes.
