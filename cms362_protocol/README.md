# NXP — Network eXchange Protocol

**Course:** CMS 362 – Operating Systems, Khazar University, Spring 2026
**Grading:** Functionality 15 pts · Code Quality 10 pts · Documentation 5 pts

NXP is a TCP-based multi-client chat protocol implemented entirely in Python's standard library. It provides challenge-response authentication so only clients who know the room password can join, and end-to-end encryption using HMAC-SHA256-CTR so the server forwards ciphertext it cannot read. Every socket call, thread decision, and file-descriptor operation is annotated with the OS concept it demonstrates.

---

## File Structure

```
cms362_protocol/
├── protocol.py   # Wire protocol — NXPMessage, build_message(), parse_message(), recv_message()
├── crypto.py     # Security layer — derive_key(), encrypt(), decrypt(), make_auth_token()
├── server.py     # Server process — NXPServer, ThreadPoolExecutor, challenge-response auth, broadcast
├── client.py     # Client process — auth handshake, receiver thread, /join /send /leave /help
├── logger.py     # Logging utility — console + rotating file handler (server.log)
└── README.md     # This file
```

---

## How to Run

### Start the server

The three password modes are mutually exclusive:

```bash
# Open room — no password, anyone can join
python server.py --no-password

# Fixed password — you choose it
python server.py --room-password mysecret

# Random password — server generates and prints a 16-character alphanumeric password
python server.py --random-password
```

Optional flags:

```bash
python server.py --host 0.0.0.0 --port 9090   # defaults shown
```

When the server starts it prints a banner with the room password (if any) and the listening address:

```
╔════════════════════════════════════════════════════╗
║                  NXP Chat Server                   ║
╠════════════════════════════════════════════════════╣
║  Listening : 0.0.0.0:9090                          ║
║  Auth      : challenge-response (HMAC-SHA256)      ║
║  Encryption: E2E — server cannot read messages     ║
╠════════════════════════════════════════════════════╣
║  Room password : xK7mP2nQr9sT4vWy                  ║
║  Share out-of-band. NEVER share over chat.         ║
║  Wrong password → connection rejected.             ║
╠════════════════════════════════════════════════════╣
║  Executor  : ThreadPoolExecutor (I/O + auth)       ║
║  Press Ctrl+C to stop                              ║
╚════════════════════════════════════════════════════╝
```

Stop the server at any time with **Ctrl+C**.

---

### Connect a client

```bash
# Interactive prompts for address and password
python client.py

# All flags up front — skips all prompts
python client.py --host 127.0.0.1 --port 9090 --password mysecret

# Connect to a public server by hostname
python client.py --host chat.example.com --port 9090

# Join an open room without encryption
python client.py --no-encrypt
```

After connecting, the client shows whether the room requires authentication. On a password-protected server it prompts for the password (if `--password` was not given), derives the encryption key, and confirms that E2E is ready before showing the command prompt.

---

### In-client commands

| Command | Example | Description |
|---------|---------|-------------|
| `/join <name>` | `/join alice` | Authenticate with the room password and register the username |
| `/send <text>` | `/send Hello!` | Encrypt and broadcast a message to all connected clients |
| `/leave` | `/leave` | Send a LEAVE frame and disconnect cleanly |
| `/help` | `/help` | Print the command list locally |

After `/join`, typing bare text (without a slash) is a shortcut for `/send`.

---

### Full demo walkthrough

**Step 1 — Start the server with a random password (Terminal 1)**

```bash
$ python server.py --random-password
```

```
╔════════════════════════════════════════════════════╗
║                  NXP Chat Server                   ║
...
║  Room password : aB3cD4eF5gH6iJkL                  ║
...
```

**Step 2 — Connect Alice (Terminal 2)**

```bash
$ python client.py
NXP Chat Client
────────────────────────────────────────
  Server address [default: 127.0.0.1:9090]:
  This room requires a password.
  Room password: aB3cD4eF5gH6iJkL
  Deriving encryption key… done.
  E2E encryption ready. Server cannot read your messages.
Type /help for commands.

> /join alice
  [server] Welcome, alice!
alice>
```

**Step 3 — Connect Bob (Terminal 3)**

```bash
$ python client.py --password aB3cD4eF5gH6iJkL
  ...
  E2E encryption ready. Server cannot read your messages.
Type /help for commands.

> /join bob
  [server] Welcome, bob!
bob>
```

Alice's terminal now shows:
```
  [bob] has joined the chat.
```

**Step 4 — Send messages**

In Alice's terminal:
```
alice> Hello Bob!
  [server] Message delivered
```

In Bob's terminal:
```
  [alice][enc] Hello Bob!
```

The `[enc]` label confirms the message was decrypted from an `ENC:` token.

**Step 5 — Alice leaves**

```
alice> /leave

Disconnected.
```

Bob's terminal shows:
```
  alice has left the chat.
```

---

## Protocol Specification

### Message format

Every NXP message on the wire is two lines separated by `\r\n`:

```
COMMAND LENGTH\r\n
PAYLOAD\r\n
```

- `COMMAND` — one of five reserved ASCII words (uppercase)
- `LENGTH` — decimal count of the UTF-8 bytes in PAYLOAD
- `PAYLOAD` — UTF-8 text; may be empty (LENGTH = 0, but the trailing `\r\n` is still required)

### Commands

| Command | Direction | Payload | Description |
|---------|-----------|---------|-------------|
| `JOIN` | Client → Server | `username` or `username\|token` | Authenticate and register. In password-protected rooms the payload is `username\|<64-char-hex-HMAC-token>`. |
| `SEND` | Client → Server | plaintext or `ENC:<base64>` | Broadcast a message. Encrypted clients send an `ENC:` token; the server forwards it to all other clients unchanged. |
| `ACK` | Server → Client | status text | Confirms success. Used for: welcome message, message-delivered notice, and the auth handshake signals `CHALLENGE:<hex>` and `OPEN`. |
| `ERROR` | Server → Client | error description | Reports failure. The server closes the connection after sending ERROR during auth. |
| `LEAVE` | Client → Server | *(empty, LENGTH=0)* | Graceful disconnect. Server broadcasts departure and closes the socket. |

### Authentication handshake

```
Client                              Server
  |                                    |
  |<-------- ACK CHALLENGE:<hex> ------|  (16 random bytes, hex-encoded)
  |                                    |
  |---- JOIN alice|<64-hex-token> ---->|  (HMAC-SHA256(password, challenge))
  |                                    |
  |<------------ ACK Welcome, alice! --|  (success)
  |                                    |
  |============ chat begins ============|
```

For open rooms (`--no-password`) the server sends `ACK OPEN` instead of a challenge, and the client sends `JOIN alice` with no token.

### Wire examples

**JOIN on a password-protected server:**
```
JOIN 133\r\nalice|a3f8c1d2e4b5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1\r\n
```

**SEND with end-to-end encryption:**
```
SEND 108\r\nENC:abc123...base64encodedciphertext==\r\n
```

**LEAVE (empty payload):**
```
LEAVE 0\r\n\r\n
```

---

## Security Design

### 1. Key derivation — PBKDF2-HMAC-SHA256

`derive_key(password)` calls `hashlib.pbkdf2_hmac("sha256", password, _APP_SALT, 260_000, dklen=32)`. The 260,000-iteration count follows the OWASP 2023 recommendation and means an attacker who captures ciphertext must spend roughly 43 ms per password guess on modern hardware, making brute-force of even short passwords extremely expensive. The fixed application salt `b"NXP-CMS362-KhazarUniversity-v1"` ensures all participants derive the identical 32-byte key from the same password without a salt-exchange protocol.

### 2. Message encryption — HMAC-SHA256-CTR

`encrypt(key, plaintext)` generates a 128-bit random nonce via `os.urandom()`, builds a keystream using `HMAC-SHA256(key, nonce ‖ counter)` in counter mode (a proven PRF construction), XORs the keystream with the UTF-8 plaintext bytes, then appends a 128-bit authentication tag computed as `HMAC-SHA256(key, nonce ‖ ciphertext)[:16]`. The result is packed as `nonce[16] | tag[16] | ciphertext`, base64-encoded, and prefixed with `ENC:`. `decrypt()` first verifies the tag with `hmac.compare_digest()` (constant-time) before attempting decryption, so a tampered or wrongly-keyed message returns `None` without leaking timing information.

### 3. Authentication — HMAC-SHA256 challenge-response

When the server has a room password it generates 16 random bytes via `os.urandom()` and sends them as a hex-encoded challenge in the first ACK. The client computes `HMAC-SHA256(password.encode(), challenge)` and appends the 64-character hex digest to the JOIN payload separated by `|`. The server recomputes the expected token and compares with `hmac.compare_digest()`. The password never appears on the wire; each session's challenge is unique so captured tokens cannot be replayed; a wrong token results in an immediate ERROR and connection close with no retry allowed.

### 4. Server blindness

The server stores the room password only in RAM and uses it solely to verify HMAC auth tokens. Message encryption keys are derived via `PBKDF2(password)`, a computation the server never performs. The server sees only `ENC:<base64>` blobs in SEND payloads and forwards them without modification. An operator with full access to the server process cannot decrypt message history because the 32-byte message keys exist only inside connected client processes.

---

## OS Concepts Explained

### 6.1 TCP Sockets and the OS Kernel

A socket is a kernel data structure — not a file on disk — that represents one end of a network connection. When `socket.socket(AF_INET, SOCK_STREAM)` is called, it issues the `socket(2)` system call, which transitions from user space into kernel space via a software interrupt. The kernel allocates an internal socket object containing a TCP state machine, a send buffer, a receive buffer, and connection metadata, then returns an integer **file descriptor** that user code uses as a handle.

### 6.2 bind(), listen(), accept()

`bind(fd, (host, port))` registers the chosen IP address and port number in the kernel's socket-to-port mapping so that incoming TCP segments addressed to that port are delivered to this socket. `listen(fd, backlog)` transitions the socket to `LISTEN` state and allocates an **accept queue** in kernel memory; completed TCP three-way handshakes are placed there with a queue depth limited by `BACKLOG = 10`. `accept(fd)` dequeues the next completed handshake and returns a **new socket FD** representing that individual connection — the original listening socket stays in `LISTEN` state and continues accepting additional clients. Each call crosses the user/kernel boundary via the `syscall` instruction on x86-64.

### 6.3 Threads and the OS Scheduler

Each connected client runs in a dedicated worker thread supplied by `ThreadPoolExecutor(max_workers=200)`, which maps directly to an OS thread (`pthread_create` on Linux). The OS scheduler assigns threads to available CPU cores using preemptive, time-sliced scheduling. Client handler threads are **I/O-bound**: they spend almost all their time blocked inside `sock.recv(1)`, a blocking system call that puts the thread in a kernel `WAIT` state and yields its CPU timeslice to other runnable threads. A blocked thread consumes zero CPU cycles. When bytes arrive in the socket's receive buffer, the kernel wakes the thread and the scheduler makes it runnable again.

### 6.4 File Descriptors

A **file descriptor** is a small non-negative integer that indexes into the kernel's **per-process open-file table**. Every process inherits three at startup: 0 (stdin), 1 (stdout), 2 (stderr). Each call to `socket()` or `open()` appends a new entry and returns its index (3, 4, 5, …). Because sockets reuse the same FD abstraction as regular files, the same `read(2)`, `write(2)`, and `close(2)` system calls work on both. Calling `sock.close()` in Python issues `close(fd)`, decrements the kernel's reference count on the socket object, and when the count reaches zero sends a TCP FIN segment to the remote peer and frees all associated kernel memory.

### 6.5 Kernel Send/Receive Buffers

The OS maintains two **ring buffers in kernel memory** for every TCP socket — one for sending, one for receiving. When `sock.sendall(data)` is called, the kernel copies bytes from user-space into the **send buffer** and returns immediately; the TCP stack independently segments, transmits, retransmits if necessary, and drains the buffer as the network allows. On the receiving side, the kernel's network interrupt handler copies incoming TCP segment payloads into the **receive buffer**; `sock.recv(n)` then copies up to `n` bytes from that buffer into user space. `recv_message()` reads the header one byte at a time and the payload with an exact count precisely to avoid consuming bytes from a subsequent message that the kernel may have delivered in the same TCP segment due to **Nagle's algorithm** (which coalesces small writes). **TCP flow control** (the sliding-window mechanism) ensures the sender never fills the receiver's buffer: if the remote buffer is full, `sendall()` blocks until space is available.

---

## Requirements

- Python 3.8 or later
- No external libraries — standard library only (`socket`, `threading`, `concurrent.futures`, `hashlib`, `hmac`, `os`, `secrets`, `logging`, `base64`)
- Tested on Linux (Kali) and compatible with macOS
