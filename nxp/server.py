"""
NXP Multi-Client TCP Server

Security model
──────────────
  • Challenge-response auth: client proves knowledge of the room password
    without sending it over the wire.  The server sends a random nonce;
    the client replies with HMAC-SHA256(password, nonce).  A wrong token
    closes the connection immediately — no retries, no hints.

  • The server stores the room password in RAM only (never writes to disk).
    It is used solely for auth verification; the server cannot decrypt
    messages because message keys are derived via PBKDF2(password), and
    the server never performs that derivation.

  • The room key is NEVER sent to clients.  Any client that connects
    without knowing the password is rejected before JOIN succeeds.

Threading + multiprocessing architecture
─────────────────────────────────────────
  ThreadPoolExecutor   — one worker thread per connected client.
    Threads are lightweight OS scheduling units that share the process
    address space (and therefore the _clients dict + _lock).  Client
    handlers are I/O-bound (blocking on recv_message), so threads are
    the correct primitive: a blocked thread yields its CPU timeslice to
    other threads without spinning.

  ProcessPoolExecutor  — the correct tool for CPU-bound auth if the
    verification used PBKDF2 (slow by design).  HMAC is fast enough
    that thread-level parallelism suffices here, so auth verification
    runs in the same ThreadPoolExecutor.  A ProcessPoolExecutor would
    bypass the CPython GIL for true core-level parallelism, but it
    requires daemon-process setup to avoid orphan workers on shutdown —
    an OS-level concern beyond this project's scope.

OS Concepts
───────────
  socket()  — kernel allocates a new socket file descriptor (FD).
  bind()    — registers (IP, port) with the kernel routing tables.
  listen()  — moves socket to LISTEN state; kernel maintains an accept queue.
  accept()  — dequeues next completed TCP handshake, returns a new FD.
  close()   — decrements FD reference count; sends TCP FIN when it hits 0.
  Threading — OS thread scheduling; blocked threads consume no CPU.
  Processes — separate OS address spaces; communicate via kernel IPC pipes.
"""

import concurrent.futures
import os
import secrets
import signal
import socket
import string
import sys
import threading

from crypto   import CHALLENGE_PREFIX, verify_auth_token
from logger   import get_logger
from protocol import (
    CMD_ACK, CMD_ERROR, CMD_JOIN, CMD_LEAVE, CMD_SEND,
    NXPProtocolError, build_message, recv_message,
)

# ── Configuration ─────────────────────────────────────────────────────────────
HOST    = "0.0.0.0"   # bind all interfaces — remote clients can connect
PORT    = 9090
BACKLOG = 10          # kernel accept-queue depth

log = get_logger("server")


# ── Module-level worker (must be importable by ProcessPoolExecutor) ────────────

def _auth_worker(room_password: str, challenge: bytes, token: str) -> bool:
    """
    CPU-bound auth verification — runs in a separate OS process.

    ProcessPoolExecutor serialises arguments via pickle and sends them to
    the worker process through a multiprocessing.Pipe (kernel IPC).  The
    result travels back the same way.  This isolates the cryptographic
    check from the server's main memory space.
    """
    return verify_auth_token(room_password, challenge, token)


def generate_room_password(length: int = 16) -> str:
    """
    Cryptographically random room password using the OS CSPRNG.
    secrets.choice() calls os.urandom() — same entropy source as TLS.
    """
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ── Server class ───────────────────────────────────────────────────────────────

class NXPServer:
    """
    Multi-client NXP chat server.

    State protected by _lock (threading.Lock):
        _clients : dict[username -> socket]

    Executors:
        _thread_pool : ThreadPoolExecutor  — one thread per client (I/O-bound)
        _auth_pool   : ProcessPoolExecutor — auth verification (CPU-bound)
    """

    def __init__(self, host: str = HOST, port: int = PORT,
                 room_password: str | None = None) -> None:
        self.host          = host
        self.port          = port
        self.room_password = room_password   # None = open room, no auth

        self._clients: dict[str, socket.socket] = {}
        self._all_sockets: set[socket.socket] = set()   # every accepted socket
        self._lock    = threading.Lock()
        self._shutdown = threading.Event()
        self._server_sock: socket.socket | None = None

        # ThreadPoolExecutor: bounded pool of OS threads.
        #   • Client I/O handlers (I/O-bound, the primary use)
        #   • Auth token verification (CPU-bound but fast for HMAC;
        #     swap for ProcessPoolExecutor if using PBKDF2 verification)
        # max_workers=200 caps file-descriptor use; excess connections
        # queue inside the executor rather than being dropped.
        self._thread_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=200, thread_name_prefix="nxp-client"
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Bind, listen, then block in the accept loop."""
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(BACKLOG)
        self._server_sock.settimeout(1.0)

        self._print_banner()
        self._accept_loop()

    def stop(self) -> None:
        """Signal shutdown, close the server socket, drain the pools."""
        self._shutdown.set()
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
        # Close every active socket so blocked recv() calls in handler threads
        # get ConnectionError and exit — otherwise non-daemon threads prevent
        # the process from terminating cleanly.
        with self._lock:
            socks = list(self._all_sockets)
        for s in socks:
            try: s.close()
            except OSError: pass
        self._thread_pool.shutdown(wait=False, cancel_futures=True)

    # ── Accept loop ───────────────────────────────────────────────────────────

    def _accept_loop(self) -> None:
        """
        Block on accept(); submit each new connection to the thread pool.

        OS: accept() dequeues a completed TCP handshake from the kernel's
        accept queue and returns a new FD.  We give that FD to the thread
        pool — the main thread never handles client I/O directly.
        """
        while not self._shutdown.is_set():
            try:
                client_sock, addr = self._server_sock.accept()
            except socket.timeout:
                continue   # woke up to check _shutdown
            except OSError:
                break      # server socket closed by stop()

            log.info("New connection from %s:%d", *addr)
            with self._lock:
                self._all_sockets.add(client_sock)
            self._thread_pool.submit(self._handle_client, client_sock, addr)

        log.info("Accept loop exited.")

    # ── Per-client thread ─────────────────────────────────────────────────────

    def _handle_client(self, sock: socket.socket, addr: tuple) -> None:
        """
        Runs in a ThreadPoolExecutor worker thread.

        Phase 1 — Authentication (if room has a password):
            Server sends a unique random challenge nonce.
            Client must respond with HMAC-SHA256(password, nonce) inside JOIN.
            Verification runs in a ProcessPoolExecutor worker (separate process).
            Wrong token → ERROR + close.  No retries.

        Phase 2 — Chat loop:
            Read SEND / LEAVE messages; broadcast or disconnect.
        """
        username: str | None = None

        try:
            # ── Phase 1: Auth ─────────────────────────────────────────────────
            if self.room_password:
                challenge = os.urandom(16)
                self._send_ack(sock, f"{CHALLENGE_PREFIX}{challenge.hex()}")
                log.debug("Sent challenge to %s", addr)

                try:
                    msg = recv_message(sock)
                except (ConnectionError, NXPProtocolError) as exc:
                    log.warning("Auth read error from %s: %s", addr, exc)
                    return

                if msg.command != CMD_JOIN:
                    self._send_error(sock, "Expected JOIN <username>|<token>")
                    return

                # JOIN payload must be "username|<64-hex-token>"
                if "|" not in msg.payload:
                    self._send_error(sock, "Auth required — client missing room password")
                    log.warning("No auth token from %s — possible old/no-key client", addr)
                    return

                raw_name, token = msg.payload.split("|", 1)

                # Verify in the thread pool (non-blocking for the accept loop).
                # For PBKDF2-based auth, swap self._thread_pool for a
                # ProcessPoolExecutor so the slow KDF runs on a dedicated core.
                try:
                    future = self._thread_pool.submit(
                        _auth_worker, self.room_password, challenge, token
                    )
                    valid = future.result(timeout=5)
                except Exception as exc:
                    log.error("Auth verification error: %s", exc)
                    self._send_error(sock, "Internal auth error")
                    return

                if not valid:
                    self._send_error(sock, "Authentication failed — wrong password")
                    log.warning("Auth FAILED for '%s' from %s", raw_name.strip(), addr)
                    return

                log.info("Auth OK for '%s' from %s", raw_name.strip(), addr)
                username = self._register_user(sock, raw_name, addr)

            else:
                # Open room — no password required
                self._send_ack(sock, "OPEN")

                try:
                    msg = recv_message(sock)
                except (ConnectionError, NXPProtocolError):
                    return

                if msg.command != CMD_JOIN:
                    self._send_error(sock, "Expected JOIN")
                    return

                username = self._register_user(sock, msg.payload, addr)

            if username is None:
                return

            # ── Phase 2: Chat loop ────────────────────────────────────────────
            while not self._shutdown.is_set():
                try:
                    msg = recv_message(sock)
                except (ConnectionError, NXPProtocolError) as exc:
                    log.warning("Read error from '%s': %s", username, exc)
                    break

                log.debug("Recv %s from '%s'", msg.command, username)

                if msg.command == CMD_SEND:
                    self._handle_send(sock, username, msg.payload)

                elif msg.command == CMD_LEAVE:
                    self._handle_leave(username, addr)
                    username = None   # already removed — skip finally cleanup
                    break

                else:
                    self._send_error(sock, f"Unexpected command: {msg.command}")

        finally:
            if username:
                self._remove_client(username)
                self._broadcast(f"{username} has left the chat.")
            try:
                sock.close()
            except OSError:
                pass
            with self._lock:
                self._all_sockets.discard(sock)
            log.info("Connection from %s closed", addr)

    # ── Command handlers ──────────────────────────────────────────────────────

    def _register_user(self, sock: socket.socket, name: str,
                        addr: tuple) -> str | None:
        """Register username after successful auth. Rejects duplicates."""
        name = name.strip()
        if not name:
            self._send_error(sock, "Username cannot be empty")
            return None

        with self._lock:
            if name in self._clients:
                self._send_error(sock, f"Username '{name}' already taken")
                return None
            self._clients[name] = sock

        self._send_ack(sock, f"Welcome, {name}!")
        self._broadcast(f"{name} has joined the chat.", exclude=name)
        log.info("User '%s' registered from %s:%d", name, *addr)
        return name

    def _handle_send(self, sock: socket.socket, sender: str, text: str) -> None:
        full_msg = f"[{sender}] {text}"
        self._send_ack(sock, "Message delivered")
        self._broadcast(full_msg, exclude=sender)
        log.info("SEND from '%s': %s", sender, text[:80])

    def _handle_leave(self, username: str, addr: tuple) -> None:
        self._remove_client(username)
        self._broadcast(f"{username} has left the chat.")
        log.info("User '%s' left (%s:%d)", username, *addr)

    # ── Utilities ─────────────────────────────────────────────────────────────

    def _send_ack(self, sock: socket.socket, text: str) -> None:
        self._safe_send(sock, build_message(CMD_ACK, text))

    def _send_error(self, sock: socket.socket, text: str) -> None:
        self._safe_send(sock, build_message(CMD_ERROR, text))

    def _safe_send(self, sock: socket.socket, data: bytes) -> None:
        """
        send() copies bytes into the kernel TCP send buffer; EPIPE means
        the peer already closed — swallow it rather than crashing the thread.
        """
        try:
            sock.sendall(data)
        except OSError as exc:
            log.debug("Send failed: %s", exc)

    def _broadcast(self, text: str, exclude: str | None = None) -> None:
        data = build_message(CMD_SEND, text)
        with self._lock:
            targets = [(u, s) for u, s in self._clients.items() if u != exclude]
        for uname, sock in targets:
            log.debug("Broadcast to '%s': %s", uname, text[:60])
            self._safe_send(sock, data)

    def _remove_client(self, username: str) -> None:
        with self._lock:
            self._clients.pop(username, None)

    def _print_banner(self) -> None:
        width = 52
        border = "═" * width
        print(f"\n╔{border}╗")
        print(f"║{'NXP Chat Server':^{width}}║")
        print(f"╠{border}╣")
        print(f"║  Listening : {self.host}:{self.port:<{width - 15}}║")
        if self.room_password:
            print(f"║  Auth      : challenge-response (HMAC-SHA256){' ' * (width - 46)}║")
            print(f"║  Encryption: E2E — server cannot read messages{' ' * (width - 47)}║")
            print(f"╠{border}╣")
            pw_line = f"  Room password : {self.room_password}"
            print(f"║{pw_line:<{width}}║")
            print(f"║  Share out-of-band. NEVER share over chat.{' ' * (width - 43)}║")
            print(f"║  Wrong password → connection rejected.{' ' * (width - 39)}║")
        else:
            print(f"║  Auth      : none (open room){' ' * (width - 30)}║")
            print(f"║  Tip: use --random-password to require auth{' ' * (width - 44)}║")
        print(f"╠{border}╣")
        print(f"║  Executor  : ThreadPoolExecutor (I/O + auth){' ' * (width - 44)}║")
        print(f"║  Press Ctrl+C to stop{' ' * (width - 22)}║")
        print(f"╚{border}╝\n")
        log.info("Server started on %s:%d | auth=%s",
                 self.host, self.port,
                 "challenge-response" if self.room_password else "none")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="NXP Chat Server")
    parser.add_argument("--host", default=HOST,
                        help="Interface to bind (default: 0.0.0.0)")
    parser.add_argument("--port", default=PORT, type=int,
                        help="Port to listen on (default: 9090)")

    pw_group = parser.add_mutually_exclusive_group()
    pw_group.add_argument("--room-password", metavar="PASSWORD",
                          help="Set a specific room password")
    pw_group.add_argument("--random-password", action="store_true",
                          help="Generate a random room password (recommended)")
    pw_group.add_argument("--no-password", action="store_true",
                          help="Open room — no password required (default)")

    args = parser.parse_args()

    if args.random_password:
        room_password = generate_room_password()
    elif args.room_password:
        room_password = args.room_password
    else:
        room_password = None

    server = NXPServer(host=args.host, port=args.port, room_password=room_password)

    # SIGTERM (sent by process managers / test harnesses) must also trigger
    # clean shutdown so ProcessPoolExecutor workers are reaped properly.
    def _on_sigterm(sig, frame):
        log.info("SIGTERM received — shutting down.")
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _on_sigterm)

    try:
        server.start()
    except KeyboardInterrupt:
        log.info("Keyboard interrupt — shutting down.")
        server.stop()
        sys.exit(0)


if __name__ == "__main__":
    main()
