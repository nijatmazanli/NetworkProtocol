"""
NXP Interactive Client Shell

OS Concepts:
  Threads — Two threads run concurrently once connected: the main thread reads
             user keyboard input (blocking read on stdin, FD 0), while a
             background thread blocks on recv_message() (blocking read on the
             network socket FD).  The OS scheduler interleaves them so neither
             starves the other.

  stdin   — File descriptor 0.  input() calls read(0, …) which blocks in the
             kernel until a newline is available from the terminal driver.

Security model:
  The client proves knowledge of the room password WITHOUT sending it:
    1. Server sends CHALLENGE:<hex_nonce>
    2. Client computes HMAC-SHA256(password, nonce) and appends it to JOIN
    3. Server verifies in a separate process; wrong → kicked immediately
  Message encryption uses PBKDF2(password) which the server cannot derive
  from the HMAC token alone — the two keys are cryptographically independent.
"""

import random
import socket
import sys
import threading

import crypto as _crypto
from logger   import get_logger
from protocol import (
    CMD_JOIN, CMD_LEAVE, CMD_SEND,
    NXPProtocolError, build_message, recv_message,
)

HOST = "127.0.0.1"
PORT = 9090

log = get_logger("client")

# ── Per-user color assignment ─────────────────────────────────────────────────
_USER_COLORS = [
    "\033[96m",   # bright cyan
    "\033[93m",   # bright yellow
    "\033[95m",   # bright magenta
    "\033[94m",   # bright blue
    "\033[33m",   # orange/dark yellow
    "\033[36m",   # dark cyan
    "\033[35m",   # dark magenta
    "\033[34m",   # dark blue
]
_RESET = "\033[0m"
_DIM   = "\033[2m"
_BOLD  = "\033[1m"

_user_color_map: dict[str, str] = {}

def _color_for(username: str) -> str:
    """Assign a random color to a username on first sight, stable afterwards."""
    if username not in _user_color_map:
        used      = set(_user_color_map.values())
        available = [c for c in _USER_COLORS if c not in used] or _USER_COLORS
        _user_color_map[username] = random.choice(available)
    return _user_color_map[username]


# ── Message formatting ────────────────────────────────────────────────────────

def _format_chat(text: str, key: bytes | None) -> str:
    """
    Colorize a broadcast message and decrypt the body if a key is set.
    Expected format from server: '[username] body'
    Body may be a plain string or 'ENC:<base64>' token.
    """
    if not (text.startswith("[") and "] " in text):
        return f"  {text}"

    bracket_end = text.index("] ")
    username    = text[1:bracket_end]
    body        = text[bracket_end + 2:]
    color       = _color_for(username)
    name_tag    = f"{color}{_BOLD}[{username}]{_RESET}"

    if _crypto.is_encrypted(body):
        if key is None:
            return f"  {name_tag} {_DIM}[encrypted — join with the room password]{_RESET}"
        plaintext = _crypto.decrypt(key, body)
        if plaintext is None:
            return f"  {name_tag} \033[31m[wrong password — cannot decrypt]{_RESET}"
        return f"  {name_tag} \033[32m[enc]{_RESET} {plaintext}"
    else:
        if key is not None:
            return f"  {name_tag} \033[33m[unencrypted]{_RESET} {body}"
        return f"  {name_tag} {body}"


# ── ANSI helpers ──────────────────────────────────────────────────────────────

def _clear_line() -> None:
    sys.stdout.write("\r\033[K")
    sys.stdout.flush()

def _reprint_prompt(prompt: str) -> None:
    sys.stdout.write(prompt)
    sys.stdout.flush()


# ── Receiver thread ───────────────────────────────────────────────────────────

def _receiver(
    sock: socket.socket,
    stop_event: threading.Event,
    prompt_ref: list,
    key_ref: list,         # key_ref[0]: bytes | None — encryption key
) -> None:
    """
    Background thread: reads messages from the server and prints them.
    Decrypts using key_ref[0] if set.  Never auto-accepts a server-sent key
    — the user must have supplied the password before connecting.
    """
    while not stop_event.is_set():
        try:
            msg = recv_message(sock)
        except (ConnectionError, NXPProtocolError, OSError):
            if not stop_event.is_set():
                _clear_line()
                print("\n[disconnected from server]")
                stop_event.set()
            break

        _clear_line()

        if msg.command == "ACK":
            print(f"  \033[32m[server]{_RESET} {msg.payload}")
        elif msg.command == "ERROR":
            print(f"  \033[31m[error ]{_RESET} {msg.payload}")
            # Server sends ERROR then closes — stop_event will be set by the
            # next recv_message call when it gets ConnectionError.
        elif msg.command == "SEND":
            print(_format_chat(msg.payload, key_ref[0]))
        else:
            print(f"  [{msg.command}] {msg.payload}")

        _reprint_prompt(prompt_ref[0])


# ── Main client logic ─────────────────────────────────────────────────────────

def _print_help() -> None:
    print(
        "\nNXP Client commands:\n"
        "  /join <name>   — authenticate and join the room\n"
        "  /send <text>   — send a chat message\n"
        "  /leave         — leave and disconnect\n"
        "  /help          — show this help\n"
    )


def run_client(host: str = HOST, port: int = PORT,
               password: str | None = None) -> None:
    """
    Connect, perform challenge-response auth, then enter the chat loop.

    Auth flow (happens before /join):
        1. Server sends CHALLENGE:<hex_nonce>  OR  OPEN
        2. If challenge: derive encryption key + compute HMAC auth token
        3. /join sends  'username|HMAC_token'  (password-gated room)
                   or   'username'             (open room)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
    except ConnectionRefusedError:
        print(f"[error] Cannot connect to {host}:{port} — is the server running?")
        sys.exit(1)

    log.info("Connected to %s:%d", host, port)

    # ── Step 1: Receive auth signal from server (before any user input) ───────
    try:
        auth_msg = recv_message(sock)
    except (ConnectionError, NXPProtocolError) as exc:
        print(f"[error] Server handshake failed: {exc}")
        sock.close()
        sys.exit(1)

    challenge: bytes | None = None
    needs_auth = False

    if auth_msg.payload.startswith(_crypto.CHALLENGE_PREFIX):
        # Server requires password authentication
        challenge_hex = auth_msg.payload[len(_crypto.CHALLENGE_PREFIX):]
        challenge     = bytes.fromhex(challenge_hex)
        needs_auth    = True

        print(f"\nConnected to {host}:{port}")
        print("\033[33m  This room requires a password.\033[0m")

        if password is None:
            password = input("  Room password: ").strip()

        if not password:
            print("[error] Password is required for this room.")
            sock.close()
            sys.exit(1)

        print("  Deriving encryption key… ", end="", flush=True)
        enc_key = _crypto.derive_key(password)
        print("done.")
        print("\033[32m  E2E encryption ready. Server cannot read your messages.\033[0m")

    elif auth_msg.payload == _crypto.OPEN_SIGNAL:
        # Open room — no auth required
        print(f"\nConnected to {host}:{port}")
        print("\033[33m  Open room — no password required.\033[0m")

        # Still allow optional client-side encryption if user passed --password
        if password:
            enc_key = _crypto.derive_key(password)
            print("\033[32m  E2E encryption enabled (your own password).\033[0m")
        else:
            enc_key = None
            print("  Messages are sent in plaintext.")

    else:
        print(f"[error] Unexpected server signal: {auth_msg.payload!r}")
        sock.close()
        sys.exit(1)

    print("Type /help for commands.\n")

    key_ref    = [enc_key]
    prompt_ref = ["> "]
    stop_event = threading.Event()

    receiver_thread = threading.Thread(
        target=_receiver,
        args=(sock, stop_event, prompt_ref, key_ref),
        daemon=True,
    )
    receiver_thread.start()

    joined = False

    try:
        while not stop_event.is_set():
            try:
                raw = input(prompt_ref[0])
            except EOFError:
                break
            except KeyboardInterrupt:
                print()
                break

            line = raw.strip()
            if not line:
                continue

            # ── Command dispatch ──────────────────────────────────────────────

            if line.startswith("/join"):
                parts = line.split(maxsplit=1)
                if len(parts) < 2 or not parts[1].strip():
                    print("  Usage: /join <username>")
                    continue
                username = parts[1].strip()

                if needs_auth:
                    # Append HMAC auth token — proves password without sending it
                    token   = _crypto.make_auth_token(password, challenge)
                    payload = f"{username}|{token}"
                else:
                    payload = username

                sock.sendall(build_message(CMD_JOIN, payload))
                prompt_ref[0] = f"{username}> "
                joined = True

            elif line.startswith("/send"):
                if not joined:
                    print("  [hint] You must /join first.")
                    continue
                parts = line.split(maxsplit=1)
                if len(parts) < 2 or not parts[1].strip():
                    print("  Usage: /send <message>")
                    continue
                _do_send(sock, parts[1], key_ref)

            elif line in ("/leave", "/quit", "/exit"):
                sock.sendall(build_message(CMD_LEAVE, ""))
                break

            elif line == "/help":
                _print_help()

            else:
                if joined:
                    _do_send(sock, line, key_ref)
                else:
                    print("  Unknown command. Type /help for usage.")

    finally:
        stop_event.set()
        try:
            sock.close()
        except OSError:
            pass
        receiver_thread.join(timeout=1.0)
        print("\nDisconnected.")


def _do_send(sock: socket.socket, text: str, key_ref: list) -> None:
    """Encrypt with current key (if set), then send NXP SEND."""
    key     = key_ref[0]
    payload = _crypto.encrypt(key, text) if key else text
    sock.sendall(build_message(CMD_SEND, payload))


# ── Startup prompts ───────────────────────────────────────────────────────────

def _prompt_connection() -> tuple[str, int]:
    """Interactive server-address prompt. Accepts host, host:port, [::1]:port."""
    print("NXP Chat Client")
    print("─" * 40)
    raw = input(f"  Server address [default: 127.0.0.1:{PORT}]: ").strip()

    if not raw:
        return "127.0.0.1", PORT

    if raw.count(":") == 1:
        host_part, port_part = raw.rsplit(":", 1)
        try:
            return host_part.strip(), int(port_part.strip())
        except ValueError:
            return raw, PORT

    if raw.startswith("["):
        try:
            bracket_end = raw.index("]")
            return raw[1:bracket_end], int(raw[bracket_end + 2:])
        except (ValueError, IndexError):
            pass

    return raw, PORT


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="NXP Chat Client")
    parser.add_argument("--host", default=None,
                        help="Server hostname or IP (omit to be prompted)")
    parser.add_argument("--port", default=PORT, type=int,
                        help=f"Server port (default: {PORT})")
    parser.add_argument("--password", default=None,
                        help="Room password (omit to be prompted if required)")
    parser.add_argument("--no-encrypt", action="store_true",
                        help="Disable client-side encryption in open rooms")
    args = parser.parse_args()

    if args.host is None:
        host, port = _prompt_connection()
    else:
        host, port = args.host, args.port

    password = None if args.no_encrypt else args.password
    run_client(host, port, password)


if __name__ == "__main__":
    main()
