"""
NXP (Network eXchange Protocol) - Message format, parser, and builder.

Wire format:
    COMMAND LENGTH\r\n
    PAYLOAD\r\n

OS Concept: This module defines the application-layer protocol that rides on
top of TCP. TCP itself is a stream protocol — it gives us a reliable byte
stream, but has no notion of message boundaries. NXP adds framing via an
explicit LENGTH field so both ends agree on where one message ends and the
next begins (the "message boundary" problem).
"""

# ── Command constants ─────────────────────────────────────────────────────────
CMD_JOIN  = "JOIN"   # client announces its username
CMD_SEND  = "SEND"   # client sends a chat message
CMD_ACK   = "ACK"    # server acknowledges a command
CMD_ERROR = "ERROR"  # server signals an error condition
CMD_LEAVE = "LEAVE"  # client announces graceful disconnect

VALID_COMMANDS = {CMD_JOIN, CMD_SEND, CMD_ACK, CMD_ERROR, CMD_LEAVE}

# Delimiter used to separate header from payload on the wire.
CRLF = b"\r\n"


class NXPProtocolError(Exception):
    """Raised when an incoming byte sequence cannot be parsed as a valid NXP message."""


class NXPMessage:
    """
    Represents a single NXP protocol message.

    Attributes:
        command : one of the CMD_* constants
        payload : decoded string payload (may be empty)
    """

    def __init__(self, command: str, payload: str) -> None:
        if command not in VALID_COMMANDS:
            raise NXPProtocolError(f"Unknown command: {command!r}")
        self.command = command
        self.payload = payload

    def __repr__(self) -> str:
        return f"NXPMessage(command={self.command!r}, payload={self.payload!r})"

    def to_bytes(self) -> bytes:
        """Serialize this message back to the wire format."""
        return build_message(self.command, self.payload)


def build_message(command: str, payload: str) -> bytes:
    """
    Encode a command and payload into NXP wire bytes.

    Args:
        command: one of the CMD_* constants
        payload: arbitrary string (may be empty)

    Returns:
        Encoded bytes ready to be written to a TCP socket.

    Example:
        >>> build_message("JOIN", "alice")
        b'JOIN 5\r\nalice\r\n'
    """
    if command not in VALID_COMMANDS:
        raise NXPProtocolError(f"Cannot build message with unknown command: {command!r}")

    payload_bytes = payload.encode("utf-8")
    header = f"{command} {len(payload_bytes)}".encode("utf-8")
    return header + CRLF + payload_bytes + CRLF


def parse_message(raw_bytes: bytes) -> NXPMessage:
    """
    Decode raw bytes (exactly one NXP frame) into an NXPMessage.

    Args:
        raw_bytes: bytes starting from the very beginning of a frame,
                   containing at least the header CRLF.

    Returns:
        Parsed NXPMessage.

    Raises:
        NXPProtocolError: on any format violation (missing CRLF, bad length,
                          wrong payload size, unknown command).

    OS Concept: On the receiving end, the OS kernel delivers bytes from its
    TCP receive buffer to us via recv(). Those bytes may arrive in chunks
    that do not align with message boundaries. The caller is responsible for
    accumulating data until a full frame is present before calling this
    function (see recv_message() below).
    """
    # Locate the mandatory header terminator
    header_end = raw_bytes.find(CRLF)
    if header_end == -1:
        raise NXPProtocolError("Missing CRLF after header")

    header = raw_bytes[:header_end].decode("utf-8", errors="replace").strip()
    parts = header.split(" ", 1)
    if len(parts) != 2:
        raise NXPProtocolError(f"Malformed header (expected 'COMMAND LENGTH'): {header!r}")

    command, length_str = parts
    if command not in VALID_COMMANDS:
        raise NXPProtocolError(f"Unknown command in header: {command!r}")

    try:
        payload_len = int(length_str)
    except ValueError:
        raise NXPProtocolError(f"Non-integer length field: {length_str!r}")

    if payload_len < 0:
        raise NXPProtocolError(f"Negative payload length: {payload_len}")

    # Extract payload section (after header CRLF)
    payload_start = header_end + len(CRLF)
    payload_bytes  = raw_bytes[payload_start : payload_start + payload_len]

    if len(payload_bytes) != payload_len:
        raise NXPProtocolError(
            f"Payload length mismatch: expected {payload_len}, got {len(payload_bytes)}"
        )

    payload = payload_bytes.decode("utf-8", errors="replace")
    return NXPMessage(command, payload)


def recv_message(sock) -> NXPMessage:
    """
    Read exactly one NXP frame from a connected TCP socket.

    Reads byte-by-byte for the header (typically ~15 bytes) so it never
    consumes bytes that belong to the next message — critical when the server
    sends two messages back-to-back and the OS delivers them in a single TCP
    segment.  The payload is then read in bulk with an exact byte count.

    OS Concept: The OS kernel maintains a per-socket receive buffer in kernel
    space. Each call to sock.recv(n) copies UP TO n bytes from that buffer.
    Two consecutive sendall() calls on the server may be coalesced by the
    kernel's TCP stack (Nagle's algorithm) into one segment, so a single
    recv() on the client side could return bytes from multiple messages.
    Reading the header one byte at a time and the payload with an exact count
    guarantees we stop at precisely the message boundary.

    Args:
        sock: a connected socket.socket object (blocking mode assumed)

    Returns:
        Parsed NXPMessage, or raises NXPProtocolError / ConnectionError.
    """
    # Phase 1 — read header one byte at a time until CRLF
    # Headers are short (~15 bytes), so the syscall overhead is negligible.
    header_data = b""
    while not header_data.endswith(CRLF):
        byte = sock.recv(1)
        if not byte:
            raise ConnectionError("Socket closed while reading header")
        header_data += byte

    header = header_data[:-2].decode("utf-8", errors="replace").strip()
    parts  = header.split(" ", 1)
    if len(parts) != 2:
        raise NXPProtocolError(f"Malformed header: {header!r}")

    command, length_str = parts
    if command not in VALID_COMMANDS:
        raise NXPProtocolError(f"Unknown command: {command!r}")

    try:
        payload_len = int(length_str)
    except ValueError:
        raise NXPProtocolError(f"Bad length: {length_str!r}")

    # Phase 2 — read exactly payload_len bytes, then the trailing CRLF
    payload_data = b""
    while len(payload_data) < payload_len:
        chunk = sock.recv(payload_len - len(payload_data))
        if not chunk:
            raise ConnectionError("Socket closed while reading payload")
        payload_data += chunk

    # Consume the mandatory trailing CRLF without storing it
    trailing = b""
    while len(trailing) < 2:
        b = sock.recv(1)
        if not b:
            raise ConnectionError("Socket closed while reading trailing CRLF")
        trailing += b

    payload = payload_data.decode("utf-8", errors="replace")
    return NXPMessage(command, payload)


# ── Self-test (run directly: python protocol.py) ─────────────────────────────
if __name__ == "__main__":
    import sys

    def _check(label: str, condition: bool) -> None:
        status = "PASS" if condition else "FAIL"
        print(f"  [{status}] {label}")
        if not condition:
            sys.exit(1)

    print("=== protocol.py self-test ===")

    # build_message
    msg = build_message(CMD_JOIN, "alice")
    _check("build JOIN", msg == b"JOIN 5\r\nalice\r\n")

    msg = build_message(CMD_SEND, "Hello world!")
    _check("build SEND", msg == b"SEND 12\r\nHello world!\r\n")

    msg = build_message(CMD_LEAVE, "")
    _check("build LEAVE (empty payload)", msg == b"LEAVE 0\r\n\r\n")

    msg = build_message(CMD_ACK, "OK")
    _check("build ACK", msg == b"ACK 2\r\nOK\r\n")

    msg = build_message(CMD_ERROR, "Unknown command")
    _check("build ERROR", msg == b"ERROR 15\r\nUnknown command\r\n")

    # parse_message
    parsed = parse_message(b"JOIN 5\r\nalice\r\n")
    _check("parse JOIN command", parsed.command == CMD_JOIN)
    _check("parse JOIN payload", parsed.payload == "alice")

    parsed = parse_message(b"LEAVE 0\r\n\r\n")
    _check("parse LEAVE empty payload", parsed.payload == "")

    # round-trip
    original = NXPMessage(CMD_SEND, "round-trip test")
    recovered = parse_message(original.to_bytes())
    _check("round-trip command", recovered.command == original.command)
    _check("round-trip payload", recovered.payload == original.payload)

    # error handling
    try:
        parse_message(b"BADCMD 3\r\nhey\r\n")
        _check("reject unknown command", False)
    except NXPProtocolError:
        _check("reject unknown command", True)

    try:
        parse_message(b"no-crlf-here")
        _check("reject missing CRLF", False)
    except NXPProtocolError:
        _check("reject missing CRLF", True)

    try:
        build_message("INVALID", "x")
        _check("build rejects unknown command", False)
    except NXPProtocolError:
        _check("build rejects unknown command", True)

    try:
        NXPMessage("JUNK", "x")
        _check("NXPMessage rejects unknown command", False)
    except NXPProtocolError:
        _check("NXPMessage rejects unknown command", True)

    print("All tests passed.")
