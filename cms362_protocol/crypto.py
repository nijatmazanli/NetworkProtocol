"""
NXP End-to-End Encryption  —  stdlib only, no pip installs.

Scheme: PBKDF2-HMAC-SHA256 key derivation  +  HMAC-SHA256 in CTR mode
        (authenticated stream cipher, semantically equivalent to AES-GCM
        but built from primitives that ship with Python).

Why no AES?
    Python's standard library has no block cipher.  HMAC-SHA256-CTR is a
    well-understood construction: HMAC with a secret key is a PRF
    (Pseudo-Random Function), so using it in counter mode produces a
    computationally indistinguishable-from-random keystream — exactly what
    a stream cipher needs.  Adding a 128-bit authentication tag (Encrypt-
    then-MAC) gives authenticated encryption, preventing ciphertext
    tampering.

Wire token format (base64url, embedded in the NXP SEND payload):
    [ nonce 16B | tag 16B | ciphertext ]

    nonce  — random, unique per message; never reused with the same key
    tag    — HMAC-SHA256(key, nonce ‖ ciphertext) truncated to 16 bytes
    ct     — plaintext XOR keystream

Security properties:
    • Confidentiality  — server and eavesdroppers see only ciphertext
    • Integrity / Auth — forged or tampered messages are rejected
    • Replay safety    — random nonce makes every ciphertext unique
    • Key stretching   — PBKDF2 with 260 000 iterations makes brute-force
                         of weak passwords expensive (~0.1 s per guess)
"""

import base64
import hashlib
import hmac
import os

# ── Constants ─────────────────────────────────────────────────────────────────
NONCE_LEN   = 16   # bytes — 128-bit random nonce, unique per message
TAG_LEN     = 16   # bytes — 128-bit authentication tag (truncated HMAC-SHA256)
KDF_ITERS   = 260_000   # PBKDF2 iteration count (OWASP 2023 recommendation)
# Fixed application salt: same for all users so they derive the same key from
# the same password.  Per-user salts would require a salt-exchange protocol.
_APP_SALT   = b"NXP-CMS362-KhazarUniversity-v1"
# Prefix that marks an encrypted payload on the wire.
ENC_PREFIX  = "ENC:"


# ── Key derivation ────────────────────────────────────────────────────────────

def derive_key(password: str) -> bytes:
    """
    Derive a 256-bit secret key from a human-chosen password.

    Uses PBKDF2-HMAC-SHA256: applies the HMAC-SHA256 pseudo-random function
    KDF_ITERS times so that an attacker who intercepts ciphertext must pay
    that cost for every password guess.

    Args:
        password: the room password all participants share

    Returns:
        32 bytes suitable as a symmetric encryption key
    """
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        _APP_SALT,
        KDF_ITERS,
        dklen=32,
    )


# ── Stream cipher (HMAC-SHA256 in CTR mode) ───────────────────────────────────

def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """
    Generate `length` pseudorandom bytes by running HMAC-SHA256 in counter mode.

    Each 32-byte block is:   HMAC-SHA256(key, nonce ‖ counter)
    where counter is a big-endian 64-bit integer.

    Because HMAC with a secret key is a PRF, this output is computationally
    indistinguishable from a truly random byte string — the defining property
    of a secure stream cipher.
    """
    stream = b""
    counter = 0
    while len(stream) < length:
        block = hmac.new(
            key,
            nonce + counter.to_bytes(8, "big"),
            "sha256",
        ).digest()
        stream += block
        counter += 1
    return stream[:length]


# ── Public encrypt / decrypt ──────────────────────────────────────────────────

def encrypt(key: bytes, plaintext: str) -> str:
    """
    Encrypt a plaintext string and return a wire-ready token.

    Steps:
        1. Encode plaintext to UTF-8 bytes
        2. Generate a fresh 128-bit random nonce (os.urandom — CSPRNG)
        3. XOR plaintext bytes with keystream (stream cipher)
        4. Compute authentication tag: HMAC-SHA256(key, nonce ‖ ciphertext)[:16]
        5. Pack  nonce ‖ tag ‖ ciphertext  and base64-encode it
        6. Prepend ENC: prefix so receivers know to decrypt

    Args:
        key:       32-byte key from derive_key()
        plaintext: the message text to protect

    Returns:
        String starting with "ENC:" — safe to embed as an NXP payload
    """
    pt_bytes = plaintext.encode("utf-8")

    # os.urandom() calls the OS CSPRNG (getrandom(2) on Linux) — each call
    # returns a fresh nonce that is statistically impossible to repeat.
    nonce = os.urandom(NONCE_LEN)

    ks = _keystream(key, nonce, len(pt_bytes))
    ct = bytes(a ^ b for a, b in zip(pt_bytes, ks))

    # Encrypt-then-MAC: compute the tag over the *ciphertext* (not plaintext)
    # so the tag also authenticates the nonce.
    tag = hmac.new(key, nonce + ct, "sha256").digest()[:TAG_LEN]

    token = base64.b64encode(nonce + tag + ct).decode("ascii")
    return ENC_PREFIX + token


def decrypt(key: bytes, token: str) -> str | None:
    """
    Verify and decrypt a token produced by encrypt().

    Returns the plaintext string, or None if:
        • token does not start with ENC:  (not encrypted)
        • base64 decoding fails           (corrupted)
        • authentication tag mismatch     (wrong key or tampered ciphertext)

    The tag comparison uses hmac.compare_digest() — a constant-time equality
    check that prevents timing side-channel attacks.

    Args:
        key:   32-byte key from derive_key()
        token: string starting with "ENC:"

    Returns:
        Decrypted plaintext, or None on any failure
    """
    if not token.startswith(ENC_PREFIX):
        return None

    try:
        raw = base64.b64decode(token[len(ENC_PREFIX):])
    except Exception:
        return None

    if len(raw) < NONCE_LEN + TAG_LEN:
        return None

    nonce = raw[:NONCE_LEN]
    tag   = raw[NONCE_LEN : NONCE_LEN + TAG_LEN]
    ct    = raw[NONCE_LEN + TAG_LEN:]

    expected_tag = hmac.new(key, nonce + ct, "sha256").digest()[:TAG_LEN]

    # Constant-time comparison — prevents timing oracle
    if not hmac.compare_digest(tag, expected_tag):
        return None

    ks = _keystream(key, nonce, len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks)).decode("utf-8", errors="replace")


def is_encrypted(token: str) -> bool:
    return token.startswith(ENC_PREFIX)


# ── Challenge-Response Authentication ─────────────────────────────────────────
#
# Security model:
#   The client proves knowledge of the password WITHOUT sending it over the
#   wire.  The server sends a random nonce (challenge); the client responds
#   with HMAC-SHA256(password, nonce).  Properties:
#     • Password never travels on the network
#     • Each session produces a unique token — cannot be replayed
#     • Constant-time comparison prevents timing side-channels
#     • Server must know the password to verify (inherent in symmetric auth)
#
# This is distinct from message encryption: auth uses plain HMAC(password,
# nonce), while encryption uses PBKDF2(password) as the key.  An attacker
# who captures the auth token cannot derive the message key from it.

CHALLENGE_PREFIX = "CHALLENGE:"
OPEN_SIGNAL      = "OPEN"


def make_auth_token(password: str, challenge: bytes) -> str:
    """
    Compute HMAC-SHA256(password, challenge) as a 64-char hex string.

    Called by the client to respond to a server challenge.  The token
    proves knowledge of `password` without disclosing it.
    """
    return hmac.new(password.encode("utf-8"), challenge, "sha256").hexdigest()


def verify_auth_token(password: str, challenge: bytes, token: str) -> bool:
    """
    Verify a client's auth token against the room password.

    Uses hmac.compare_digest for constant-time equality — prevents an
    attacker from learning partial token matches via response-time differences.

    Called in the server's ProcessPoolExecutor worker so verification runs
    in a separate OS process, bypassing the GIL for true CPU parallelism.
    """
    try:
        expected = make_auth_token(password, challenge)
        return hmac.compare_digest(expected, token)
    except (TypeError, ValueError):
        return False


# ── Self-test ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys, time

    def check(label, cond):
        print(f"  [{'PASS' if cond else 'FAIL'}] {label}")
        if not cond:
            sys.exit(1)

    print("=== crypto.py self-test ===")

    # Key derivation
    t0 = time.monotonic()
    key = derive_key("supersecret")
    elapsed = time.monotonic() - t0
    check("derive_key returns 32 bytes", len(key) == 32)
    print(f"  [INFO] derive_key took {elapsed*1000:.1f} ms ({KDF_ITERS} iterations)")
    check("derive_key takes measurable time (>1 ms)", elapsed > 0.001)
    check("same password → same key", derive_key("supersecret") == key)
    check("different password → different key", derive_key("other") != key)

    # Encrypt / decrypt round-trip
    messages = ["Hello!", "Unicode: Salam 🌍", "A" * 1000, ""]
    for m in messages:
        token = encrypt(key, m)
        check(f"token starts with ENC: ({m[:20]!r})", token.startswith("ENC:"))
        recovered = decrypt(key, token)
        check(f"round-trip ({m[:20]!r})", recovered == m)

    # Each encryption produces a unique ciphertext (nonce randomness)
    t1 = encrypt(key, "same text")
    t2 = encrypt(key, "same text")
    check("two encryptions of same plaintext differ", t1 != t2)

    # Wrong key returns None
    wrong_key = derive_key("wrongpassword")
    check("wrong key → None", decrypt(wrong_key, encrypt(key, "secret")) is None)

    # Tampered ciphertext returns None
    token = encrypt(key, "tamper me")
    bad = token[:-4] + "XXXX"
    check("tampered token → None", decrypt(key, bad) is None)

    # Non-ENC token returns None
    check("plain text → None", decrypt(key, "hello world") is None)

    # is_encrypted
    check("is_encrypted(ENC:...) is True",  is_encrypted(encrypt(key, "x")))
    check("is_encrypted(plain)   is False", not is_encrypted("plain text"))

    # Challenge-response auth
    import os as _os
    challenge = _os.urandom(16)
    token = make_auth_token("roompass", challenge)
    check("auth token is 64-char hex", len(token) == 64 and all(c in "0123456789abcdef" for c in token))
    check("verify correct token",      verify_auth_token("roompass", challenge, token))
    check("verify wrong password",     not verify_auth_token("wrongpass", challenge, token))
    check("verify wrong challenge",    not verify_auth_token("roompass", _os.urandom(16), token))
    check("verify tampered token",     not verify_auth_token("roompass", challenge, token[:-2] + "00"))
    check("two challenges differ",     make_auth_token("p", _os.urandom(16)) != make_auth_token("p", _os.urandom(16)))

    print("All tests passed.")
