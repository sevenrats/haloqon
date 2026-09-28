"""AES transport encryption matching the lock (util_AES + ModuleBase.sendCmd).

The app uses "AES/CBC/NoPadding" with an all-zero IV, but encrypts each 16-byte
block independently in its own cipher call with that fixed zero IV. With a fresh
zero-IV CBC single block, that is identical to AES-ECB per block. The last
partial block is zero-padded to 16 bytes before encryption.

So the whole scheme reduces to: zero-pad plaintext to a multiple of 16, then
AES-128-ECB with key = the 16-byte ECDH shared secret. We implement it exactly
as the app does (per-block, zero IV) to stay faithful, wrapping pyca/cryptography.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK = 16
_ZERO_IV = b"\x00" * BLOCK


def _cipher(key: bytes):
    if len(key) != BLOCK:
        raise ValueError(f"AES key must be {BLOCK} bytes, got {len(key)}")
    return Cipher(algorithms.AES(key), modes.CBC(_ZERO_IV))


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt block-by-block with zero IV, zero-padding the final block."""
    out = bytearray()
    for i in range(0, len(plaintext), BLOCK):
        block = plaintext[i : i + BLOCK]
        if len(block) < BLOCK:
            block = block + b"\x00" * (BLOCK - len(block))
        enc = _cipher(key).encryptor()
        out += enc.update(block) + enc.finalize()
    return bytes(out)


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt block-by-block with zero IV (inverse of encrypt)."""
    if len(ciphertext) % BLOCK != 0:
        raise ValueError("ciphertext length must be a multiple of 16")
    out = bytearray()
    for i in range(0, len(ciphertext), BLOCK):
        block = ciphertext[i : i + BLOCK]
        dec = _cipher(key).decryptor()
        out += dec.update(block) + dec.finalize()
    return bytes(out)
