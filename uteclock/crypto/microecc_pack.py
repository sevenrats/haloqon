"""Byte packing that matches the lock's micro-ecc public API.

libanvizecc.so is a micro-ecc build on a little-endian target. Empirically
(confirmed against the real lock, 2026-09-23), each coordinate is serialized
**little-endian**: the lock's returned public-key halves only land on the curve
when decoded little-endian, so we both decode the lock's key and encode ours the
same way (ECDH is symmetric, so our sent key must use the lock's convention).

For secp128r1 each coordinate/scalar is 16 bytes. A public key on the wire is
X (16 bytes, LE) followed by Y (16 bytes, LE) = 32 bytes.
"""

from __future__ import annotations

from .secp128r1 import COORD_BYTES, Point

PUBKEY_BYTES = COORD_BYTES * 2
_BYTEORDER = "little"


def int_to_bytes(value: int) -> bytes:
    return value.to_bytes(COORD_BYTES, _BYTEORDER)


def int_from_bytes(data: bytes) -> int:
    if len(data) != COORD_BYTES:
        raise ValueError(f"expected {COORD_BYTES} bytes, got {len(data)}")
    return int.from_bytes(data, _BYTEORDER)


def public_to_bytes(point: Point) -> bytes:
    """Serialize a public point as X||Y (32 bytes)."""
    if point.is_infinity:
        raise ValueError("cannot serialize the point at infinity")
    return int_to_bytes(point.x) + int_to_bytes(point.y)


def public_x_bytes(point: Point) -> bytes:
    return int_to_bytes(point.x)


def public_y_bytes(point: Point) -> bytes:
    return int_to_bytes(point.y)


def public_from_halves(x_bytes: bytes, y_bytes: bytes) -> Point:
    """Rebuild a public point from the lock's two 16-byte notify halves."""
    return Point(int_from_bytes(x_bytes), int_from_bytes(y_bytes))
