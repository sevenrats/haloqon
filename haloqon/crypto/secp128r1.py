"""secp128r1 elliptic curve + ECDH, matching the lock's micro-ecc build.

Curve parameters were confirmed byte-for-byte from libanvizecc.so's .data
Curve_secp128r1 struct (see scratch/xthings-re/NATIVE-CRYPTO.md). They are the
standard SEC 2 secp128r1 domain parameters.

The lock exchanges public keys as two 16-byte halves (X then Y), and the shared
secret is the 16-byte X coordinate of priv*peerPub. No KDF is applied; that raw
X is used directly as the AES-128 key.

Byte order: micro-ecc's public API serializes each coordinate big-endian (most
significant byte first), 16 bytes per coordinate. See microecc_pack.py.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# --- Standard secp128r1 domain parameters -------------------------------------
P = 0xFFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3  # -3 mod p
B = 0xE87579C11079F43DD824993C2CEE5ED3
N = 0xFFFFFFFE0000000075A30D1B9038A115
GX = 0x161FF7528B899B2D0C28607CA52C5B86
GY = 0xCF5AC8395BAFEB13C02DA292DDED7A83
COORD_BYTES = 16


@dataclass(frozen=True)
class Point:
    """An affine point on secp128r1, or the point at infinity (x=y=None)."""

    x: int | None
    y: int | None

    @property
    def is_infinity(self) -> bool:
        return self.x is None


INFINITY = Point(None, None)
G = Point(GX, GY)


def _inv_mod(k: int, p: int = P) -> int:
    return pow(k, -1, p)


def point_add(a: Point, b: Point) -> Point:
    if a.is_infinity:
        return b
    if b.is_infinity:
        return a
    if a.x == b.x and (a.y + b.y) % P == 0:
        return INFINITY
    if a.x == b.x:  # doubling
        s = (3 * a.x * a.x + A) * _inv_mod(2 * a.y) % P
    else:
        s = (b.y - a.y) * _inv_mod(b.x - a.x) % P
    x = (s * s - a.x - b.x) % P
    y = (s * (a.x - x) - a.y) % P
    return Point(x, y)


def scalar_mul(k: int, point: Point = G) -> Point:
    """Constant-shape double-and-add. k is reduced mod N."""
    k %= N
    result = INFINITY
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def is_valid_public_key(point: Point) -> bool:
    if point.is_infinity:
        return False
    if not (0 <= point.x < P and 0 <= point.y < P):
        return False
    # y^2 == x^3 + a*x + b (mod p)
    lhs = point.y * point.y % P
    rhs = (point.x * point.x * point.x + A * point.x + B) % P
    return lhs == rhs


def make_key(private_value: int | None = None) -> tuple[int, Point]:
    """Return (private_scalar, public_point). Random private if not given."""
    if private_value is None:
        while True:
            private_value = int.from_bytes(os.urandom(COORD_BYTES), "big")
            if 1 <= private_value < N:
                break
    else:
        private_value %= N
        if private_value == 0:
            raise ValueError("private scalar must be non-zero mod N")
    return private_value, scalar_mul(private_value, G)


def ecdh_shared_x(private_scalar: int, peer_public: Point) -> int:
    """ECDH: return the X coordinate of private_scalar * peer_public."""
    if not is_valid_public_key(peer_public):
        raise ValueError("peer public key is not on the curve")
    shared = scalar_mul(private_scalar, peer_public)
    if shared.is_infinity:
        raise ValueError("ECDH produced the point at infinity")
    return shared.x
