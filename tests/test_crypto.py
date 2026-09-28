import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from haloqon.crypto import secp128r1 as S
from haloqon.crypto import microecc_pack as P
from haloqon.crypto import aes


def test_curve_params_standard_secp128r1():
    assert S.P == 0xFFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF
    assert S.N == 0xFFFFFFFE0000000075A30D1B9038A115
    assert S.GX == 0x161FF7528B899B2D0C28607CA52C5B86
    assert S.GY == 0xCF5AC8395BAFEB13C02DA292DDED7A83
    assert S.B == 0xE87579C11079F43DD824993C2CEE5ED3
    assert S.A == S.P - 3


def test_generator_on_curve_and_order():
    assert S.is_valid_public_key(S.G)
    assert S.scalar_mul(S.N, S.G).is_infinity
    assert S.scalar_mul(1, S.G) == S.G
    neg = S.scalar_mul(S.N - 1, S.G)
    assert neg.x == S.GX and neg.y == (S.P - S.GY)


def test_ecdh_symmetric_many():
    for _ in range(100):
        da, ap = S.make_key()
        db, bp = S.make_key()
        assert S.is_valid_public_key(ap) and S.is_valid_public_key(bp)
        assert S.ecdh_shared_x(da, bp) == S.ecdh_shared_x(db, ap)


def test_pack_roundtrip():
    _, pt = S.make_key()
    b = P.public_to_bytes(pt)
    assert len(b) == 32
    assert P.public_from_halves(b[:16], b[16:]) == pt


def test_aes_block_roundtrip():
    key = bytes(range(16))
    pt = b"hello world" + b"\x00" * 5  # 16 bytes
    ct = aes.encrypt(pt, key)
    assert len(ct) == 16
    assert aes.decrypt(ct, key) == pt


def test_aes_multiblock_and_zeropad():
    key = bytes(range(16))
    pt = b"A" * 20  # 1.25 blocks -> encrypt pads to 32
    ct = aes.encrypt(pt, key)
    assert len(ct) == 32
    dec = aes.decrypt(ct, key)
    assert dec[:20] == pt
    assert dec[20:] == b"\x00" * 12
