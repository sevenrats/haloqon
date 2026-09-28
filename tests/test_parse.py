import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from uteclock.protocol import parse


def test_admin_login_payload_packing():
    # code "123456": value=123456 -> 4 bytes LE, length nibble 6 in high nibble of byte3
    p = parse.admin_login_payload("123456")
    assert len(p) == 4
    val = int.from_bytes(p, "little") & 0x0FFFFFFF  # strip the length nibble
    assert val == 123456
    assert (p[3] >> 4) == 6  # digit count


def test_admin_login_default_len_nibble():
    p = parse.admin_login_payload("0000")
    assert (p[3] >> 4) == 4


def test_register_finger_payload():
    p = parse.register_finger_payload(uid=7, slot=2)
    assert p == (7).to_bytes(4, "little") + (2).to_bytes(4, "little")


def test_parse_user_record():
    # real Latch 5 Pro record (params after cmd), uid=11 user with a PIN
    params = bytes.fromhex(
        "0002000000020000000b00000009f75f8400000000000000000000"
    )
    rec = parse.parse_user_record(params)
    assert rec is not None
    assert rec.total == 2 and rec.index == 2
    assert rec.uid == 11
    assert rec.user_type == 0


def test_parse_user_record_end():
    assert parse.parse_user_record(b"\x01" + b"\x00" * 26) is None
    assert parse.parse_user_record(b"") is None


def test_parse_finger_crc():
    params = bytearray(8)
    params[0] = 0
    params[1:5] = (4242).to_bytes(4, "little")
    params[4:8] = b"\xde\xad\xbe\xef"
    rec = parse.parse_finger_crc(bytes(params))
    assert rec is not None
    assert rec.crc == b"\xde\xad\xbe\xef"


def test_parse_enroll_progress():
    params = bytearray(9)
    params[0] = 0
    params[1:5] = (4).to_bytes(4, "little")  # total
    params[5:9] = (2).to_bytes(4, "little")  # current
    pr = parse.parse_enroll_progress(bytes(params))
    assert (pr.status, pr.total, pr.current) == (0, 4, 2)
    # soft error carries no counts
    pr2 = parse.parse_enroll_progress(bytes([16]))
    assert pr2.status == 16 and pr2.total == 0


def test_admin_verify_payload():
    from uteclock.protocol import parse as P
    p = P.admin_verify_payload("654321")
    assert len(p) == 8
    assert int.from_bytes(p[:4], "little") == 0xF0000000  # LOCK_ADMIN_UID
    assert (p[7] >> 4) == 6  # digit count in high nibble of last byte


def test_parse_counts():
    from uteclock.protocol import parse as P
    params = bytearray(5)
    params[0] = 0
    params[1:3] = (2).to_bytes(2, "little")
    params[3:5] = (1).to_bytes(2, "little")
    c = P.parse_counts(bytes(params))
    assert c.passwords == 2 and c.fingerprints == 1


def test_register_password_payload():
    from uteclock.protocol import parse as P
    p = P.register_password_payload(uid=11, pin="1234", user_type=1)
    assert len(p) == 12
    assert int.from_bytes(p[:4], "little") == 11
    assert int.from_bytes(p[8:12], "little") == 1
    assert (p[7] >> 4) == 4  # pin digit count


def test_set_latch_payload():
    assert parse.set_latch_payload(parse.DIRECTION_LEFT) == b"\x00"
    assert parse.set_latch_payload(parse.DIRECTION_RIGHT) == b"\x01"


def test_set_latch_payload_rejects_bad_value():
    import pytest

    with pytest.raises(ValueError):
        parse.set_latch_payload(2)


def test_parse_latch_direction():
    # RES_GET_LATCH params: [status=0][direction]; direction is GetParam()[1].
    assert parse.parse_latch_direction(bytes([0, parse.DIRECTION_LEFT])) == 0
    assert parse.parse_latch_direction(bytes([0, parse.DIRECTION_RIGHT])) == 1


def test_parse_latch_direction_short():
    import pytest

    with pytest.raises(ValueError):
        parse.parse_latch_direction(bytes([0]))


def test_enroll_empty_user_status():
    # ACK_EMPTY (5) in an enroll response means the target uid doesn't exist;
    # enroll_finger must fail eagerly rather than wait for a sensor touch.
    from uteclock.protocol import parse
    pr = parse.parse_enroll_progress(bytes([5]))
    assert pr.status == 5
