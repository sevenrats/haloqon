import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from haloqon.protocol import parse


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
    from haloqon.protocol import parse as P
    p = P.admin_verify_payload("654321")
    assert len(p) == 8
    assert int.from_bytes(p[:4], "little") == 0xF0000000  # LOCK_ADMIN_UID
    assert (p[7] >> 4) == 6  # digit count in high nibble of last byte


def test_parse_counts():
    from haloqon.protocol import parse as P
    params = bytearray(5)
    params[0] = 0
    params[1:3] = (2).to_bytes(2, "little")
    params[3:5] = (1).to_bytes(2, "little")
    c = P.parse_counts(bytes(params))
    assert c.passwords == 2 and c.fingerprints == 1


def test_register_password_payload():
    from haloqon.protocol import parse as P
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
    from haloqon.protocol import parse
    pr = parse.parse_enroll_progress(bytes([5]))
    assert pr.status == 5


def test_set_ble_name_payload_padding():
    p = parse.set_ble_name_payload("FrontDoor")
    assert len(p) == parse.BLE_NAME_FIELD_LEN
    assert p[:9] == b"FrontDoor"
    assert p[9:] == b"\x00" * (parse.BLE_NAME_FIELD_LEN - 9)


def test_set_ble_name_payload_rejects_too_long():
    import pytest

    with pytest.raises(ValueError):
        parse.set_ble_name_payload("x" * 33)


def test_set_ble_name_payload_rejects_non_ascii():
    import pytest

    with pytest.raises(UnicodeEncodeError):
        parse.set_ble_name_payload("café")


def test_pack_unpack_log_time_roundtrip():
    import datetime as dt

    t = dt.datetime(2026, 9, 28, 14, 5, 33)
    v = parse.pack_log_time(t)
    assert parse.unpack_log_time(v) == t


def test_read_log_payload_layout():
    import datetime as dt

    t = dt.datetime(2026, 9, 28, 14, 5, 33)
    p = parse.read_log_payload(t, parse.LOG_READ_BACKWARD, 10)
    assert len(p) == 10  # 4 time + 1 (0x20) + 1 dir + 4 count
    assert p[0:4] == parse.pack_log_time(t).to_bytes(4, "little")
    assert p[4] == 0x20
    assert p[5] == 0
    assert p[6:10] == (10).to_bytes(4, "little")


def test_read_log_payload_rejects_bad_direction():
    import datetime as dt
    import pytest

    with pytest.raises(ValueError):
        parse.read_log_payload(dt.datetime(2026, 1, 1), 2, 10)


def test_parse_log_record():
    import datetime as dt

    t = dt.datetime(2026, 9, 28, 8, 30, 0)
    packed = parse.pack_log_time(t)
    params = (
        bytes([0])  # status
        + (5).to_bytes(4, "little")  # remaining count
        + (42).to_bytes(4, "little")  # index
        + packed.to_bytes(4, "little")  # time
        + bytes([0x21])  # type: door open / unlock
        + bytes([1])  # info: fingerprint
        + (11).to_bytes(4, "little")  # uid
    )
    rec = parse.parse_log_record(params)
    assert rec is not None
    assert rec.index == 42
    assert rec.time == t
    assert rec.type_name == "door open / unlock"
    assert rec.info_name == "fingerprint"
    assert rec.uid == 11
    assert rec.remaining == 5


def test_parse_log_record_matter_source():
    params = (
        bytes([0])
        + (1).to_bytes(4, "little")
        + (1).to_bytes(4, "little")
        + parse.pack_log_time(__import__("datetime").datetime(2026, 1, 1, 0, 0, 0)).to_bytes(4, "little")
        + bytes([0x21])
        + bytes([0x80 | 16])  # extended: Matter
        + (0xFFFFFFFF).to_bytes(4, "little")
    )
    rec = parse.parse_log_record(params)
    assert rec.info_name == "Matter"


def test_parse_log_record_end():
    assert parse.parse_log_record(bytes([5])) is None  # EMPTY status
    assert parse.parse_log_record(b"") is None


def test_unlock_payload():
    p = parse.unlock_payload("123456")
    # uid F0000000 LE + packed pwd (4B) + timeout 30 LE (4B) + 0x0d + relock 0
    assert p[0:4] == parse.LOCK_ADMIN_UID.to_bytes(4, "little")
    assert p[4:8] == parse._packed_code("123456")
    assert p[8:12] == (30).to_bytes(4, "little")
    assert p[12] == 0x0D
    assert p[13] == 0
    assert parse.unlock_payload("123456", relock=True)[13] == 1


def test_bolt_lock_payload():
    p = parse.bolt_lock_payload("123456")
    assert p[0:4] == parse.LOCK_ADMIN_UID.to_bytes(4, "little")
    assert p[4:8] == parse._packed_code("123456")


def test_parse_lock_status():
    params = bytes([0, 3, 0, 87, 0])  # status ok, lock=3(unlocked), bolt=0, batt=87
    s = parse.parse_lock_status(params)
    assert s.lock_status == 3
    assert s.bolt_status == 0
    assert s.battery == 87
    assert s.work_mode == 0


def test_read_sn_payload():
    assert parse.read_sn_payload() == b"\x10"


def test_parse_battery():
    assert parse.parse_battery(bytes([0, 87])) == 87


def test_parse_firmware_version():
    params = bytes([0]) + b"3.7.0.2\x00\x00"
    assert parse.parse_firmware_version(params) == "3.7.0.2"


def test_parse_serial():
    params = bytes([0]) + b"BOLT12345678\x00\x00\x00\x00" + b"trailing"
    assert parse.parse_serial(params) == "BOLT12345678"


def test_delete_user_payload():
    assert parse.delete_user_payload(11) == (11).to_bytes(4, "little")


def test_disable_enable_payload():
    p = parse.disable_enable_payload(11, parse.USER_DISABLE)
    assert p == (11).to_bytes(4, "little") + (1).to_bytes(2, "little") + (0).to_bytes(2, "little")
    p2 = parse.disable_enable_payload(11, parse.USER_ENABLE, is_admin=True)
    assert p2 == (11).to_bytes(4, "little") + (0).to_bytes(2, "little") + (1).to_bytes(2, "little")


def test_disable_enable_payload_rejects_bad_state():
    import pytest

    with pytest.raises(ValueError):
        parse.disable_enable_payload(11, 2)


def test_set_autolock_payload():
    assert parse.set_autolock_payload(30) == (30).to_bytes(2, "little") + b"\x00"
    assert parse.set_autolock_payload(30, relock=True) == (30).to_bytes(2, "little") + b"\x01"


def test_parse_autolock():
    assert parse.parse_autolock(bytes([0, 30, 0])) == 30
    assert parse.parse_autolock(bytes([0, 0x2C, 0x01])) == 300


def test_mute_roundtrip():
    assert parse.set_mute_payload(True) == b"\x01"
    assert parse.set_mute_payload(False) == b"\x00"
    assert parse.parse_mute(bytes([0, 0])) is False  # param[1]==0 -> sound on
    assert parse.parse_mute(bytes([0, 1])) is True


def test_schedule_week_roundtrip():
    # bit0=Sun..bit6=Sat; weekdays Mon-Fri = bits 1..5 = 0b0111110 = 0x3E
    p = parse.set_schedule_week_payload(11, 0x3E)
    assert p == (11).to_bytes(4, "little") + bytes([0x3E])
    assert parse.parse_schedule_week(bytes([0, 0x3E])) == 0x3E


def test_schedule_time_roundtrip():
    p = parse.set_schedule_time_payload(11, 8, 30, 17, 45)
    assert p == (11).to_bytes(4, "little") + bytes([8, 30, 17, 45])
    st = parse.parse_schedule_time(bytes([0, 8, 30, 17, 45]))
    assert (st.start_h, st.start_m, st.end_h, st.end_m) == (8, 30, 17, 45)


def test_schedule_date_roundtrip():
    import datetime as dt

    start = dt.date(2026, 9, 29)
    end = dt.date(2026, 12, 31)
    p = parse.set_schedule_date_payload(11, start, end)
    assert p[0:4] == (11).to_bytes(4, "little")
    # parse back the two packed dates from the wire
    params = bytes([0]) + p[4:8]
    sd = parse.parse_schedule_date(params)
    assert sd.start == start
    assert sd.end == end


def test_schedule_date_payload_with_times():
    import datetime as dt

    p = parse.set_schedule_date_payload(
        11, dt.date(2026, 1, 1), dt.date(2026, 1, 2), times=(8, 0, 18, 0)
    )
    assert p[-4:] == bytes([8, 0, 18, 0])


def test_schedule_num_roundtrip():
    assert parse.set_schedule_num_payload(11, 3) == (11).to_bytes(4, "little") + bytes([3])
    n = parse.parse_schedule_num(bytes([0, 3, 8]))
    assert n.current == 3 and n.maximum == 8


def test_parse_log_record_live_bolt():
    # Captured from a real Bolt: type 0x27 (unlocked), info 0x07 (smart home).
    p = bytes.fromhex("000a000000010000004c705748270700000000")
    rec = parse.parse_log_record(p)
    assert rec is not None
    assert rec.index == 1
    assert rec.type_name == "unlocked"
    assert rec.info_name == "smart home"
    assert rec.time.year == 2018 and rec.time.month == 1 and rec.time.day == 11


def test_res_read_plevel_is_standard():
    from haloqon.protocol.commands import Cmd

    assert parse.RES_READ_PLEVEL == (Cmd.READ_PLEVEL | 0x80) == 195
