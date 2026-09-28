import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from haloqon.protocol import frame
from haloqon.protocol.commands import Cmd
from haloqon.protocol import parse


def test_crc8_table_head():
    # matches the decompiled tcb_base.java CRC8Table head
    assert frame.CRC8_TABLE[:4] == [0, 94, 188, 226]
    assert len(frame.CRC8_TABLE) == 256


def test_build_parse_roundtrip():
    raw = frame.build_frame(Cmd.READ_ALL_IDPWD, parse.read_all_idpwd_payload(0))
    assert raw[0] == 0x7F
    # payload_len (LE) = len(cmd+params+crc) = 1 + 4 + 1 = 6
    assert int.from_bytes(raw[1:3], "little") == 6
    f, rest = frame.parse_frame(raw)
    assert rest == b""
    assert f.cmd == Cmd.READ_ALL_IDPWD
    assert f.params == b"\x00\x00\x00\x00"


def test_ack_bit_and_req_cmd():
    # simulate a response frame: cmd = REGISTER_ID_FINGER | 0x80
    resp = frame.build_frame(Cmd.REGISTER_ID_FINGER | 0x80, b"\x00")
    f, _ = frame.parse_frame(resp)
    assert f.is_ack
    assert f.req_cmd == Cmd.REGISTER_ID_FINGER
    assert f.status == 0


def test_crc_mismatch_raises():
    raw = bytearray(frame.build_frame(Cmd.ADMIN_LOGIN, b"\x01\x02\x03\x04"))
    raw[-1] ^= 0xFF
    try:
        frame.parse_frame(bytes(raw))
    except frame.FrameError:
        return
    raise AssertionError("expected FrameError on bad CRC")


def test_partial_frame_detected():
    raw = frame.build_frame(Cmd.READ_ALL_IDPWD, b"\x00\x00\x00\x00")
    assert not frame.frame_complete(raw[:3])
    assert frame.frame_complete(raw)
    # trailing bytes of a second frame are returned as remainder
    f, rest = frame.parse_frame(raw + b"\x7f\x99")
    assert rest == b"\x7f\x99"


def test_two_frames_streamed():
    a = frame.build_frame(Cmd.READ_ALL_IDPWD, b"\x00\x00\x00\x00")
    b = frame.build_frame(Cmd.READ_IDFP_COUNT, b"")
    buf = a + b
    f1, rest = frame.parse_frame(buf)
    f2, rest2 = frame.parse_frame(rest)
    assert f1.cmd == Cmd.READ_ALL_IDPWD
    assert f2.cmd == Cmd.READ_IDFP_COUNT
    assert rest2 == b""
