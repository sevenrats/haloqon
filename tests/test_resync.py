import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from haloqon.ble import transport as T
from haloqon.protocol import frame
from haloqon.crypto import aes


class FakeQueue:
    def __init__(self): self.items=[]
    def put_nowait(self, x): self.items.append(x)


def make_transport():
    t = T.LockTransport.__new__(T.LockTransport)
    t._rx = bytearray()
    t._frames = FakeQueue()
    t._debug = False
    def dbg(_): pass
    t._dbg = dbg
    return t


def test_resync_past_padding():
    t = make_transport()
    # frame A (login ack) 16B with zero padding, then frame B (reg-psw ack) padded
    a = frame.build_frame(0xA0, b"\x00")  # 6 bytes
    b = frame.build_frame(0xB3, b"\x00")
    t._rx += a + b"\x00"*10   # simulate first decrypted 16B block
    t._drain_frames()
    assert [f.cmd for f in t._frames.items] == [0xA0]
    # leftover padding remains; next block starts with more zeros then frame B
    t._rx += b + b"\x00"*10
    t._drain_frames()
    assert [f.cmd for f in t._frames.items] == [0xA0, 0xB3]


def test_notify_decrypt_and_resync():
    key = bytes(range(16))
    t = make_transport()
    t._key = key
    fr = frame.build_frame(0xC9, bytes([0])+b"\x11"*4)
    enc = aes.encrypt(fr, key)  # padded to 16
    t._on_data_notify(None, bytearray(enc))
    assert [f.cmd for f in t._frames.items] == [0xC9]
