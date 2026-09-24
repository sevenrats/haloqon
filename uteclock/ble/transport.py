"""BLE transport over bleak: connect, ECDH handshake, encrypted request/response.

Implements the "ECC" key scheme used by the Latch 5 Pro:
  - subscribe to the ECC key characteristic (…7221)
  - write our public key X (16B) then Y (16B), 50ms apart
  - receive the lock's public key as two 16B notifies
  - shared X coord = AES-128 session key
Then commands are AES-encrypted TCB frames written to the data char (…7201),
with responses arriving as notifications on the same char.
"""

from __future__ import annotations

import asyncio
import logging

from bleak import BleakClient, BleakScanner

from ..crypto import aes, microecc_pack, secp128r1
from ..protocol import frame

_LOGGER = logging.getLogger(__name__)

SERVICE = "00007200-0000-1000-8000-00805f9b34fb"
CHAR_DATA = "00007201-0000-1000-8000-00805f9b34fb"
CHAR_KEY_LEGACY = "00007220-0000-1000-8000-00805f9b34fb"
CHAR_KEY_ECC = "00007221-0000-1000-8000-00805f9b34fb"
CHAR_KEY_MD5 = "00007223-0000-1000-8000-00805f9b34fb"

LOCK_NAME = "Latch5-Pro"
WRITE_CHUNK = 16
CHUNK_DELAY = 0.05
# Real frames are well under the BLE MTU; a larger declared length means the
# buffer is desynced or the firmware sent a malformed reply.
MAX_FRAME_PAYLOAD = 256


class TransportError(Exception):
    pass


async def scan(timeout: float = 8.0) -> list[tuple[str, str]]:
    """Return [(address, name), …] for advertising U-tec locks."""
    devices = await BleakScanner.discover(timeout=timeout)
    found = []
    for d in devices:
        if d.name and ("Latch" in d.name or d.name.startswith("U")):
            found.append((d.address, d.name))
    return found


class LockTransport:
    def __init__(self, address: str, adapter: str | None = None, debug: bool = False):
        self.address = address
        self._client = BleakClient(address, adapter=adapter) if adapter else BleakClient(address)
        self._debug = debug
        self._key: bytes | None = None
        # handshake state
        self._lock_pub_x: bytes | None = None
        self._lock_pub_y: bytes | None = None
        self._handshake_done = asyncio.Event()
        # response framing
        self._rx = bytearray()
        self._frames: asyncio.Queue = asyncio.Queue()

    async def __aenter__(self) -> "LockTransport":
        await self.connect()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    def _dbg(self, msg: str) -> None:
        if self._debug:
            _LOGGER.warning(msg)

    async def connect(self) -> None:
        await self._client.connect()
        # Pick key scheme by which characteristic exists.
        char_uuids = {
            c.uuid.lower()
            for s in self._client.services
            for c in s.characteristics
        }
        if CHAR_KEY_ECC in char_uuids:
            await self._ecc_handshake()
        else:
            raise TransportError(
                "lock does not expose the ECC key characteristic; "
                "only the ECC scheme is implemented"
            )
        await self._client.start_notify(CHAR_DATA, self._on_data_notify)

    async def _ecc_handshake(self) -> None:
        await self._client.start_notify(CHAR_KEY_ECC, self._on_key_notify)
        priv, pub = secp128r1.make_key()
        self._priv = priv
        await self._client.write_gatt_char(
            CHAR_KEY_ECC, microecc_pack.public_x_bytes(pub), response=False
        )
        await asyncio.sleep(CHUNK_DELAY)
        await self._client.write_gatt_char(
            CHAR_KEY_ECC, microecc_pack.public_y_bytes(pub), response=False
        )
        try:
            await asyncio.wait_for(self._handshake_done.wait(), timeout=10.0)
        except asyncio.TimeoutError as e:
            raise TransportError("ECDH handshake timed out") from e
        await self._client.stop_notify(CHAR_KEY_ECC)
        self._dbg(f"session key = {self._key.hex()}")

    def _on_key_notify(self, _char, data: bytearray) -> None:
        data = bytes(data)
        if self._lock_pub_x is None:
            self._lock_pub_x = data[:16]
            return
        self._lock_pub_y = data[:16]
        peer = microecc_pack.public_from_halves(self._lock_pub_x, self._lock_pub_y)
        shared_x = secp128r1.ecdh_shared_x(self._priv, peer)
        self._key = microecc_pack.int_to_bytes(shared_x)
        self._handshake_done.set()

    def _on_data_notify(self, _char, data: bytearray) -> None:
        raw = bytes(data)
        self._dbg(f"RX-raw {len(raw)}B {raw.hex()}")
        # Decrypt inbound in 16-byte blocks. Tolerate a non-multiple length by
        # decrypting only whole blocks (the lock pads, so this should not happen,
        # but never drop a notify by throwing inside the BLE callback).
        usable = len(raw) - (len(raw) % 16)
        if usable == 0:
            return
        try:
            plain = aes.decrypt(raw[:usable], self._key)
        except Exception as e:  # noqa: BLE001 - must not raise in callback
            self._dbg(f"decrypt error: {e}")
            return
        self._dbg(f"RX-plain {plain.hex()}")
        self._rx += plain
        self._drain_frames()

    def _drain_frames(self) -> None:
        while True:
            # Resync to the frame magic: AES zero-padding leaves trailing 0x00
            # bytes after a frame, which must be skipped before the next one.
            start = self._rx.find(frame.COMM_HEAD)
            if start < 0:
                self._rx.clear()
                return
            if start > 0:
                del self._rx[:start]
            if len(self._rx) < 3:
                return  # need the length bytes before we can judge
            payload_len = int.from_bytes(self._rx[1:3], "little")
            if payload_len == 0 or payload_len > MAX_FRAME_PAYLOAD:
                # Not a well-formed length-prefixed frame at this magic byte. This
                # happens for the firmware's malformed error reply to enroll on a
                # nonexistent user (7f 00 02 b5 05 06 ...), which even the official
                # app cannot parse (its tcb_ack stalls in APPENDING). Skip this
                # byte and resync to the next magic rather than stall forever.
                del self._rx[:1]
                continue
            if not frame.frame_complete(self._rx):
                return  # a plausible frame, just not fully arrived yet
            try:
                f, rest = frame.parse_frame(bytes(self._rx))
            except frame.FrameError:
                del self._rx[:1]
                continue
            self._rx = bytearray(rest)
            self._frames.put_nowait(f)

    async def send(self, cmd: int, params: bytes = b"") -> None:
        if self._key is None:
            raise TransportError("no session key; handshake not complete")
        raw = frame.build_frame(cmd, params)
        self._dbg(f"TX cmd={cmd} {raw.hex()}")
        enc = aes.encrypt(raw, self._key)
        for i in range(0, len(enc), WRITE_CHUNK):
            await self._client.write_gatt_char(
                CHAR_DATA, enc[i : i + WRITE_CHUNK], response=False
            )
            await asyncio.sleep(CHUNK_DELAY)

    async def next_frame(self, timeout: float = 15.0) -> frame.Frame:
        f = await asyncio.wait_for(self._frames.get(), timeout=timeout)
        self._dbg(f"RX cmd={f.cmd} status={f.status} {f.raw.hex()}")
        return f

    async def request(self, cmd: int, params: bytes = b"", timeout: float = 15.0) -> frame.Frame:
        """Send a command and wait for the matching ack (cmd | 0x80)."""
        await self.send(cmd, params)
        expected = cmd | 0x80
        while True:
            f = await self.next_frame(timeout=timeout)
            if f.cmd == expected:
                return f

    async def close(self) -> None:
        try:
            await self._client.disconnect()
        except Exception:
            pass
