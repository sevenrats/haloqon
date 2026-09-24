"""TCB frame build/parse for the U-tec lock protocol.

Wire format (plaintext, before AES):
    [0]      = 0x7F           magic (COMM_HEAD)
    [1..2]   = payload_len    little-endian, = (total_len - 3) = cmd + params + crc
    [3]      = command byte
    [4..]    = params
    [last]   = CRC8 over bytes[3:last]   (table below; matches tcb_base.java)

GetPackageLen() in the app = payload_len + 3, i.e. the full frame length including
magic and the 2 length bytes. Numeric fields are little-endian.
"""

from __future__ import annotations

from dataclasses import dataclass

COMM_HEAD = 0x7F
ACK_MASK = 0x80

# Verbatim from tcb_base.java CRC8Table (clean numeric copy cross-checked against
# the maeneak/utecio project). Do not edit.
CRC8_TABLE = [
    0, 94, 188, 226, 97, 63, 221, 131, 194, 156, 126, 32, 163, 253, 31, 65,
    157, 195, 33, 127, 252, 162, 64, 30, 95, 1, 227, 189, 62, 96, 130, 220,
    35, 125, 159, 193, 66, 28, 254, 160, 225, 191, 93, 3, 128, 222, 60, 98,
    190, 224, 2, 92, 223, 129, 99, 61, 124, 34, 192, 158, 29, 67, 161, 255,
    70, 24, 250, 164, 39, 121, 155, 197, 132, 218, 56, 102, 229, 187, 89, 7,
    219, 133, 103, 57, 186, 228, 6, 88, 25, 71, 165, 251, 120, 38, 196, 154,
    101, 59, 217, 135, 4, 90, 184, 230, 167, 249, 27, 69, 198, 152, 122, 36,
    248, 166, 68, 26, 153, 199, 37, 123, 58, 100, 134, 216, 91, 5, 231, 185,
    140, 210, 48, 110, 237, 179, 81, 15, 78, 16, 242, 172, 47, 113, 147, 205,
    17, 79, 173, 243, 112, 46, 204, 146, 211, 141, 111, 49, 178, 236, 14, 80,
    175, 241, 19, 77, 206, 144, 114, 44, 109, 51, 209, 143, 12, 82, 176, 238,
    50, 108, 142, 208, 83, 13, 239, 177, 240, 174, 76, 18, 145, 207, 45, 115,
    202, 148, 118, 40, 171, 245, 23, 73, 8, 86, 180, 234, 105, 55, 213, 139,
    87, 9, 235, 181, 54, 104, 138, 212, 149, 203, 41, 119, 244, 170, 72, 22,
    233, 183, 85, 11, 136, 214, 52, 106, 43, 117, 151, 201, 74, 20, 246, 168,
    116, 42, 200, 150, 21, 75, 169, 247, 182, 232, 10, 84, 215, 137, 107, 53,
]


def crc8(data: bytes) -> int:
    """CRC8 over the given bytes (the app runs this over frame bytes[3:])."""
    crc = 0
    for byte in data:
        crc = CRC8_TABLE[(crc ^ byte) & 0xFF]
    return crc & 0xFF


def build_frame(cmd: int, params: bytes = b"") -> bytes:
    """Build a complete plaintext TCB frame for the given command + params."""
    body = bytes([cmd & 0xFF]) + params  # bytes that the CRC covers (from index 3)
    payload_len = len(body) + 1  # + CRC byte; == write_pos-2 in the app
    header = bytes([COMM_HEAD]) + payload_len.to_bytes(2, "little")
    frame = header + body
    return frame + bytes([crc8(body)])


@dataclass(frozen=True)
class Frame:
    cmd: int
    status: int  # first param byte (ret status), or -1 if absent
    params: bytes  # everything after the command byte, excluding the trailing CRC
    raw: bytes

    @property
    def is_ack(self) -> bool:
        return bool(self.cmd & ACK_MASK)

    @property
    def req_cmd(self) -> int:
        """The request command this ack corresponds to (cmd with ACK bit cleared)."""
        return self.cmd & ~ACK_MASK


class FrameError(ValueError):
    pass


def parse_frame(data: bytes) -> tuple[Frame, bytes]:
    """Parse one frame from the front of `data`.

    Returns (frame, remaining_bytes). Raises FrameError on bad magic/CRC or if
    the buffer does not yet hold a complete frame (caller should read more).
    """
    if len(data) < 4:
        raise FrameError("incomplete: need at least 4 bytes")
    if data[0] != COMM_HEAD:
        raise FrameError(f"bad magic 0x{data[0]:02x}")
    payload_len = int.from_bytes(data[1:3], "little")
    total = payload_len + 3  # magic + 2 len bytes + payload
    # Sanity: real frames are well under the BLE MTU. A wild length means the
    # buffer is desynced (stray byte / mid-frame magic); reject so the caller
    # resyncs past this magic byte instead of waiting for 512+ bytes forever.
    if payload_len == 0 or payload_len > 256:
        raise FrameError(f"implausible payload_len {payload_len}")
    if len(data) < total:
        raise FrameError("incomplete: waiting for more bytes")
    body = data[3 : total - 1]  # cmd + params (CRC-covered region)
    crc = data[total - 1]
    if crc8(body) != crc:
        raise FrameError(f"CRC mismatch: got 0x{crc:02x}")
    cmd = body[0]
    params = body[1:]
    status = params[0] if params else -1
    return Frame(cmd=cmd, status=status, params=params, raw=data[:total]), data[total:]


def frame_complete(data: bytes) -> bool:
    """True if `data` contains at least one full frame."""
    if len(data) < 4 or data[0] != COMM_HEAD:
        return False
    payload_len = int.from_bytes(data[1:3], "little")
    if payload_len == 0 or payload_len > 256:
        return False
    return len(data) >= payload_len + 3
