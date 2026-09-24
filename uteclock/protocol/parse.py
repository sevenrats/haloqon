"""Payload builders and response parsers (from ModuleLockUser* / AddFingerDelegate).

All multi-byte integers are little-endian, matching util_byte.toByteArray/byteToInt.
Parser inputs are `Frame.params` — i.e. the bytes after the command byte, starting
with the status byte at index 0 (the app's GetParam()).
"""

from __future__ import annotations

from dataclasses import dataclass


# --- payload builders ---------------------------------------------------------

LOCK_ADMIN_UID = 0xF0000000  # DeviceLock.LOCK_ADMIIN_UID


def _packed_code(code: str) -> bytes:
    """4-byte LE numeric code with digit-count in the high nibble of byte[3]."""
    if not code.isdigit():
        raise ValueError("code must be numeric digits")
    b = bytearray(int(code).to_bytes(4, "little"))
    b[3] = ((len(code) << 4) | b[3]) & 0xFF
    return bytes(b)


def admin_login_payload(code: str) -> bytes:
    """Pack an admin code for REQ_ADMIN_LOGIN (cmd 32): 4-byte LE + length nibble."""
    return _packed_code(code)


def admin_verify_payload(code: str, uid: int = LOCK_ADMIN_UID) -> bytes:
    """REQ_ADMIN_VERIFY_ID (49): [uid 4B LE][packed code 4B].

    Used by add-device (TestRegister) to set the FIRST admin password when the
    lock has no admin credential yet (status EMPTY).
    """
    return uid.to_bytes(4, "little") + _packed_code(code)


def register_password_payload(uid: int, pin: str, user_type: int = 1) -> bytes:
    """REQ_ADMIN_REG_PSW (51): create a user with a PIN.

    Layout (from ModuleLockUser.RegisterPasswordById):
        [uid 4B LE] + [pin packed 4B LE with digit-count nibble] + [type 4B LE]
    type 3 is remapped to 1 by the app; 1 = normal keypad user.
    """
    if user_type == 3:
        user_type = 1
    return (
        uid.to_bytes(4, "little")
        + _packed_code(pin)
        + user_type.to_bytes(4, "little")
    )


def register_finger_payload(uid: int, slot: int) -> bytes:
    """REQ_REGISTER_ID_FINGER (cmd 53): [uid 4B LE][slot 4B LE]."""
    return uid.to_bytes(4, "little") + slot.to_bytes(4, "little")


def read_all_idpwd_payload(uid: int = 0) -> bytes:
    """REQ_READ_ALL_IDPWD (cmd 73): a 4-byte LE user id (0 to start enumeration)."""
    return uid.to_bytes(4, "little")


# --- response parsers ---------------------------------------------------------

@dataclass
class Counts:
    passwords: int
    fingerprints: int


def parse_counts(params: bytes) -> Counts:
    """RES_READ_IDFP_COUNT (200): [status][pwd_count LE16 @1..2][fp_count LE16 @3..4]."""
    pwd = int.from_bytes(params[1:3], "little") if len(params) >= 3 else 0
    fp = int.from_bytes(params[3:5], "little") if len(params) >= 5 else 0
    return Counts(passwords=pwd, fingerprints=fp)


@dataclass
class UserRecord:
    total: int  # total number of password users (constant across the stream)
    index: int  # 1-based position of this record in the stream
    uid: int
    pin_raw: int  # raw 4-byte PIN field (packed; includes length nibble)
    user_type: int  # 0 = normal, 1 = admin
    schedule_mask: int
    flag0: bool
    flag1: bool


def parse_user_record(params: bytes) -> UserRecord | None:
    """Parse one RES_READ_ALL_IDPWD (201) record from `params`.

    Verified against live Latch 5 Pro records. Offsets from the status byte:
      [0] status (0 = record present), [1:5] total, [5:9] index, [9:13] uid,
      [13:17] PIN (packed), [17] type, [21:25] schedule mask, [25],[26] flags.
    Returns None when status != 0 (empty/end).
    """
    if not params or params[0] != 0 or len(params) < 18:
        return None

    def le32(off: int) -> int:
        return int.from_bytes(params[off : off + 4], "little")

    flag_word = (params[26] << 8) | params[25] if len(params) >= 27 else 0
    return UserRecord(
        total=le32(1),
        index=le32(5),
        uid=le32(9),
        pin_raw=le32(13),
        user_type=params[17],
        schedule_mask=le32(21) if len(params) >= 25 else 0,
        flag0=bool(flag_word & 0x1),
        flag1=bool(flag_word & 0x2),
    )


@dataclass
class FingerCrc:
    uid: int
    crc: bytes  # 4 bytes


def parse_finger_crc(params: bytes) -> FingerCrc | None:
    """Parse one RES_READ_ALL_IDFGC (202) record.

    uid is stored little-endian in [1..4]; the 4-byte fingerprint CRC is [4..7]
    (byte 4 is shared, per the decompiled loop). Returns None on non-success.
    """
    if not params or params[0] != 0:
        return None
    if len(params) < 8:
        return None
    uid = int.from_bytes(params[1:5], "little")
    crc = bytes(params[4:8])
    return FingerCrc(uid=uid, crc=crc)


@dataclass
class EnrollProgress:
    status: int
    total: int  # scans required
    current: int  # scans done


def parse_enroll_progress(params: bytes) -> EnrollProgress:
    """Parse a RES_REGISTER_ID_FINGER (189) response.

    On status 0 (SUCCESS/progress): total = [1..4], current = [5..8].
    Soft errors (16 repeat, 17 incomplete) and hard fail (1) carry no counts.
    """
    status = params[0] if params else -1
    total = current = 0
    if status == 0 and len(params) >= 9:
        total = int.from_bytes(params[1:5], "little")
        current = int.from_bytes(params[5:9], "little")
    return EnrollProgress(status=status, total=total, current=current)
