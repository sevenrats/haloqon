"""Payload builders and response parsers (from ModuleLockUser* / AddFingerDelegate).

All multi-byte integers are little-endian, matching util_byte.toByteArray/byteToInt.
Parser inputs are `Frame.params` — i.e. the bytes after the command byte, starting
with the status byte at index 0 (the app's GetParam()).
"""

from __future__ import annotations

import datetime as _dt
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


# Lock/latch direction (handedness). From DirectionLockActivity.notifyChangeCheck():
# directionStatus == 0 -> left checkbox, else right. For model "Bolt" (Bolt SE /
# DeviceLockBoltF6Matter) the app does NOT invert between UI and wire — the byte on
# the wire is this value directly (the invert branch is only Bolt-F-Matter/Bolt-M/
# BOLTMISSIONWIFI).
DIRECTION_LEFT = 0
DIRECTION_RIGHT = 1


def set_latch_payload(direction: int) -> bytes:
    """REQ_SET_LATCH (cmd 87): a single direction byte (0 = left, 1 = right).

    ModuleLockSettingUBolt.set_latch appends one byte (the Java `char` cast to a
    byte) after the command.
    """
    if direction not in (DIRECTION_LEFT, DIRECTION_RIGHT):
        raise ValueError("direction must be 0 (left) or 1 (right)")
    return bytes([direction & 0xFF])


# --- lock actuation (unlock 85 / bolt-lock 86 / status 80) --------------------
#
# From ModuleLockAccess(UBolt/WiFi). Unlock/lock payload is:
#   [uid 4B LE] + [pwd 4B packed]   (append_pwd == our _packed_code; blank -> "123456")
# The WiFi autoUnlock adds a 4B timeout(30), a 0x0D byte, and a relock flag.
# We authenticate as the admin: uid = LOCK_ADMIN_UID, pwd = the admin code.


def unlock_payload(
    code: str, uid: int = LOCK_ADMIN_UID, *, timeout_s: int = 30, relock: bool = False
) -> bytes:
    """REQ_UNLOCK (85), Bolt/WiFi form: uid + packed pwd + timeout + 0x0D + relock."""
    return (
        uid.to_bytes(4, "little")
        + _packed_code(code)
        + timeout_s.to_bytes(4, "little")
        + b"\x0d"
        + bytes([1 if relock else 0])
    )


def bolt_lock_payload(code: str, uid: int = LOCK_ADMIN_UID) -> bytes:
    """REQ_BOLTLOCK (86): uid + packed pwd (ModuleLockAccessUBolt.Lock)."""
    return uid.to_bytes(4, "little") + _packed_code(code)


# --- auto-lock (89/90) and mute (83/84) ---------------------------------------


def set_autolock_payload(seconds: int, relock: bool = False) -> bytes:
    """REQ_SET_AUTOLOCK (89): seconds 2B LE + relock byte (BoltNFC form)."""
    return seconds.to_bytes(2, "little") + bytes([1 if relock else 0])


def parse_autolock(params: bytes) -> int:
    """RES_GET_AUTOLOCK (218): seconds = byteToInt2(param[1..2]) little-endian."""
    if len(params) < 3:
        raise ValueError("RES_GET_AUTOLOCK too short")
    return int.from_bytes(params[1:3], "little")


def set_mute_payload(muted: bool) -> bytes:
    """REQ_LOCK_SETMUTE (84): 1 byte — 0 = sound on, 1 = muted (app: !sound?1:0)."""
    return bytes([1 if muted else 0])


def parse_mute(params: bytes) -> bool:
    """RES_LOCK_GETMUTE (211): returns True if muted. App: onGetSound(param[1]==0),
    i.e. param[1]==0 means sound ON, so muted = param[1] != 0."""
    if len(params) < 2:
        raise ValueError("RES_LOCK_GETMUTE too short")
    return params[1] != 0


# --- user management (delete 60 / disable-enable 63) --------------------------


def delete_user_payload(uid: int) -> bytes:
    """REQ_ADMIN_DEL_PSWFP (60): a 4-byte LE user id."""
    return uid.to_bytes(4, "little")


# disableEnable(uid, state, is_admin): state 0 = enable, 1 = disable (from the
# UI's mNowStatusInt: enabled user -> set 1 to disable). is_admin = 0 for normal
# users, 1 for admin-type (user.getType()==3).
USER_ENABLE = 0
USER_DISABLE = 1


def disable_enable_payload(uid: int, state: int, is_admin: bool = False) -> bytes:
    """REQ_DISABLE_ENABLE (63): uid 4B LE + state 2B LE + is-admin 2B LE."""
    if state not in (USER_ENABLE, USER_DISABLE):
        raise ValueError("state must be 0 (enable) or 1 (disable)")
    return (
        uid.to_bytes(4, "little")
        + state.to_bytes(2, "little")
        + (1 if is_admin else 0).to_bytes(2, "little")
    )


# --- info reads (battery 67 / version 93 / serial 94) -------------------------

# REQ_READ_PLEVEL (67) replies on RES 195 (== 67|0x80, standard). The okhttp
# CipherSuite the enum used resolves to a different number, but the live lock
# answers on 195 — confirmed against a real Bolt.
RES_READ_PLEVEL = 195


def read_sn_payload() -> bytes:
    """REQ_READ_LOCK_SN (94): a single length byte 0x10 (read_sn appends 16)."""
    return b"\x10"


def parse_battery(params: bytes) -> int:
    """RES_READ_PLEVEL (196): battery level is GetParam()[1]."""
    if len(params) < 2:
        raise ValueError("RES_READ_PLEVEL too short")
    return params[1]


def _decode_ascii_field(raw: bytes) -> str:
    """Decode a firmware ASCII field: drop NULs/spaces, keep printable ASCII."""
    return "".join(chr(b) for b in raw if 0x20 < b < 0x7F)


def parse_firmware_version(params: bytes) -> str:
    """RES_FIRMWARE_VERSION (221): ASCII string in all bytes after status.

    The app hexifies then de-hexifies (convertHexToString), which round-trips to
    the raw bytes decoded as ASCII; we decode directly and strip padding.
    """
    return _decode_ascii_field(params[1:])


def parse_serial(params: bytes) -> str:
    """RES_READ_LOCK_SN (222): 16 ASCII bytes at offset 1, spaces stripped."""
    return _decode_ascii_field(params[1:17])


@dataclass
class LockStatus:
    lock_status: int  # RES params[1]: 3 == unlocked (updateStatus maps 3->1)
    bolt_status: int  # params[2]
    battery: int  # params[3], raw byte
    work_mode: int  # params[4]


def parse_lock_status(params: bytes) -> LockStatus:
    """Parse RES_LOCK_STATUS (208): [status][lock][bolt][battery][workmode].

    The app reads each as a raw byte (its parseInt(toHexString(b)) dance just
    round-trips the byte value); we take the bytes directly.
    """
    if len(params) < 5:
        raise ValueError("RES_LOCK_STATUS too short")
    return LockStatus(
        lock_status=params[1],
        bolt_status=params[2],
        battery=params[3],
        work_mode=params[4],
    )


# Device (BLE-advertised) name. EXPERIMENTAL — see Cmd.SET_HOMEKIT_BLE_NAME.
# The app's string setters (configAp/REQ_SET_WIFI_AP, bindDevice) all use a
# fixed-width, zero-padded byte buffer: getBytes() copied into offset 0 of a
# new byte[N], then append(buf, N). 32 is the app's universal string-field
# width (SN, setup-code and read-ver responses all unpack 32-byte ASCII).
BLE_NAME_FIELD_LEN = 32


def set_ble_name_payload(name: str, field_len: int = BLE_NAME_FIELD_LEN) -> bytes:
    """REQ_SET_HOMEKIT_BLE_NAME (0x69): a fixed-width, zero-padded ASCII name.

    UNVERIFIED payload shape, inferred from the app's other fixed-width string
    setters (see configAp). ASCII, no null terminator added beyond the zero
    padding; truncated to field_len if longer.
    """
    raw = name.encode("ascii")  # advertised names are ASCII; raise on non-ASCII
    if len(raw) > field_len:
        raise ValueError(f"name too long ({len(raw)} > {field_len} bytes)")
    buf = bytearray(field_len)
    buf[: len(raw)] = raw
    return bytes(buf)


def parse_latch_direction(params: bytes) -> int:
    """Parse RES_GET_LATCH (216): direction byte is GetParam()[1] == params[1].

    params[0] is the status byte (already checked SUCCESS by the caller); the
    direction value sits at index 1.
    """
    if len(params) < 2:
        raise ValueError("RES_GET_LATCH too short to contain a direction byte")
    return params[1]


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


# --- event log (REQ_READ_LOG_BY_TIME 79 / RES 207) ----------------------------
#
# From ModuleLockEvent.ReadLogByTime / doReadLog and ParserLog.
#
# The lock stores a packed 32-bit timestamp:
#   (year-2000)<<26 | month<<22 | day<<17 | hour<<12 | min<<6 | sec
# (month is 1-based, all little-endian on the wire via util_byte.toByteArray).
#
# Request payload:
#   [packed_time 4B LE][0x20][direction 1B][count 4B LE]
#   direction 0 = read backward (older records, from the given time),
#             1 = read forward (newer). The app uses count=10 per page and
#   pages by feeding the timestamp of the last record it received.
#
# Response record (offsets from the status byte params[0]):
#   [0] status  (0 = record present; 5/EMPTY = no logs / end)
#   [1:5]  count  (total remaining; app treats count==1 as the last record)
#   [5:9]  index  (log index, for paging)
#   [9:13] time   (packed 32-bit, same format)
#   [13]   type   (event type; see LOG_TYPE_NAMES)
#   [14]   info   (source/method; see LOG_INFO_NAMES, UBolt bit-7 variant)
#   [15:19] uid   (4B LE user id)

LOG_READ_BACKWARD = 0
LOG_READ_FORWARD = 1


def pack_log_time(t: _dt.datetime) -> int:
    """Pack a datetime into the lock's 32-bit log timestamp (month 1-based)."""
    return (
        ((t.year - 2000) << 26)
        | (t.month << 22)
        | (t.day << 17)
        | (t.hour << 12)
        | (t.minute << 6)
        | t.second
    )


def unpack_log_time(v: int) -> _dt.datetime | None:
    """Inverse of pack_log_time; None if the fields are out of range."""
    try:
        return _dt.datetime(
            2000 + ((v >> 26) & 0x3F),
            (v >> 22) & 0x0F,
            (v >> 17) & 0x1F,
            (v >> 12) & 0x1F,
            (v >> 6) & 0x3F,
            v & 0x3F,
        )
    except ValueError:
        return None


def read_log_payload(
    when: _dt.datetime, direction: int = LOG_READ_BACKWARD, count: int = 10
) -> bytes:
    """Build REQ_READ_LOG_BY_TIME (79) payload: time(4 LE) + 0x20 + dir + count(4 LE)."""
    if direction not in (LOG_READ_BACKWARD, LOG_READ_FORWARD):
        raise ValueError("direction must be 0 (backward) or 1 (forward)")
    return (
        pack_log_time(when).to_bytes(4, "little")
        + b"\x20"
        + bytes([direction & 0xFF])
        + count.to_bytes(4, "little")
    )


# Event types (ModuleLockEventUBolt.setData); values are the raw type byte.
LOG_TYPE_NAMES = {
    0x11: "power up",
    0x12: "wake up",
    0x1F: "overtime",
    0x21: "door open / unlock",
    0x22: "access fail",
    0x23: "lock",
    0x24: "lock fail",
    0x25: "unlock forbidden",
    0x26: "auto lock",  # UBolt overrides LOCK_LOCKED(0x26) with LOCK_AUTO_LOCK
    0x27: "unlocked",  # base ModuleLockEvent LOG_T_LOCK_UNLOCKED
    0x41: "connect",
    0x48: "set clock",
    0x4A: "test unlock",
    0x4B: "test lock",
    0x81: "admin login",
    0x82: "admin login fail",
    0x88: "user added",
    0x89: "user deleted",
    0x8A: "admin added",
    0x8B: "admin deleted",
    0x8C: "clear all",
}

# Info/source (unlock method). Bit 7 clear = base source; bit 7 set = extended
# source in the low 7 bits (INFO_* remap in ModuleLockEvent). We report the raw
# byte plus a best-effort label.
LOG_INFO_NAMES = {
    0: "password",
    1: "fingerprint",
    2: "card",
    3: "app",
    4: "Alexa",
    5: "Google",
    6: "IFTTT",
    7: "smart home",
}
LOG_INFO_EXT_NAMES = {
    8: "API",
    9: "Z-Wave",
    10: "HomeKit",
    11: "HomeKit code",
    12: "home key",
    13: "HomeKit auto-unlock",
    15: "Matter PIN",
    16: "Matter",
    19: "Matter Aliro",
}


def log_type_name(type_byte: int) -> str:
    return LOG_TYPE_NAMES.get(type_byte, f"type 0x{type_byte:02x}")


def log_info_name(info_byte: int) -> str:
    if info_byte & 0x80:
        return LOG_INFO_EXT_NAMES.get(info_byte & 0x7F, f"ext 0x{info_byte & 0x7F:02x}")
    return LOG_INFO_NAMES.get(info_byte, f"src 0x{info_byte:02x}")


@dataclass
class LogRecord:
    index: int
    time: _dt.datetime | None
    type_byte: int
    info_byte: int
    uid: int
    remaining: int  # the record's own "count" field (1 == last, per the app)

    @property
    def type_name(self) -> str:
        return log_type_name(self.type_byte)

    @property
    def info_name(self) -> str:
        return log_info_name(self.info_byte)


def parse_log_record(params: bytes) -> LogRecord | None:
    """Parse one RES_READ_LOG_BY_TIME (207) record. None on non-success/end."""
    if not params or params[0] != 0 or len(params) < 19:
        return None

    def le32(off: int) -> int:
        return int.from_bytes(params[off : off + 4], "little")

    return LogRecord(
        remaining=le32(1),
        index=le32(5),
        time=unpack_log_time(le32(9)),
        type_byte=params[13],
        info_byte=params[14],
        uid=le32(15),
    )


# --- per-user access schedules (104-111) --------------------------------------
#
# All requests start with uid (4B LE). From ModuleLockUserBoltNFC_34 /
# ModuleLockUserUBolt. Packed date is 16-bit LE: (year-2000)<<9 | month<<5 | day
# (see ModuleLockUser.getDate). Weekday is a 7-bit bitmask byte. Times are raw
# hour/minute bytes.


def _uid4(uid: int) -> bytes:
    return uid.to_bytes(4, "little")


def get_schedule_payload(uid: int) -> bytes:
    """Any REQ_GET_SCHEDULE_* (104/106/108/110): just the 4-byte LE uid."""
    return _uid4(uid)


def set_schedule_week_payload(uid: int, weekday_mask: int) -> bytes:
    """REQ_SET_SCHEDULE_WEEK (105): uid + one weekday-bitmask byte (bit0=Sun..bit6=Sat)."""
    return _uid4(uid) + bytes([weekday_mask & 0x7F])


def parse_schedule_week(params: bytes) -> int:
    """RES_GET_SCHEDULE_WEEK (232): weekday bitmask in the low 7 bits of param[1]."""
    if len(params) < 2:
        raise ValueError("RES_GET_SCHEDULE_WEEK too short")
    return params[1] & 0x7F


def set_schedule_time_payload(
    uid: int, start_h: int, start_m: int, end_h: int, end_m: int
) -> bytes:
    """REQ_SET_SCHEDULE_TIME (107): uid + start_h + start_m + end_h + end_m (bytes)."""
    return _uid4(uid) + bytes([start_h, start_m, end_h, end_m])


@dataclass
class ScheduleTime:
    start_h: int
    start_m: int
    end_h: int
    end_m: int


def parse_schedule_time(params: bytes) -> ScheduleTime:
    """RES_GET_SCHEDULE_TIME (234): param[1..4] = start hh, mm, end hh, mm."""
    if len(params) < 5:
        raise ValueError("RES_GET_SCHEDULE_TIME too short")
    return ScheduleTime(params[1], params[2], params[3], params[4])


def _pack_sched_date(d: _dt.date) -> int:
    return ((d.year - 2000) << 9) | (d.month << 5) | d.day


def _unpack_sched_date(v: int) -> _dt.date | None:
    try:
        return _dt.date(2000 + ((v >> 9) & 0xFF), (v >> 5) & 0x0F, v & 0x1F)
    except ValueError:
        return None


def set_schedule_date_payload(
    uid: int,
    start: _dt.date,
    end: _dt.date,
    times: tuple[int, int, int, int] | None = None,
) -> bytes:
    """REQ_SET_SCHEDULE_DATE (109): uid + start(2B LE) + end(2B LE).

    On _34 firmware the app also appends 4 time bytes (start_h, start_m, end_h,
    end_m); pass `times` to include them.
    """
    body = (
        _uid4(uid)
        + _pack_sched_date(start).to_bytes(2, "little")
        + _pack_sched_date(end).to_bytes(2, "little")
    )
    if times is not None:
        body += bytes(times)
    return body


@dataclass
class ScheduleDate:
    start: _dt.date | None
    end: _dt.date | None


def parse_schedule_date(params: bytes) -> ScheduleDate:
    """RES_GET_SCHEDULE_DATE (236): start packed date [1:3], end [3:5] (LE)."""
    if len(params) < 5:
        raise ValueError("RES_GET_SCHEDULE_DATE too short")
    start = _unpack_sched_date(int.from_bytes(params[1:3], "little"))
    end = _unpack_sched_date(int.from_bytes(params[3:5], "little"))
    return ScheduleDate(start=start, end=end)


def set_schedule_num_payload(uid: int, num: int) -> bytes:
    """REQ_SET_SCHEDULE_NUM (111): uid + one num byte."""
    return _uid4(uid) + bytes([num & 0xFF])


@dataclass
class ScheduleNum:
    current: int
    maximum: int


def parse_schedule_num(params: bytes) -> ScheduleNum:
    """RES_GET_SCHEDULE_NUM (238): param[1] = current, param[2] = max."""
    if len(params) < 3:
        raise ValueError("RES_GET_SCHEDULE_NUM too short")
    return ScheduleNum(current=params[1], maximum=params[2])
