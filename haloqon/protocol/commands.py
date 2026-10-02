"""Command codes and ACK status constants (from tcb_base.java / tcb_ack.java).

Request codes are the raw command byte. The lock's response code is the request
code OR 0x80 (see frame.ACK_MASK), e.g. ADMIN_LOGIN 32 -> response 160.
"""

from __future__ import annotations

from enum import IntEnum


class Cmd(IntEnum):
    # Admin / session
    ADMIN_LOGIN = 32
    ADMIN_LOGOUT = 33
    ADMIN_VERIFY_ID = 49
    ADMIN_REG_PSW = 51
    ADMIN_REG_FP = 52
    ADMIN_DEL_PSWFP = 60  # REQ_ADMIN_DEL_PSWFP, delete a user (payload = uid 4B LE)
    DISABLE_ENABLE = 63  # REQ_DISABLE_ENABLE, uid + 2B state + 2B is-admin

    # Credentials
    REGISTER_ID_FINGER = 53
    REGISTER_CARD_BY_CARDID = 54
    REGISTER_ID_FOB = 55

    # Actuation
    LOCK_STATUS = 80  # REQ_LOCK_STATUS, no payload -> RES 208
    UNLOCK = 85  # REQ_UNLOCK, payload = uid + pwd (+ timeout/flags on Bolt/WiFi)
    BOLTLOCK = 86  # REQ_BOLTLOCK, payload = uid + pwd

    # Info reads
    READ_PLEVEL = 67  # REQ_READ_PLEVEL, no payload -> RES 196 (battery)
    FIRMWARE_VERSION = 93  # REQ_FIRMWARE_VERSION, no payload -> RES 221
    READ_LOCK_SN = 94  # REQ_READ_LOCK_SN, payload = one byte 0x10 -> RES 222

    # Settings
    LOCK_GETMUTE = 83  # REQ_LOCK_GETMUTE, no payload -> RES 211
    LOCK_SETMUTE = 84  # REQ_LOCK_SETMUTE, payload = 1 byte (0 = sound on, 1 = mute)
    SET_AUTOLOCK = 89  # REQ_SET_AUTOLOCK, payload = seconds 2B LE + relock byte
    GET_AUTOLOCK = 90  # REQ_GET_AUTOLOCK, no payload -> RES 218

    # Settings — latch/lock direction (handedness), Bolt/UBolt series
    SET_LATCH = 87  # REQ_SET_LATCH (tcb_base.CommCmd), payload = 1 direction byte
    GET_LATCH = 88  # REQ_GET_LATCH, no payload

    # Device (BLE-advertised) name. EXPERIMENTAL / UNVERIFIED: this opcode is
    # defined in tcb_base.CommCmd (REQ_SET_HOMEKIT_BLE_NAME = 0x69, ACK
    # RES_SET_HOMEKIT_BLE_NAME = 0x21) but is never invoked anywhere in the
    # decompiled U-tec app. It sits in the factory/HomeKit-provisioning command
    # cluster, so it may require admin authority or a factory mode we can't reach
    # post-sale. Payload shape below is inferred from the app's other string
    # setters, not confirmed. Response ack is 0x69 | 0x80 = 0xE9.
    SET_HOMEKIT_BLE_NAME = 0x69

    # Enumeration / reads
    READ_IDFP_COUNT = 72
    READ_ALL_IDPWD = 73
    READ_ALL_IDFGC = 74
    READ_FINGER_BAG = 75
    READ_FINGER_IMAGE = 116

    # Event log. REQ_READ_LOG_BY_TIME streams one RES (207) record per notify.
    READ_LOG_BY_TIME = 79

    # Per-user access schedules (payload starts with uid 4B LE).
    GET_SCHEDULE_WEEK = 104  # -> RES 232; body = weekday bitmask byte
    SET_SCHEDULE_WEEK = 105  # uid + 1 bitmask byte
    GET_SCHEDULE_TIME = 106  # -> RES 234; body = start hh,mm + end hh,mm
    SET_SCHEDULE_TIME = 107  # uid + start_hh + start_mm + end_hh + end_mm
    GET_SCHEDULE_DATE = 108  # -> RES 236; body = start(2B) + end(2B) packed dates
    SET_SCHEDULE_DATE = 109  # uid + start(2B) + end(2B) [+ 4 time bytes on _34]
    GET_SCHEDULE_NUM = 110  # -> RES 238; body = current, max
    SET_SCHEDULE_NUM = 111  # uid + num byte

    def response(self) -> int:
        """The response (ack) code the lock replies with for this request."""
        return int(self) | 0x80


class Ack(IntEnum):
    """First status byte of a response payload (tcb_ack.java)."""

    SUCCESS = 0
    FAIL = 1
    CONT = 2
    FULL = 4
    EMPTY = 5
    BUSY = 6
    TIME_OUT = 8
    OCCUPIED = 11
    BACKLOCK = 15
    FINGER_REPEAT_FAIL = 16
    FINGER_INCOMPLETE_FAIL = 17
    # signed-byte values from the app, as unsigned:
    ADMINFAIL = 0xF0  # -16
    USER_DISABLED = 0xF4  # -12
    OFFLINE = 0xFF  # -1
