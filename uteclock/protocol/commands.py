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
    ADMIN_DEL_PSWFP = 60

    # Credentials
    REGISTER_ID_FINGER = 53
    REGISTER_CARD_BY_CARDID = 54
    REGISTER_ID_FOB = 55
    DISABLE_ENABLE = 63

    # Settings — latch/lock direction (handedness), Bolt/UBolt series
    SET_LATCH = 87  # REQ_SET_LATCH (tcb_base.CommCmd), payload = 1 direction byte
    GET_LATCH = 88  # REQ_GET_LATCH, no payload

    # Enumeration / reads
    READ_IDFP_COUNT = 72
    READ_ALL_IDPWD = 73
    READ_ALL_IDFGC = 74
    READ_FINGER_BAG = 75
    READ_FINGER_IMAGE = 116

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
