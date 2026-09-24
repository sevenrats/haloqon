"""High-level lock operations built on the BLE transport."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from .ble.transport import LockTransport
from .protocol import parse
from .protocol.commands import Ack, Cmd


class LockError(Exception):
    pass


class Lock:
    def __init__(self, transport: LockTransport):
        self.t = transport

    async def admin_login(self, code: str) -> None:
        f = await self.t.request(Cmd.ADMIN_LOGIN, parse.admin_login_payload(code))
        if f.status == Ack.SUCCESS:
            return
        if f.status == Ack.EMPTY:
            raise LockError(
                "lock has no admin credential set (status EMPTY). This lock was "
                "likely set up only via Matter, so no U-tec admin passcode/program "
                "code exists to authenticate against. It must be registered first "
                "(REQ_ADMIN_REG_PSW=51) or the lock factory-reset and set up via U-tec."
            )
        if f.status == Ack.ADMINFAIL:
            raise LockError("admin login rejected (wrong code).")
        raise LockError(f"admin login failed (status {f.status}).")

    async def set_first_admin(self, code: str) -> None:
        """Register the first admin password (REQ_ADMIN_VERIFY_ID=49).

        Works only when the lock has no admin credential yet (login returns
        EMPTY). This mirrors the app's add-device TestRegister step. On a lock
        that already has an admin, expect a non-success status.
        """
        f = await self.t.request(Cmd.ADMIN_VERIFY_ID, parse.admin_verify_payload(code))
        if f.status != Ack.SUCCESS:
            raise LockError(
                f"set-admin failed (status {f.status}); the lock may already have "
                "an admin credential, or is not in a state that accepts one."
            )

    async def add_user(self, uid: int, pin: str, user_type: int = 1) -> None:
        """Create a user with a PIN (REQ_ADMIN_REG_PSW=51). Requires admin login."""
        f = await self.t.request(
            Cmd.ADMIN_REG_PSW, parse.register_password_payload(uid, pin, user_type)
        )
        if f.status != Ack.SUCCESS:
            raise LockError(f"add-user failed (status {f.status}).")

    async def list_users(self, count: int | None = None) -> list[parse.UserRecord]:
        """Enumerate password users.

        Sends REQ_READ_ALL_IDPWD (73) with no payload; the lock streams one
        RES_READ_ALL_IDPWD (201) per user. Each record carries its own position:
        slot_index = current index (1-based), count_or_next = total. We stop when
        current >= total, or on a non-success (empty) record. This does not rely
        on REQ_READ_IDFP_COUNT (72), which this firmware does not answer.
        """
        users: list[parse.UserRecord] = []
        await self.t.send(Cmd.READ_ALL_IDPWD)
        expected = Cmd.READ_ALL_IDPWD | 0x80
        while True:
            try:
                f = await self.t.next_frame(timeout=10.0)
            except asyncio.TimeoutError:
                break
            if f.cmd != expected:
                continue
            rec = parse.parse_user_record(f.params)
            if rec is None:  # status != 0 -> empty/end
                break
            users.append(rec)
            if rec.total and rec.index >= rec.total:
                break
            if len(users) > 1000:
                break
        return users

    async def finger_crcs(self) -> list[parse.FingerCrc]:
        """Read per-user fingerprint CRCs; lock streams one RES_READ_ALL_IDFGC (202) each.

        Terminated by a non-success record or a short read timeout (this firmware
        does not answer the count command, so we drain until it goes quiet).
        """
        out: list[parse.FingerCrc] = []
        await self.t.send(Cmd.READ_ALL_IDFGC)
        expected = Cmd.READ_ALL_IDFGC | 0x80
        while True:
            try:
                f = await self.t.next_frame(timeout=10.0)
            except asyncio.TimeoutError:
                break
            if f.cmd != expected:
                continue
            rec = parse.parse_finger_crc(f.params)
            if rec is None:
                break
            out.append(rec)
            if len(out) > 1000:
                break
        return out

    async def enroll_finger(
        self, uid: int, slot: int, code: str
    ) -> AsyncIterator[parse.EnrollProgress]:
        """Admin-login then enroll a fingerprint, yielding progress updates.

        Yields EnrollProgress for each scan. Completion is when current == total.
        Soft errors (repeat/incomplete) are yielded too so the caller can prompt.
        """
        await self.admin_login(code)
        await self.t.send(Cmd.REGISTER_ID_FINGER, parse.register_finger_payload(uid, slot))
        expected = Cmd.REGISTER_ID_FINGER | 0x80
        first = True
        while True:
            # Once armed on a valid user, the lock immediately sends a RES 181
            # "0/N" progress frame (before any touch), then one per finger touch.
            # A nonexistent user instead yields a malformed error reply the
            # transport can't frame, so no 181 arrives -> short first-frame
            # timeout means "bad user", a longer one means "waiting for touches".
            timeout = 8.0 if first else 60.0
            try:
                f = await self.t.next_frame(timeout=timeout)
            except asyncio.TimeoutError as e:
                if first:
                    raise LockError(
                        f"user uid={uid} does not exist on the lock (no valid "
                        "enrollment response). Create it first with add-user."
                    ) from e
                raise LockError("enrollment stalled (no further scans).") from e
            if f.cmd != expected:
                continue  # ignore unsolicited lock-status/log broadcasts (208 etc.)
            first = False
            pr = parse.parse_enroll_progress(f.params)
            if pr.status == Ack.EMPTY:
                raise LockError(
                    f"user uid={uid} does not exist on the lock (status EMPTY). "
                    "Create it first with add-user."
                )
            if pr.status in (Ack.SUCCESS, Ack.FINGER_REPEAT_FAIL, Ack.FINGER_INCOMPLETE_FAIL):
                yield pr  # genuine progress or a soft retry prompt
                if pr.status == Ack.SUCCESS and pr.total and pr.current >= pr.total:
                    return
                continue
            # anything else (FAIL, FULL, OCCUPIED, TIME_OUT, ...) is fatal
            raise LockError(f"enrollment failed (status {pr.status}).")
