"""High-level lock operations built on the BLE transport."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from .ble.transport import LockTransport
from .protocol import frame, parse
from .protocol.commands import Ack, Cmd


class LockError(Exception):
    pass


class NotImplementedOnDevice(LockError):
    """The command's opcode is handled by the firmware, but this model reports
    it has nothing to act on (ACK_EMPTY) — i.e. the feature is compiled in but
    is a no-op on this device (e.g. a HomeKit-provisioning command on a
    Matter/non-HomeKit unit). Distinct from a wrong payload or missing auth.
    """


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

    async def get_direction(self) -> int:
        """Read the lock/latch direction (handedness). Requires admin login.

        Sends REQ_GET_LATCH (88); parses the direction byte from RES_GET_LATCH.
        Returns 0 (left) or 1 (right) — parse.DIRECTION_LEFT / DIRECTION_RIGHT.
        """
        f = await self.t.request(Cmd.GET_LATCH)
        if f.status != Ack.SUCCESS:
            raise LockError(f"get-direction failed (status {f.status}).")
        return parse.parse_latch_direction(f.params)

    async def set_direction(self, direction: int) -> None:
        """Set the lock/latch direction (handedness). Requires admin login.

        Sends REQ_SET_LATCH (87) with a single direction byte (0 = left,
        1 = right) and checks the RES_SET_LATCH status.
        """
        f = await self.t.request(Cmd.SET_LATCH, parse.set_latch_payload(direction))
        if f.status != Ack.SUCCESS:
            raise LockError(f"set-direction failed (status {f.status}).")

    async def set_ble_name(self, name: str) -> frame.Frame:
        """Set the BLE-advertised device name (cmd 0x69). EXPERIMENTAL.

        This opcode (REQ_SET_HOMEKIT_BLE_NAME) is defined in the app but never
        invoked, so both the payload shape and the authority requirement are
        unverified. We admit login is a good idea (do it before calling this),
        but we do NOT assume a particular ACK code: the app's RES_* constant for
        this command is 0x21, which does NOT follow the usual `req | 0x80` rule,
        so the transport's request() matcher (which expects 0xE9) can't be
        trusted here. Instead we send and return the FIRST frame that comes back
        (matching either 0xE9 or 0x21), or raise on timeout, so the caller can
        inspect whatever the firmware actually replies.
        """
        await self.t.send(Cmd.SET_HOMEKIT_BLE_NAME, parse.set_ble_name_payload(name))
        expected = {Cmd.SET_HOMEKIT_BLE_NAME | 0x80, 0x21}
        deadline = asyncio.get_event_loop().time() + 10.0
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise LockError(
                    "no response to set-ble-name (cmd 0x69). The firmware may not "
                    "implement this opcode, or may only accept it in a factory "
                    "provisioning mode that isn't reachable post-sale."
                )
            f = await self.t.next_frame(timeout=remaining)
            if f.cmd in expected:
                if f.status == Ack.EMPTY:
                    raise NotImplementedOnDevice(
                        "set-ble-name: the firmware handled cmd 0x69 but returned "
                        "EMPTY — this HomeKit-provisioning command is a no-op on "
                        "this model (a Matter/non-HomeKit unit). Not a payload or "
                        "auth problem; the feature simply isn't active on this device."
                    )
                if f.status not in (Ack.SUCCESS, -1):
                    raise LockError(
                        f"set-ble-name rejected (cmd 0x{f.cmd:02x}, status {f.status}). "
                        "The opcode exists but the payload or authority was wrong."
                    )
                return f
            # ignore unsolicited broadcasts (lock status/log) while we wait

    async def unlock(self, code: str, *, relock: bool = False) -> None:
        """Unlock the lock (REQ_UNLOCK=85). Requires admin login with `code`.

        Authenticates as the admin user (uid F0000000, pwd = admin code). Set
        relock=True to have the lock re-lock after its auto-lock window.
        """
        f = await self.t.request(Cmd.UNLOCK, parse.unlock_payload(code, relock=relock))
        if f.status == Ack.SUCCESS:
            return
        if f.status == Ack.BACKLOCK:
            raise LockError("unlock refused: lock is in back-lock (privacy) mode.")
        raise LockError(f"unlock failed (status {f.status}).")

    async def lock(self, code: str) -> None:
        """Throw the bolt / lock the lock (REQ_BOLTLOCK=86). Requires admin login."""
        f = await self.t.request(Cmd.BOLTLOCK, parse.bolt_lock_payload(code))
        if f.status != Ack.SUCCESS:
            raise LockError(f"lock failed (status {f.status}).")

    async def status(self) -> parse.LockStatus:
        """Read lock/bolt status + battery (REQ_LOCK_STATUS=80). Requires admin login."""
        f = await self.t.request(Cmd.LOCK_STATUS)
        if f.status != Ack.SUCCESS:
            raise LockError(f"status read failed (status {f.status}).")
        return parse.parse_lock_status(f.params)

    # --- per-user access schedules (104-111) ---------------------------------

    # A schedule read returns one of these "not set" statuses when the user has
    # no such schedule (or no such user) — a normal outcome, not a fault. The app
    # shows it as "no schedule". We map it to None; anything else raises.
    _SCHEDULE_UNSET = (Ack.FAIL, Ack.EMPTY)

    def _schedule_unset(self, f: frame.Frame, what: str) -> bool:
        if f.status == Ack.SUCCESS:
            return False
        if f.status in self._SCHEDULE_UNSET:
            return True
        raise LockError(f"get-schedule-{what} failed (status {f.status}).")

    async def get_schedule_week(self, uid: int) -> int | None:
        """Read a user's allowed-weekday bitmask, or None if not set (cmd 104)."""
        f = await self.t.request(Cmd.GET_SCHEDULE_WEEK, parse.get_schedule_payload(uid))
        if self._schedule_unset(f, "week"):
            return None
        return parse.parse_schedule_week(f.params)

    async def set_schedule_week(self, uid: int, weekday_mask: int) -> None:
        """Set a user's allowed-weekday bitmask (REQ_SET_SCHEDULE_WEEK=105).

        Bit 0 = Sunday .. bit 6 = Saturday (low 7 bits).
        """
        f = await self.t.request(
            Cmd.SET_SCHEDULE_WEEK, parse.set_schedule_week_payload(uid, weekday_mask)
        )
        if f.status != Ack.SUCCESS:
            raise LockError(f"set-schedule-week failed (status {f.status}).")

    async def get_schedule_time(self, uid: int) -> parse.ScheduleTime | None:
        """Read a user's daily allowed time window, or None if not set (cmd 106)."""
        f = await self.t.request(Cmd.GET_SCHEDULE_TIME, parse.get_schedule_payload(uid))
        if self._schedule_unset(f, "time"):
            return None
        return parse.parse_schedule_time(f.params)

    async def set_schedule_time(
        self, uid: int, start_h: int, start_m: int, end_h: int, end_m: int
    ) -> None:
        """Set a user's daily allowed time window (REQ_SET_SCHEDULE_TIME=107)."""
        f = await self.t.request(
            Cmd.SET_SCHEDULE_TIME,
            parse.set_schedule_time_payload(uid, start_h, start_m, end_h, end_m),
        )
        if f.status != Ack.SUCCESS:
            raise LockError(f"set-schedule-time failed (status {f.status}).")

    async def get_schedule_date(self, uid: int) -> parse.ScheduleDate | None:
        """Read a user's valid date range, or None if not set (cmd 108)."""
        f = await self.t.request(Cmd.GET_SCHEDULE_DATE, parse.get_schedule_payload(uid))
        if self._schedule_unset(f, "date"):
            return None
        return parse.parse_schedule_date(f.params)

    async def set_schedule_date(
        self, uid: int, start, end, times=None
    ) -> None:
        """Set a user's valid date range (REQ_SET_SCHEDULE_DATE=109).

        `start`/`end` are datetime.date. On _34 firmware (this lock) the app also
        appends a (start_h, start_m, end_h, end_m) tuple; pass `times` to match.
        """
        f = await self.t.request(
            Cmd.SET_SCHEDULE_DATE, parse.set_schedule_date_payload(uid, start, end, times)
        )
        if f.status != Ack.SUCCESS:
            raise LockError(f"set-schedule-date failed (status {f.status}).")

    async def get_schedule_num(self, uid: int) -> parse.ScheduleNum | None:
        """Read a user's schedule slot usage, or None if not set (cmd 110)."""
        f = await self.t.request(Cmd.GET_SCHEDULE_NUM, parse.get_schedule_payload(uid))
        if self._schedule_unset(f, "num"):
            return None
        return parse.parse_schedule_num(f.params)

    async def set_schedule_num(self, uid: int, num: int) -> None:
        """Set a user's schedule number/slot (REQ_SET_SCHEDULE_NUM=111)."""
        f = await self.t.request(
            Cmd.SET_SCHEDULE_NUM, parse.set_schedule_num_payload(uid, num)
        )
        if f.status != Ack.SUCCESS:
            raise LockError(f"set-schedule-num failed (status {f.status}).")

    async def get_autolock(self) -> int:
        """Read the auto-lock time in seconds (REQ_GET_AUTOLOCK=90)."""
        f = await self.t.request(Cmd.GET_AUTOLOCK)
        if f.status != Ack.SUCCESS:
            raise LockError(f"get-autolock failed (status {f.status}).")
        return parse.parse_autolock(f.params)

    async def set_autolock(self, seconds: int, *, relock: bool = False) -> None:
        """Set the auto-lock time in seconds (REQ_SET_AUTOLOCK=89)."""
        f = await self.t.request(
            Cmd.SET_AUTOLOCK, parse.set_autolock_payload(seconds, relock)
        )
        if f.status != Ack.SUCCESS:
            raise LockError(f"set-autolock failed (status {f.status}).")

    async def get_mute(self) -> bool:
        """Read mute state — True if muted (REQ_LOCK_GETMUTE=83)."""
        f = await self.t.request(Cmd.LOCK_GETMUTE)
        if f.status != Ack.SUCCESS:
            raise LockError(f"get-mute failed (status {f.status}).")
        return parse.parse_mute(f.params)

    async def set_mute(self, muted: bool) -> None:
        """Mute or unmute the lock's sounds (REQ_LOCK_SETMUTE=84)."""
        f = await self.t.request(Cmd.LOCK_SETMUTE, parse.set_mute_payload(muted))
        if f.status != Ack.SUCCESS:
            raise LockError(f"set-mute failed (status {f.status}).")

    async def delete_user(self, uid: int) -> None:
        """Delete a user and its credentials (REQ_ADMIN_DEL_PSWFP=60).

        Requires admin login. The lock treats deleting a nonexistent user as
        EMPTY, which the app accepts as success — we do the same.
        """
        f = await self.t.request(Cmd.ADMIN_DEL_PSWFP, parse.delete_user_payload(uid))
        if f.status in (Ack.SUCCESS, Ack.EMPTY):
            return
        raise LockError(f"delete-user failed (status {f.status}).")

    async def set_user_enabled(
        self, uid: int, enabled: bool, *, is_admin: bool = False
    ) -> None:
        """Enable or disable a user (REQ_DISABLE_ENABLE=63). Requires admin login."""
        state = parse.USER_ENABLE if enabled else parse.USER_DISABLE
        f = await self.t.request(
            Cmd.DISABLE_ENABLE, parse.disable_enable_payload(uid, state, is_admin)
        )
        if f.status != Ack.SUCCESS:
            raise LockError(
                f"{'enable' if enabled else 'disable'}-user failed (status {f.status})."
            )

    async def battery(self) -> int:
        """Read battery level % (REQ_READ_PLEVEL=67). Requires admin login.

        The lock answers on RES 195 (== 67|0x80, standard — confirmed live).
        """
        f = await self.t.request(Cmd.READ_PLEVEL)
        if f.status != Ack.SUCCESS:
            raise LockError(f"battery read failed (status {f.status}).")
        return parse.parse_battery(f.params)

    async def firmware_version(self) -> str:
        """Read the firmware version string (REQ_FIRMWARE_VERSION=93)."""
        f = await self.t.request(Cmd.FIRMWARE_VERSION)
        if f.status != Ack.SUCCESS:
            raise LockError(f"firmware-version read failed (status {f.status}).")
        return parse.parse_firmware_version(f.params)

    async def serial(self) -> str:
        """Read the lock serial number (REQ_READ_LOCK_SN=94)."""
        f = await self.t.request(Cmd.READ_LOCK_SN, parse.read_sn_payload())
        if f.status != Ack.SUCCESS:
            raise LockError(f"serial read failed (status {f.status}).")
        return parse.parse_serial(f.params)

    async def read_logs(
        self,
        since=None,
        max_records: int = 200,
        page: int = 10,
    ) -> list[parse.LogRecord]:
        """Read the lock's event log, newest-first (REQ_READ_LOG_BY_TIME=79).

        Requires admin login. Starts at `since` (a datetime; defaults to now)
        and reads backward in pages of `page` records, feeding the oldest
        record's timestamp back as the next page's start, until the lock
        reports EMPTY, a record's own count reaches 1 (the app's last-record
        signal), we stop making progress, or we hit `max_records`.
        """
        import datetime as _dt

        if since is None:
            since = _dt.datetime.now()
        out: list[parse.LogRecord] = []
        expected = Cmd.READ_LOG_BY_TIME | 0x80
        seen: set[tuple[int, int]] = set()  # (index, packed-ish) de-dup guard
        cursor = since
        done = False
        while not done and len(out) < max_records:
            await self.t.send(
                Cmd.READ_LOG_BY_TIME,
                parse.read_log_payload(cursor, parse.LOG_READ_BACKWARD, page),
            )
            got_this_page = 0
            while True:
                try:
                    f = await self.t.next_frame(timeout=10.0)
                except asyncio.TimeoutError:
                    done = True
                    break
                if f.cmd != expected:
                    continue
                if f.status == Ack.EMPTY:
                    done = True
                    break
                rec = parse.parse_log_record(f.params)
                if rec is None:
                    done = True
                    break
                key = (rec.index, rec.type_byte)
                if key in seen:
                    # already have this record; the page didn't advance -> stop
                    done = True
                    break
                seen.add(key)
                out.append(rec)
                got_this_page += 1
                if rec.time is not None:
                    cursor = rec.time - _dt.timedelta(seconds=1)
                if rec.remaining <= 1:  # app treats count==1 as the last record
                    done = True
                    break
                if len(out) >= max_records:
                    done = True
                    break
                if got_this_page >= page:
                    break  # page complete; issue the next request
            if got_this_page == 0:
                done = True
        return out

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
