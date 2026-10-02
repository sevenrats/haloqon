"""haloqon command-line interface."""

from __future__ import annotations

import asyncio
import logging

import click

from .ble.transport import LockTransport, scan
from .session import Lock, NotImplementedOnDevice


def _run(coro):
    return asyncio.run(coro)


@click.group()
@click.option("--address", "-a", help="Lock BLE address (MAC/UUID).")
@click.option("--adapter", help="Bluetooth adapter, e.g. hci0.")
@click.option("--debug", is_flag=True, help="Hex-dump frames and session key.")
@click.pass_context
def main(ctx: click.Context, address, adapter, debug):
    """Talk to an Ultraloq Latch 5 Pro over BLE."""
    logging.basicConfig(level=logging.WARNING, format="%(message)s")
    ctx.obj = {"address": address, "adapter": adapter, "debug": debug}


@main.command("scan")
@click.option("--timeout", default=8.0)
def scan_cmd(timeout):
    """Discover nearby locks."""
    for addr, name in _run(scan(timeout)):
        click.echo(f"{addr}  {name}")


def _need_address(ctx) -> str:
    addr = ctx.obj["address"]
    if not addr:
        raise click.UsageError("--address is required for this command")
    return addr


@main.command("add-user")
@click.option("--code", required=True, help="Admin code (digits).")
@click.option("--uid", type=int, default=11, help="User id to create (normal users 11-181).")
@click.option("--pin", default=None, help="8-digit PIN (random if omitted, like the app).")
@click.option("--type", "user_type", type=int, default=0, help="User type (0 = normal).")
@click.pass_context
def add_user_cmd(ctx, code, uid, pin, user_type):
    """Create a user with a PIN, the way the U-tec app does (cmd 51)."""
    import random

    addr = _need_address(ctx)
    if pin is None:
        pin = f"{random.randint(0, 99999999):08d}"

    async def go():
        async with LockTransport(addr, ctx.obj["adapter"], ctx.obj["debug"]) as t:
            lock = Lock(t)
            await lock.admin_login(code)
            await lock.add_user(uid, pin, user_type)
            click.echo(f"Created user uid={uid} pin={pin} type={user_type}")

    _run(go())


@main.command("set-admin")
@click.option("--code", required=True, help="Admin code to register (digits, e.g. 6-8).")
@click.pass_context
def set_admin_cmd(ctx, code):
    """Register the FIRST admin code on a lock that has none (e.g. Matter-only setup)."""
    addr = _need_address(ctx)

    async def go():
        async with LockTransport(addr, ctx.obj["adapter"], ctx.obj["debug"]) as t:
            await Lock(t).set_first_admin(code)
            click.echo(f"Admin code {code} registered. Use it with other commands.")

    _run(go())


@main.command("get-direction")
@click.option("--code", required=True, help="Admin/program code (digits).")
@click.pass_context
def get_direction_cmd(ctx, code):
    """Read the lock direction / handedness (Bolt SE). Requires admin login."""
    from .protocol.parse import DIRECTION_LEFT

    addr = _need_address(ctx)

    async def go():
        async with LockTransport(addr, ctx.obj["adapter"], ctx.obj["debug"]) as t:
            lock = Lock(t)
            await lock.admin_login(code)
            d = await lock.get_direction()
            name = "left" if d == DIRECTION_LEFT else "right"
            click.echo(f"Lock direction: {name} (raw={d})")

    _run(go())


@main.command("set-direction")
@click.argument("direction", type=click.Choice(["left", "right"]))
@click.option("--code", required=True, help="Admin/program code (digits).")
@click.pass_context
def set_direction_cmd(ctx, direction, code):
    """Set the lock direction / handedness (Bolt SE). Requires admin login.

    Use `left` for a left-hand door. Requires admin login.
    """
    from .protocol.parse import DIRECTION_LEFT, DIRECTION_RIGHT

    addr = _need_address(ctx)
    value = DIRECTION_LEFT if direction == "left" else DIRECTION_RIGHT

    async def go():
        async with LockTransport(addr, ctx.obj["adapter"], ctx.obj["debug"]) as t:
            lock = Lock(t)
            await lock.admin_login(code)
            await lock.set_direction(value)
            click.echo(f"Lock direction set to {direction}.")

    _run(go())


@main.command("set-ble-name")
@click.argument("name")
@click.option("--code", required=True, help="Admin/program code (digits).")
@click.pass_context
def set_ble_name_cmd(ctx, name, code):
    """Set the BLE-advertised device name (cmd 0x69). EXPERIMENTAL / UNVERIFIED.

    This opcode is defined in the U-tec app but never used by it, so the payload
    and whether the firmware accepts it at all are unconfirmed. It may need a
    factory mode we can't reach. Probing it is non-destructive but at your own
    risk. Re-scan afterwards to see whether the advertised name changed.
    """
    addr = _need_address(ctx)

    async def go():
        async with LockTransport(addr, ctx.obj["adapter"], ctx.obj["debug"]) as t:
            lock = Lock(t)
            await lock.admin_login(code)
            f = await lock.set_ble_name(name)
            click.echo(
                f"Lock accepted set-ble-name (ack cmd=0x{f.cmd:02x}, "
                f"status={f.status}). Re-scan to confirm the advertised name."
            )

    try:
        _run(go())
    except NotImplementedOnDevice as e:
        raise click.ClickException(str(e)) from e


@main.command("unlock")
@click.option("--code", required=True, help="Admin/program code (digits).")
@click.option("--relock", is_flag=True, help="Re-lock after the auto-lock window.")
@click.pass_context
def unlock_cmd(ctx, code, relock):
    """Unlock the lock (requires admin login)."""
    addr = _need_address(ctx)

    async def go():
        async with LockTransport(addr, ctx.obj["adapter"], ctx.obj["debug"]) as t:
            lock = Lock(t)
            await lock.admin_login(code)
            await lock.unlock(code, relock=relock)
            click.echo("Unlocked.")

    _run(go())


@main.command("lock")
@click.option("--code", required=True, help="Admin/program code (digits).")
@click.pass_context
def lock_cmd(ctx, code):
    """Lock the lock / throw the bolt (requires admin login)."""
    addr = _need_address(ctx)

    async def go():
        async with LockTransport(addr, ctx.obj["adapter"], ctx.obj["debug"]) as t:
            lock = Lock(t)
            await lock.admin_login(code)
            await lock.lock(code)
            click.echo("Locked.")

    _run(go())


@main.command("status")
@click.option("--code", required=True, help="Admin/program code (digits).")
@click.pass_context
def status_cmd(ctx, code):
    """Read lock/bolt status and battery (requires admin login)."""
    addr = _need_address(ctx)

    async def go():
        async with LockTransport(addr, ctx.obj["adapter"], ctx.obj["debug"]) as t:
            lock = Lock(t)
            await lock.admin_login(code)
            s = await lock.status()
            state = "unlocked" if s.lock_status == 3 else f"locked (raw={s.lock_status})"
            click.echo(
                f"lock: {state}  bolt: {s.bolt_status}  "
                f"battery: {s.battery}%  work-mode: {s.work_mode}"
            )

    _run(go())


_WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]


def _fmt_weekmask(mask: int) -> str:
    days = [_WEEKDAYS[i] for i in range(7) if mask & (1 << i)]
    return ",".join(days) if days else "(none)"


@main.command("schedule")
@click.option("--uid", type=int, required=True, help="User id.")
@click.option("--code", required=True, help="Admin/program code (digits).")
@click.pass_context
def schedule_cmd(ctx, uid, code):
    """Read a user's access schedule: weekdays, daily window, and date range."""
    addr = _need_address(ctx)

    async def go():
        async with LockTransport(addr, ctx.obj["adapter"], ctx.obj["debug"]) as t:
            lock = Lock(t)
            await lock.admin_login(code)
            # Each getter returns None when that schedule isn't set for the user.
            week = await lock.get_schedule_week(uid)
            tm = await lock.get_schedule_time(uid)
            dt = await lock.get_schedule_date(uid)
            if week is None and tm is None and dt is None:
                click.echo(f"No schedule set for uid={uid} (or no such user).")
                return
            daily = (
                f"{tm.start_h:02d}:{tm.start_m:02d}–{tm.end_h:02d}:{tm.end_m:02d}"
                if tm
                else "(not set)"
            )
            click.echo(f"weekdays: {_fmt_weekmask(week) if week is not None else '(not set)'}")
            click.echo(f"daily:    {daily}")
            click.echo(f"dates:    {f'{dt.start} .. {dt.end}' if dt else '(not set)'}")

    _run(go())


@main.command("autolock")
@click.option("--code", required=True, help="Admin/program code (digits).")
@click.option("--set", "seconds", type=int, default=None, help="Set auto-lock seconds (0 disables).")
@click.option("--relock", is_flag=True, help="Enable relock (with --set).")
@click.pass_context
def autolock_cmd(ctx, code, seconds, relock):
    """Get or set the auto-lock time (requires admin login)."""
    addr = _need_address(ctx)

    async def go():
        async with LockTransport(addr, ctx.obj["adapter"], ctx.obj["debug"]) as t:
            lock = Lock(t)
            await lock.admin_login(code)
            if seconds is None:
                click.echo(f"Auto-lock: {await lock.get_autolock()} seconds")
            else:
                await lock.set_autolock(seconds, relock=relock)
                click.echo(f"Auto-lock set to {seconds} seconds.")

    _run(go())


@main.command("mute")
@click.option("--code", required=True, help="Admin/program code (digits).")
@click.option("--set", "state", type=click.Choice(["on", "off"]), default=None,
              help="on = mute sounds, off = unmute.")
@click.pass_context
def mute_cmd(ctx, code, state):
    """Get or set the lock's mute state (requires admin login)."""
    addr = _need_address(ctx)

    async def go():
        async with LockTransport(addr, ctx.obj["adapter"], ctx.obj["debug"]) as t:
            lock = Lock(t)
            await lock.admin_login(code)
            if state is None:
                click.echo("muted" if await lock.get_mute() else "sound on")
            else:
                await lock.set_mute(state == "on")
                click.echo(f"Mute {'on' if state == 'on' else 'off'}.")

    _run(go())


@main.command("delete-user")
@click.option("--uid", type=int, required=True, help="User id to delete.")
@click.option("--code", required=True, help="Admin/program code (digits).")
@click.pass_context
def delete_user_cmd(ctx, uid, code):
    """Delete a user and its credentials (requires admin login)."""
    addr = _need_address(ctx)

    async def go():
        async with LockTransport(addr, ctx.obj["adapter"], ctx.obj["debug"]) as t:
            lock = Lock(t)
            await lock.admin_login(code)
            await lock.delete_user(uid)
            click.echo(f"Deleted user uid={uid}.")

    _run(go())


@main.command("set-user")
@click.option("--uid", type=int, required=True, help="User id.")
@click.argument("state", type=click.Choice(["enable", "disable"]))
@click.option("--code", required=True, help="Admin/program code (digits).")
@click.option("--admin", is_flag=True, help="Target is an admin-type user.")
@click.pass_context
def set_user_cmd(ctx, uid, state, code, admin):
    """Enable or disable a user (requires admin login)."""
    addr = _need_address(ctx)

    async def go():
        async with LockTransport(addr, ctx.obj["adapter"], ctx.obj["debug"]) as t:
            lock = Lock(t)
            await lock.admin_login(code)
            await lock.set_user_enabled(uid, state == "enable", is_admin=admin)
            click.echo(f"User uid={uid} {state}d.")

    _run(go())


@main.command("info")
@click.option("--code", required=True, help="Admin/program code (digits).")
@click.pass_context
def info_cmd(ctx, code):
    """Read firmware version, serial number, and battery (requires admin login)."""
    addr = _need_address(ctx)

    async def go():
        async with LockTransport(addr, ctx.obj["adapter"], ctx.obj["debug"]) as t:
            lock = Lock(t)
            await lock.admin_login(code)
            ver = await lock.firmware_version()
            sn = await lock.serial()
            batt = await lock.battery()
            click.echo(f"firmware: {ver}")
            click.echo(f"serial:   {sn}")
            click.echo(f"battery:  {batt}%")

    _run(go())


@main.command("read-logs")
@click.option("--code", required=True, help="Admin/program code (digits).")
@click.option("--max", "max_records", type=int, default=200, help="Max records to fetch.")
@click.pass_context
def read_logs_cmd(ctx, code, max_records):
    """Read the lock's event log, newest first (requires admin login)."""
    addr = _need_address(ctx)

    async def go():
        async with LockTransport(addr, ctx.obj["adapter"], ctx.obj["debug"]) as t:
            lock = Lock(t)
            await lock.admin_login(code)
            logs = await lock.read_logs(max_records=max_records)
            if not logs:
                click.echo("(no log records)")
                return
            for r in logs:
                when = r.time.isoformat(sep=" ") if r.time else "????-??-?? ??:??:??"
                uid = "" if r.uid == 0xFFFFFFFF else f" uid={r.uid}"
                click.echo(f"{when}  {r.type_name} ({r.info_name}){uid}  [#{r.index}]")

    _run(go())


@main.command("list-users")
@click.option("--code", required=True, help="Admin/program code (digits).")
@click.pass_context
def list_users_cmd(ctx, code):
    """List users and their fingerprint CRCs (requires admin login)."""
    addr = _need_address(ctx)

    async def go():
        async with LockTransport(addr, ctx.obj["adapter"], ctx.obj["debug"]) as t:
            lock = Lock(t)
            await lock.admin_login(code)
            users = await lock.list_users()
            if not users:
                click.echo("(no password users)")
            for u in users:
                click.echo(
                    f"uid={u.uid} ({u.index}/{u.total}) "
                    f"type={u.user_type} pin={u.pin_raw & 0x0fffffff:08d}"
                )
            for fc in await lock.finger_crcs():
                click.echo(f"  finger uid={fc.uid} crc={fc.crc.hex()}")

    _run(go())


@main.command("enroll-finger")
@click.option("--uid", type=int, required=True, help="Existing lock user id.")
@click.option("--slot", type=int, required=True, help="Fingerprint slot index.")
@click.option("--code", required=True, help="Admin/program code (digits).")
@click.pass_context
def enroll_finger_cmd(ctx, uid, slot, code):
    """Enroll a fingerprint onto an existing user (scan when prompted)."""
    addr = _need_address(ctx)

    async def go():
        async with LockTransport(addr, ctx.obj["adapter"], ctx.obj["debug"]) as t:
            lock = Lock(t)
            click.echo("Admin login…")
            click.echo("Place and lift your finger on the sensor repeatedly.")
            async for pr in lock.enroll_finger(uid, slot, code):
                if pr.status == 0:
                    click.echo(f"  scan {pr.current}/{pr.total}")
                elif pr.status == 16:
                    click.echo("  (same area — shift your finger)")
                elif pr.status == 17:
                    click.echo("  (partial — press more fully)")
            click.echo("Fingerprint enrolled.")

    _run(go())


if __name__ == "__main__":
    main()
