"""uteclock command-line interface."""

from __future__ import annotations

import asyncio
import logging

import click

from .ble.transport import LockTransport, scan
from .session import Lock


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
