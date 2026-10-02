"""Session-level contract tests using a fake transport.

These exercise Lock's status-handling logic (what counts as "not set" vs. an
error) without any BLE. The fake transport returns a canned Frame from request()
and records the command it was asked to send.
"""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from haloqon.protocol import frame
from haloqon.protocol.commands import Ack
from haloqon.session import Lock, LockError


class FakeTransport:
    """Minimal stand-in for LockTransport: request() returns a queued Frame."""

    def __init__(self, status: int, params: bytes = b""):
        self._status = status
        self._params = params or bytes([status])
        self.last_cmd = None
        self.last_params = None

    async def request(self, cmd, params=b"", timeout=15.0):
        self.last_cmd = int(cmd)
        self.last_params = params
        return frame.Frame(
            cmd=int(cmd) | 0x80, status=self._status, params=self._params, raw=b""
        )


def _run(coro):
    return asyncio.run(coro)


# --- schedule getters: FAIL/EMPTY -> None, SUCCESS -> value, else -> raise ----


def _week_frame_params(mask: int) -> bytes:
    return bytes([Ack.SUCCESS, mask])


def test_get_schedule_week_success():
    t = FakeTransport(Ack.SUCCESS, _week_frame_params(0x3E))
    assert _run(Lock(t).get_schedule_week(11)) == 0x3E
    assert t.last_cmd == 104  # sent the right command


@pytest.mark.parametrize("status", [Ack.FAIL, Ack.EMPTY])
def test_get_schedule_week_unset_returns_none(status):
    t = FakeTransport(status)
    assert _run(Lock(t).get_schedule_week(11)) is None


@pytest.mark.parametrize("status", [Ack.BUSY, Ack.ADMINFAIL, Ack.TIME_OUT, 99])
def test_get_schedule_week_unexpected_status_raises(status):
    t = FakeTransport(status)
    with pytest.raises(LockError):
        _run(Lock(t).get_schedule_week(11))


@pytest.mark.parametrize("status", [Ack.FAIL, Ack.EMPTY])
def test_get_schedule_time_date_num_unset_return_none(status):
    t = FakeTransport(status)
    lock = Lock(t)
    assert _run(lock.get_schedule_time(11)) is None
    assert _run(lock.get_schedule_date(11)) is None
    assert _run(lock.get_schedule_num(11)) is None


def test_get_schedule_time_unexpected_status_raises():
    t = FakeTransport(Ack.BUSY)
    with pytest.raises(LockError):
        _run(Lock(t).get_schedule_time(11))


# --- schedule writers: any non-success raises ---------------------------------


@pytest.mark.parametrize("status", [Ack.FAIL, Ack.EMPTY, Ack.BUSY])
def test_set_schedule_week_nonsuccess_raises(status):
    t = FakeTransport(status)
    with pytest.raises(LockError):
        _run(Lock(t).set_schedule_week(11, 0x3E))


def test_set_schedule_week_success():
    t = FakeTransport(Ack.SUCCESS)
    _run(Lock(t).set_schedule_week(11, 0x3E))  # should not raise
    assert t.last_cmd == 105
