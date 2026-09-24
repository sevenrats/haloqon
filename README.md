# uteclock

A Python CLI that talks to an **Ultraloq Latch 5 Pro** directly over Bluetooth LE,
using the lock's native protocol — no Xthings app, no U-tec cloud. For
interoperability with a lock you own.

The protocol was reverse-engineered from the Xthings app and `libanvizecc.so`
(secp128r1 ECDH → AES-128 session, `0x7F` TCB frames, CRC8). See the notes under
`../scratch/xthings-re/` (git-ignored) and `docs/USER_FIELDS.md`.

## Status

Proven end to end against real hardware:

- **set-admin** — register the first admin credential on a lock that has none
- **add-user** — create a user with a PIN (as the app does)
- **list-users** — enumerate users, their PINs, and fingerprint CRCs
- **enroll-finger** — enroll a fingerprint onto an existing user (multi-scan)

Crypto, framing, and parsers are covered by offline tests (`pytest`); the BLE
layer needs a real lock in range.

## Install

```bash
cd uteclock
uv venv && . .venv/bin/activate
uv pip install -e .
```

## Use

```bash
uteclock scan

# One-time, only if the lock has no U-tec admin credential yet
# (e.g. it was set up purely over Matter):
uteclock -a <ADDRESS> set-admin --code <6-8 digits>

# Manage users / credentials (all require --code = the admin code):
uteclock -a <ADDRESS> add-user      --code <admin> [--uid 11] [--pin 12345678]
uteclock -a <ADDRESS> list-users    --code <admin>
uteclock -a <ADDRESS> enroll-finger --code <admin> --uid <existing-uid> --slot <n>
```

For `enroll-finger`, place and lift your finger on the sensor when prompted; the
CLI prints `scan X/N` until complete. Enrolling onto a uid that doesn't exist
fails within ~8s — create the user first with `add-user`.

`--debug` hex-dumps frames and prints the negotiated session key.

The admin/program code is the 6-digit **program code** printed inside the lock on
a factory-fresh lock, or the admin passcode set via `set-admin` / the U-tec app.

User id bands: admin = `0xF0000000`; normal users = 11–181.

## Fingerprints vs. Matter — important

This lock reports `supported_credential_types: [pin]` over Matter. That means:

- **PINs** can be managed and attributed to users from Home Assistant over
  Matter (`matter.set_lock_credential`, etc.), and PIN unlocks report a
  `userIndex` in Matter lock events.
- **Fingerprints are BLE-only.** The firmware does not expose fingerprint
  credentials over Matter, so a fingerprint enrolled with uteclock will unlock
  the door but will **not** appear as a Matter credential, and fingerprint
  unlocks report `userIndex: null` in Matter events. This is a firmware/spec
  boundary (Matter 1.x locks have no biometric credential management), not a
  uteclock limitation.

So uteclock is the local tool for **fingerprints** (and BLE PIN/user management);
Home Assistant/Matter remains the tool for **PINs, lock/unlock, and automations**.
The two use different user-numbering spaces — a BLE uid (e.g. 11) is not the same
as a Matter `userIndex`, and `getUser(11)` over Matter returns InvalidCommand.

## Test

```bash
. .venv/bin/activate
python -m pytest tests/ -q
```

## Notes

- **Crypto:** secp128r1 ECDH is reimplemented in pure Python; the shared-secret
  X coordinate is the AES-128 key. Coordinates are serialized **little-endian**
  (confirmed against the lock). Verified by group-theory KATs in `tests/`.
- **Transport:** frames are `0x7F | len(LE16) | cmd | params | CRC8`; commands are
  AES-128-CBC (zero IV, per-16-byte-block) written to char `0x7201`, with
  responses on the same characteristic. Trailing AES zero-padding is skipped by
  resyncing to the `0x7F` magic.
- **Firmware quirks observed:** the count command `READ_IDFP_COUNT` (72) is not
  answered; user enumeration is driven off each record's own index/total.
  Enrolling onto a nonexistent user yields a malformed error frame that even the
  official app cannot parse — uteclock skips it and fails eagerly.

## Scope / next

Deferred: delete/disable user, RFID/fob management, per-user schedules,
lock/unlock, settings, event log, and an ESP32 (`bleak-esphome`) transport
backend behind the same `ble.transport` interface.

Firmware dump over BLE is **not possible** with this protocol: there is no
memory/flash read command, and OTA is upload-only.
