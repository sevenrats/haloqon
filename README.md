# haloqon

**H**ome **A**ssistant Ultra**Loq** **On**boarder.

haloqon will eventually be a full Home Assistant integration. For now it's a
CLI you can use instead of the Xthings app. It manages U-tec Ultraloq locks
directly over Bluetooth LE, using the lock's native protocol, with no app or
cloud account.

Tested against the Ultraloq Latch 5 Pro and Bolt SE

## Install

Requires Python 3.10+.

```bash
uv sync
```

## Usage

```bash
haloqon scan
haloqon -a <ADDRESS> <command> --code <admin-code> [options]
```

| Command         | Description                                                |
| --------------- | ---------------------------------------------------------- |
| `scan`          | List nearby locks                                          |
| `set-admin`     | Set the first admin code on a lock that has none           |
| `add-user`      | Create a user with a PIN (`--uid`, `--pin`)                |
| `list-users`    | List users, PINs, and fingerprint CRCs                     |
| `enroll-finger` | Enroll a fingerprint on an existing user (`--uid`, `--slot`) |
| `get-direction` | Read lock handedness                                       |
| `set-direction` | Set lock handedness (`left` or `right`)                    |

`--code` is the admin code: either the program code printed inside a
factory-fresh lock, or one set with `set-admin` or the U-tec app.

Global options: `--adapter hci0` selects a Bluetooth adapter, and `--debug`
prints raw frames and the session key.

Normal user IDs range from 11 to 181. `enroll-finger` fails if the user
doesn't exist, so create it first with `add-user`.

## Fingerprints and Matter

The lock exposes only PIN credentials over Matter. Fingerprints enrolled with
haloqon will unlock the door, but they won't show up in Matter, and fingerprint
unlocks report `userIndex: null`. BLE user IDs and Matter `userIndex` values
are separate numbering schemes.

## Protocol

- Key exchange: secp128r1 ECDH (pure Python, little-endian coordinates). The
  shared X coordinate is the AES-128 key.
- Frames: `0x7F | len (LE16) | cmd | params | CRC8`, encrypted with AES-128-CBC
  (zero IV, per block), written to and read from characteristic `0x7201`.
- The lock ignores `READ_IDFP_COUNT` (72), so users are enumerated from each
  record's index and total.

See [docs/USER_FIELDS.md](docs/USER_FIELDS.md) for which user fields live on
the lock and which live only in the cloud.

## Tests

```bash
uv sync --extra dev
uv run pytest
```

The tests cover crypto, framing, and parsing offline. BLE commands need a lock
in range.
