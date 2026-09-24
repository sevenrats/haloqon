# Ultraloq user data model — what's on the lock vs. in the cloud

Mapped from the decompiled Xthings app (`LockUserBean`, `LockUserSchedulesBean`,
the `onReadPwd`/`onReadFinCrc` sync handlers, and the TCB command table). This
separates fields the **lock actually stores and returns over BLE** from fields
that live only in **U-tec's cloud / the app** and are never on the lock.

## On-lock fields (readable/writable over BLE — what uteclock can expose)

From the `RES_READ_ALL_IDPWD` (201) record, offsets relative to the status byte:

| Field | Where | Notes |
| --- | --- | --- |
| `uid` | params[9:13] LE | 0xF0000000 = admin; 1–10 special; 11–181 normal users; 181+ another band |
| `pin` | params[13:17] | packed 4-byte code; low nibble of byte 3 is the digit count (`passwordRemoveLength` strips it) |
| `index` | params[5:9] LE | 1-based position in the stream |
| `total` | params[1:5] LE | total password users (constant across the stream) |
| `user_type` | params[17] | 0 = normal, 1 = admin; app maps type 3 → "admin-ish" |
| `attr` | params[13:17] | same 4 bytes as pin in this record (app's `i3`) |
| `schedule_mask` | params[21:25] LE | app's `iByteToInt4` |
| `flag0`, `flag1` | params[25],[26] | low two bits of the 16-bit word {[26],[25]} |

Credential existence / counts (separate commands):

| Data | Command | Response | Notes |
| --- | --- | --- | --- |
| password + fingerprint counts | `READ_IDFP_COUNT` (72) | 200 | pwd=[1:3] LE16, fp=[3:5] LE16 — **not answered by our Latch 5 Pro firmware**; enumerate directly instead |
| password users | `READ_ALL_IDPWD` (73) | 201 | streams one record per user; needs 4-byte uid payload on this firmware |
| fingerprint CRC per user | `READ_ALL_IDFGC` (74) | 202 | uid [1:5] LE, 4-byte CRC [4:8]; presence, not the template |
| fingerprint "bag" | `READ_FINGER_BAG` (75) | — | opaque blob |

Per-user schedule (each is its own command, keyed by uid):

| Field | Get command | Response | Meaning |
| --- | --- | --- | --- |
| schedule type/num | `GET_SCHEDULE_NUM` (110) | 238 | access-schedule slot count/type |
| weekly mask | `GET_SCHEDULE_WEEK` (104) | 232 | 7-bit day-of-week bitmap |
| daily time window | `GET_SCHEDULE_TIME` (106) | 234 | start/end hour+minute |
| date range | `GET_SCHEDULE_DATE` (108) | 236 | start/end date (temporary users) |

Access methods a user can have (bitmask, `LockUserBean.ACCESS_METHOD_*`):
FP=1, ACCESSCODE=2, CARD=4, APP=8, REMOTE=16.

Credential types (enroll/register commands):
- PIN: `ADMIN_REG_PSW` (51)
- fingerprint: `REGISTER_ID_FINGER` (53)
- RFID card: `REGISTER_CARD_BY_CARDID` (54)
- fob: `REGISTER_ID_FOB` (55)
- enable/disable a user: `DISABLE_ENABLE` (63)

## Cloud / app-only fields (NOT on the lock — require the U-tec account)

`LockUserBean` carries these, but the BLE sync handlers set `name=""` and never
touch email/phone/photo, because the lock does not store them. They come from
U-tec's cloud API keyed by uid, and are unavailable to a local-only tool:

- `name`, `email`, `phone` — user identity (cloud)
- `photo`, `photoBitmap`, `avatar` tags — profile image (cloud)
- `is_share`, `share_*` (share_status, share_type, share_week, share_times,
  share_start/end_date/time, share_remote, share_auto_unlock, share_smart_alert)
  — the app's user-sharing/guest system (cloud-mediated)
- `tag1`, `tag2`, `message`, `address`, `ptype` — app bookkeeping

## Implication for uteclock

A local BLE tool can expose: **uid, pin, user_type/role (normal/admin),
enabled flags, which credentials exist (pin/finger/card/fob counts + finger CRC),
and per-user schedules.** It **cannot** expose name/email/phone/photo/sharing —
those exist only in U-tec's cloud and would require logging into their account
API, which defeats the local-only goal. If you want names, the practical option
is to keep a local uid→name mapping in uteclock itself.

## BLE vs. Matter user/credential spaces (confirmed on hardware)

These are separate address spaces on this lock:

- `matter.get_lock_info` reports **`supported_credential_types: [pin]`** — only
  PIN is a Matter credential. Fingerprints/RFID are not exposed over Matter.
- Matter user indices are **dense** (1, 2, …). A BLE uid such as 11 is not a
  valid Matter index — `getUser(11)` returns InvalidCommand (133).
- PIN unlocks report a `userIndex` in Matter `lockOperation` events; **fingerprint
  unlocks report `userIndex: null`** because the credential isn't in the Matter
  table. There is no BLE command that maps a BLE uid to a Matter user index (the
  only Matter BLE commands are global enable/mode toggles).

Net: manage **PINs via Matter/HA** (attributable to users); manage **fingerprints
via uteclock over BLE** (functional, but invisible to Matter). This is a
firmware/spec boundary, not a uteclock limitation.
