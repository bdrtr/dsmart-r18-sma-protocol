# SMA "AB" BLE protocol (Smart Time Pro / `com.szabh.smable3`)

Reverse-engineered BLE protocol of cheap JieLi-based smartwatches driven by the
**SMA / Smart Time Pro** Android app (`com.sma.smartv3.pro`, SDK package
`com.szabh.smable3`). Documented from a live btsnoop capture + APK static analysis and
**verified on real hardware** (a *DSMART R18*, JieLi **BR28 / AC701N**).

This family of watches is **not** supported by Gadgetbridge today; this doc + the
reference client are meant to make that (or any third-party client) possible. The protocol
is device-family-wide, not specific to one model.

> Educational / interoperability research on hardware you own.

## TL;DR

- Transport: **Nordic UART Service** (NUS). Write to `6e400002`, notify on `6e400003`.
- **No crypto auth** on this channel — a trivial handshake, then plaintext commands.
- Frame: `AB | flags | len(BE16) | crc16(BE16) | payload`, `payload = [BleKey BE16][BleKeyFlag][data]`.
- A separate **RCSP** channel (`ae00`, used for OTA) *does* need auth — out of scope here,
  see [Related work](#related-work).

---

## 1. Device / chip

| | |
|---|---|
| Example device | DSMART R18 (round calling watch, green strap) |
| SoC | JieLi **BR28** = **AC701N** (`pi32v2` core, 16 MB NOR flash) |
| App | Smart Time Pro `com.sma.smartv3.pro`; BLE SDK `com.szabh.smable3` |
| Advertised name | `DSMART R18`; model string `FC2_R18_DSMART` |
| MAC OUI | `9C:B0:1D` (same address for BLE and BR/EDR — dual-mode) |

The device also exposes a JieLi **RCSP** service (`0xae00`) for firmware/OTA and a
**BR/EDR audio** side (HFP/A2DP, Class-of-Device `0x240704`). Those are separate from the
AB protocol described here.

## 2. Transport

GATT layout (value handles as seen over a raw ATT connection):

| Service | Characteristic | Handle | Props |
|---|---|---|---|
| NUS `6e400001…` | RX `6e400002…` (**write**) | `0x0006` | write / write-no-response |
| | TX `6e400003…` (**notify**) | `0x0008` | notify (CCCD `0x0009`) |
| `0000ae00…` (RCSP) | `ae01` write | `0x0082` | write-no-response |
| | `ae02` notify | `0x0084` | notify (CCCD `0x0085`) |

**Raw L2CAP ATT (no BlueZ, no root).** These dual-mode same-MAC watches make BlueZ flaky
(it keeps grabbing the BR/EDR side, or GATT comes back empty). The reference client opens a
**raw L2CAP socket on the fixed ATT channel (CID 4)** and speaks ATT directly:

- `socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP)`, then `bind`/`connect` a
  `sockaddr_l2` with `cid = 4`, `addr_type = LE public` (via `ctypes`, since Python's
  `socket.bind` rejects a raw L2CAP sockaddr).
- **The watch sends its own `Exchange MTU Request` (`02 00 02`).** Every ATT transaction
  must read until the expected opcode arrives, answering that MTU request and queueing any
  stray notifications in between — otherwise responses look "off by one".

This needed **no `sudo`** in testing (the bash sandbox could open the raw socket directly);
on a normal host it needs `CAP_NET_RAW` or root.

## 3. Frame format

```
AB | flags(1) | len(2, big-endian) | crc16(2, big-endian) | payload(len bytes)
```

| Field | Notes |
|---|---|
| `0xAB` | start byte |
| `flags` | `0x01` = command (host→watch), `0x11` = response (watch→host) |
| `len` | payload length, **big-endian u16** |
| `crc16` | **CRC-16/ARC** over the payload only (poly `0x8005` / reflected `0xA001`, init `0x0000`, refin=refout=true, xorout `0x0000`), big-endian on the wire |

```
payload = [BleKey (2 bytes, big-endian)] [BleKeyFlag (1 byte)] [data …]
```

`BleKey` is a 16-bit command id; `BleKeyFlag` is the operation. Both enums are dumped from
`com.szabh.smable3.BleKey` / `BleKeyFlag` — see [BLEKEYS.md](BLEKEYS.md) for all 300+ keys.

### BleKeyFlag

| Flag | Value | Meaning |
|---|---|---|
| `UPDATE` | `0x00` | write / set |
| `READ` | `0x10` | request a value |
| `READ_CONTINUE` | `0x11` | continue a paged read |
| `CREATE` | `0x20` | create (used by the handshake) |
| `DELETE` | `0x30` | delete |
| `RESET` | `0x40` | reset |
| `NONE` | `0xff` | — |

## 4. Handshake

One exchange, **no cryptography**:

```
host → IDENTITY(0x0301) CREATE(0x20) + <4-byte token>
watch→ IDENTITY(0x0301) flag 0x00 + 00          (00 = OK)
watch→ IDENTITY(0x0301) flag 0x00 + <~158-byte device-info push>   (arrives a few seconds later)
```

The 4-byte token from a capture (`28 46 67 c2`) is accepted as-is; it appears to be a
session/app tag with no validation. The delayed device-info push is:

```
[00][ff ff ff ff]                      header
[05xx 05xx …]                          list of supported data-record BleKeys (big-endian),
                                       e.g. 05ff 0502 0503 0504 050d 0505 050e 0509 050b
[00]"DSMART R18"[00]"9C:B0:…:2C"[00]"JL"[00]"FC2"[00]"FC2_R18_DSMART"[00] …   ASCII, NUL-separated
```

**Flow-control quirk:** after the *first* large multi-notification transfer in a session
(the device-info push, or a big data read), the watch stops answering further reads on that
connection. Reliable pattern = **one big read per fresh connect+handshake**.

## 5. Reads (`READ`, flag `0x10`)

| BleKey | Response data |
|---|---|
| `POWER` `0x0203` | 1 byte — battery % |
| `FIRMWARE_VERSION` `0x0204` | 3 bytes — `major.minor.patch` |
| `BLE_ADDRESS` `0x0205` | 6 bytes |

### Health-data records (0x05xx keys)

`READ` returns a stream of fixed-size records (back-to-back, possibly split across several
notifications — reassemble by AB frame). All timestamps are **u32 seconds since
2000-01-01 00:00:00** (local).

| BleKey | Rec. len | Layout |
|---|---|---|
| `ACTIVITY` `0x0502` | 16 | `[ts BE32][steps BE32 cumulative][calories×10⁴ BE32][distance(m)×10⁴ BE32]`, 15-min buckets |
| `HEART_RATE` `0x0503` | 6 | `[ts BE32][bpm u8][pad u8]` |
| `BLOOD_OXYGEN` `0x0509` | 6 | `[ts BE32][SpO₂% u8][pad u8]` |
| `SLEEP` `0x0505` | 7 | `[ts BE32][mode u8][soft u8][strong u8]` |

`SLEEP.mode`: `1`=deep, `2`=light, `3`=awake, `9`=REM, `17`=period-start, `34`=period-end
(from `com.szabh.smable3.entity.BleSleep`).

Accelerometer sample format (`BleGsensorData`, **if** a build streams it — this one does
**not**, see [§7](#7-firmware-quirks--negative-results)): `[type u8][X i16 LE][Y i16 LE][Z i16 LE]`.

## 6. Writes / control (`UPDATE`, flag `0x00`)

### Set time — `TIME` `0x0201`

Payload = `BleTime` (6 bytes): `[year-2000][month][day][hour][minute][second]` (all u8).
*(On the read path `BleTime.year` is little-endian u16; on this write path each field is a
plain byte. Verified: the watch clock changed.)*

### Push a notification — `NOTIFICATION` `0x0401`

```
[category u8][BleTime 6][package 32][title 32][content ≤250]
```

- `category`: `127` = app message, `1` = **incoming call**, `12` = incoming-call-with-nickname.
- `package`, `title`: **fixed 32 bytes**, UTF-8, zero-padded (title truncated to 31 + NUL).
- `content`: **variable**, UTF-8, ≤250 bytes, no terminator (ellipsised if longer).
- Field sizes / `encode()` from `BleNotification` + `BleWritable.writeStringWithFix/…`.

Verified: a `category=127` notification appears on screen; a **`category=1` (incoming call)
notification shows the call screen *and* drives the vibration motor.**

### Vibration

`FIND_WATCH` `0x0234` is **not implemented** on this firmware (`READ` returns `0x00` =
unsupported) even though the motor works (`VIBRATION` `0x020b` reads `0x01` = enabled). To
buzz the watch, send an **incoming-call notification (`category=1`)**.

## 7. Firmware quirks / negative results

Saves others time — these *look* available but are stubbed on this watch build:

- **Raw accelerometer over BLE is not available.** `GSENSOR_OUTPUT` (`0x02fa`),
  `GSENSOR_RAW` (`0x02fb`) and the `FACTORY_TEST` (`0x0609`) `GSENSOR` sub-test are all
  **acked but stream no data**. (So you can't build a PC-side "air-mouse" without custom
  firmware.)
- **RCSP** (`ae00`) `SYS_INFO_GET` returns **stubs** — RTC reads a constant
  `2020-05-15 19:55:40`, battery reads 0, storage empty. Use the AB `POWER`/time path instead.
- **BT audio is call-gated**: the watch pairs over HFP and exposes a mic source + speaker
  sink, but **audio only flows during an actual call** — both directions are silent when
  idle. No A2DP source / "BT emitter" (RCSP `BT_EMITTER_INFO` = 0) and **no local music
  player** (the watch's "music" is an AVRCP remote for the phone). All of this is a *watch*
  build of the JieLi soundbox SDK with the audio/emitter features compiled out.

## 8. Reference client

[`reference-client/`](reference-client) (Python 3, raw L2CAP; comments are in Turkish):

- `l2cap_att.py` — the raw-L2CAP **ATT transport** (`ATT` class, §2). **stdlib only.**
- `ab_l2.py` — the **AB protocol** on top of it (`AB` class: frame build/parse, CRC-16/ARC,
  handshake, collect). stdlib only.
- `watch.py` — a CLI over `ab_l2`:
  `info battery firmware steps hr hr-history spo2 sleep settime notify call vibrate raw-read cmd`
  (Turkish aliases also accepted). stdlib only.
- `rcsp_auth.py` — a JieLi **RCSP** auth + command client (device-info LTV parser) on the
  *same* `ATT` transport. The RCSP cipher is **not** reimplemented here — it imports
  `qix_ble` from
  [ElectronicCats/jieli-ble-badge-research](https://github.com/ElectronicCats/jieli-ble-badge-research)
  (set `QIX_BLE_PATH` to that repo's `tools/qix-ble/`); the AB client above needs none of that.

```sh
# battery / steps / set time / notification / incoming-call(+vibrate)
python3 watch.py battery
python3 watch.py steps
python3 watch.py notify "Title" "Body"
python3 watch.py call "Caller" "+90 …"
```

## Related work

- **JieLi RCSP auth** (the `ae00`/OTA channel cipher) — reverse-engineered by
  [ElectronicCats/jieli-ble-badge-research](https://github.com/ElectronicCats/jieli-ble-badge-research);
  verified byte-exact against this device's `libjl_auth.so`.
- **JieLi USB/UBOOT dump & flash** — [kagaimiq/jl-uboot-tool](https://github.com/kagaimiq/jl-uboot-tool)
  (already lists **BR28 / AC701N** as working).
- General JieLi firmware format / teardown — [Quarkslab](https://blog.quarkslab.com/tag/jieli.html),
  leHACK 2025 "€12 watch" talk.
- Gadgetbridge's existing (unrelated) SMA support covers only the SMA Q2/Q3 OSS-firmware
  watches, **not** this `smable3` app family.

## Status

All frame formats, the handshake, reads (battery, firmware, activity/steps, HR, SpO₂, sleep)
and writes (time, notification, incoming-call/vibrate) are **verified on real hardware**
(2026-10). The full `BleKey` enum ([BLEKEYS.md](BLEKEYS.md)) is extracted statically; only
the keys above are confirmed end-to-end.
