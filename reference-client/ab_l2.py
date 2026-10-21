#!/usr/bin/env python3
"""SMA "AB" protocol client, over raw L2CAP ATT (no sudo, no BlueZ).

Transport = l2cap_att.ATT (raw L2CAP). The AB channel is NUS: write handle 0x0006,
notify 0x0008, CCCD 0x0009. There is NO crypto auth (unlike the RCSP channel).

Frame:  AB | flags(1) | len(2 BE) | crc16/ARC(2 BE) | payload(len)
  flags 0x01=command, 0x11=response.  payload = [BleKey(2 BE)][BleKeyFlag(1)][data]
BleKeyFlag: UPDATE/write=0x00, READ=0x10, READ_CONTINUE=0x11, CREATE=0x20,
            DELETE=0x30, RESET=0x40, NONE=0xff

Usage:  python3 ab_l2.py          (handshake + read demo)
"""
import struct, time, sys
from l2cap_att import ATT, ADDR

H_WRITE, H_NOTIFY, H_CCCD = 0x0006, 0x0008, 0x0009
HEAD, FLAG_CMD, FLAG_RSP = 0xAB, 0x01, 0x11

# BleKey (from APK com.szabh.smable3.BleKey)
K_POWER = 0x0203
K_FIRMWARE = 0x0204
K_IDENTITY = 0x0301
K_REAL_TIME_HR = 0x0224
K_REALTIME_MEAS = 0x0236
K_ACTIVITY = 0x0502
K_HEART_RATE = 0x0503
K_SLEEP = 0x0505
K_BLOOD_OX = 0x0509
K_NOTIFICATION = 0x0401
K_DEVICE_INFO = 0x023e
# BleKeyFlag
F_UPDATE, F_READ, F_READ_CONT, F_CREATE, F_DELETE, F_RESET, F_NONE = \
    0x00, 0x10, 0x11, 0x20, 0x30, 0x40, 0xff

KEY_NAMES = {
    0x0203: "POWER", 0x0204: "FIRMWARE", 0x0205: "BLE_ADDRESS", 0x0206: "USER_PROFILE",
    0x0224: "REAL_TIME_HEART_RATE", 0x0236: "REALTIME_MEASUREMENT", 0x023e: "DEVICE_INFO",
    0x0301: "IDENTITY", 0x0401: "NOTIFICATION",
    0x0502: "ACTIVITY", 0x0503: "HEART_RATE", 0x0505: "SLEEP", 0x0509: "BLOOD_OXYGEN",
    0x05ff: "DATA_ALL", 0x0517: "AVG_HEART_RATE", 0x0296: "RESTING_HEART_RATE",
}


def crc16_arc(data: bytes) -> int:
    crc = 0x0000
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if (crc & 1) else (crc >> 1)
    return crc & 0xFFFF


def build(payload: bytes, flags=FLAG_CMD) -> bytes:
    crc = crc16_arc(payload)
    n = len(payload)
    return bytes([HEAD, flags, (n >> 8) & 0xFF, n & 0xFF,
                  (crc >> 8) & 0xFF, crc & 0xFF]) + payload


def parse_stream(buf: bytearray):
    """Pull complete AB frames out of buf; deletes consumed bytes from buf."""
    out = []
    while True:
        i = buf.find(bytes([HEAD]))
        if i < 0 or len(buf) < i + 6:
            break
        flags = buf[i + 1]
        n = (buf[i + 2] << 8) | buf[i + 3]
        crc = (buf[i + 4] << 8) | buf[i + 5]
        end = i + 6 + n
        if len(buf) < end:
            break
        payload = bytes(buf[i + 6:end])
        out.append({"flags": flags, "crc_ok": crc16_arc(payload) == crc, "payload": payload})
        del buf[:end]
    return out


class AB:
    def __init__(self, addr=ADDR):
        self.att = ATT(addr)
        self.att.exchange_mtu()
        ok = self.att.enable_notify(H_CCCD)
        print(f"[*] AB connected (MTU={self.att.mtu}), notify(0x{H_CCCD:04x})={ok}")
        self.buf = bytearray()

    def send(self, key, flag, data=b""):
        payload = bytes([(key >> 8) & 0xFF, key & 0xFF, flag]) + bytes(data)
        frame = build(payload)
        name = KEY_NAMES.get(key, f"0x{key:04x}")
        print(f"  -> {name:22s} flag=0x{flag:02x}  {frame.hex(' ')}")
        self.att.write_cmd(H_WRITE, frame)

    def collect(self, timeout=4.0):
        """Collect incoming notifications for `timeout` s, decode into AB frames."""
        frames = []
        t0 = time.monotonic()
        while time.monotonic() - t0 < timeout:
            try:
                chunk = self.att.recv_notif(H_NOTIFY, max(0.2, timeout - (time.monotonic() - t0)))
            except TimeoutError:
                break
            self.buf += chunk
            frames += parse_stream(self.buf)
        return frames

    def show(self, frames):
        for fr in frames:
            p = fr["payload"]
            if len(p) >= 3:
                key = (p[0] << 8) | p[1]
                flag = p[2]
                data = p[3:]
                name = KEY_NAMES.get(key, f"0x{key:04x}")
                asc = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
                print(f"  <- {name:22s} flag=0x{flag:02x} crc={'OK' if fr['crc_ok'] else 'X'} "
                      f"({len(data)}B) {data.hex(' ')}  |{asc}|")
            else:
                print(f"  <- short payload: {p.hex(' ')}")

    def close(self):
        self.att.close()


def _find(frames, key):
    """Find the payload data of a given key in a frame list (first match)."""
    for fr in frames:
        p = fr["payload"]
        if len(p) >= 3 and ((p[0] << 8) | p[1]) == key:
            return p[3:]
    return None


def decode_activity(data):
    """ACTIVITY record: 16 bytes = [ts BE32 (2000 epoch)][steps][calories*1e4][distance*1e4 m]."""
    from datetime import datetime, timedelta
    base = datetime(2000, 1, 1)
    recs = []
    for i in range(0, len(data) - 15, 16):
        ts, steps, cal, dist = struct.unpack(">IIII", data[i:i + 16])
        recs.append((ts, steps, cal, dist))
    if not recs:
        print("    (no records)"); return
    last = max(recs, key=lambda r: r[1])          # highest cumulative step count = today's total
    first_ts = base + timedelta(seconds=recs[0][0])
    last_ts = base + timedelta(seconds=recs[-1][0])
    print(f"    {len(recs)} records (15-min buckets), {first_ts:%Y-%m-%d %H:%M} -> {last_ts:%H:%M}")
    print(f"    * TODAY: steps={last[1]}  calories={last[2]/10000:.1f} kcal  "
          f"distance={last[3]/10000:.0f} m")


def handshake(ab, wait_info=False):
    """IDENTITY CREATE + ack. If wait_info=True, also wait for / return the 158B info push."""
    ab.collect(0.1)
    ab.send(K_IDENTITY, F_CREATE, bytes.fromhex("284667c2"))
    fr, t0 = [], time.monotonic()
    while time.monotonic() - t0 < (9.0 if wait_info else 1.5):
        fr += ab.collect(1.0)
        if not wait_info and _find(fr, K_IDENTITY) is not None:
            break
        if wait_info and any(len(f["payload"]) > 100 for f in fr):
            break
    return fr


# NOTE: after the FIRST large transfer in a session (the 158B device-info push or an
# ACTIVITY stream) the watch stops answering further reads on that connection. So each big
# read is done in its own short session (connecting is cheap, ~2 s).

def main():
    # -- Session 1: device info + battery + firmware (small, fast reads) --
    print("=== Session 1: device info / battery / firmware ===")
    ab = AB()
    fr = handshake(ab, wait_info=True)
    print("[handshake]", "OK" if _find(fr, K_IDENTITY) == b"\x00" else "?")
    info = next((f["payload"] for f in fr if len(f["payload"]) > 100), None)
    if info:
        txt = "".join(chr(b) if 32 <= b < 127 else " " for b in info)
        keys, i = [], 8
        while i + 1 < len(info) and info[i] == 0x05:
            keys.append((info[i] << 8) | info[i + 1]); i += 2
        print(f"  device: {' '.join(txt.split())}")
        print(f"  supported data keys: {', '.join(KEY_NAMES.get(k, hex(k)) for k in keys)}")
    ab.close()

    ab = AB()
    handshake(ab)
    ab.send(K_POWER, F_READ)
    d = _find(ab.collect(3.0), K_POWER)
    print(f"  * BATTERY = {d[0]}%" if d else "  battery: no response")
    ab.send(K_FIRMWARE, F_READ)
    d = _find(ab.collect(3.0), K_FIRMWARE)
    print(f"  * FIRMWARE = {d[0]}.{d[1]}.{d[2]}" if d and len(d) >= 3 else "  fw: no response")
    ab.close()

    # -- Session 2: today's activity (big read, on its own) --
    print("\n=== Session 2: today's activity ===")
    ab = AB()
    handshake(ab)
    ab.send(K_ACTIVITY, F_READ)
    d = _find(ab.collect(8.0), K_ACTIVITY)
    if d:
        decode_activity(d)
    else:
        print("  (no response)")
    ab.close()

    # -- Session 3: real-time heart rate --
    print("\n=== Session 3: real-time heart rate ===")
    print("  NOTE: needs the watch worn (skin contact) for a real value.")
    ab = AB()
    handshake(ab)
    ab.send(K_REAL_TIME_HR, F_UPDATE, bytes([1]))
    d = _find(ab.collect(12.0), K_REAL_TIME_HR)
    if d and len(d) >= 1:
        print(f"  * LIVE HR = {d[-1]} bpm  (raw {d.hex(' ')})")
    else:
        print("  (no HR value - normal if the watch is not on a wrist)")
    ab.send(K_REAL_TIME_HR, F_UPDATE, bytes([0]))
    ab.collect(1.0)
    ab.close()
    print("\n[*] done.")


if __name__ == "__main__":
    main()
