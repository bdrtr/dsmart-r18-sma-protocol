#!/usr/bin/env python3
"""watch - command-line control tool for SMA "AB" protocol watches (e.g. DSMART R18).

Real 'AB' protocol over raw L2CAP ATT (no sudo / BlueZ / phone). No crypto auth; every
command runs in its own short session (connect + handshake + do the thing).

Usage (English names; Turkish aliases in parentheses also work):
  watch.py info                      device info + supported data keys
  watch.py battery   (batarya)       battery percent
  watch.py firmware                  firmware version
  watch.py steps     (adim)          today's steps / calories / distance
  watch.py hr        (nabiz)         live heart rate (watch must be worn)
  watch.py settime   (saat-ayarla) [YYYY-mm-dd HH:MM:SS]   set clock (default: now)
  watch.py vibrate   (titret) [sec]  FIND_WATCH (NOTE: unsupported on this firmware)
  watch.py notify    (bildirim) "TITLE" "BODY"      push an on-screen notification
  watch.py call      (cagri) ["NAME"] ["NUMBER"]    incoming-call screen + VIBRATION
  watch.py sleep     (uyku)          sleep records (stage + motion)
  watch.py spo2                      blood-oxygen history (% + time)
  watch.py hr-history (nabiz-gecmis) heart-rate history (bpm + time)
  watch.py raw-read  (raw-oku) 0xKEY read any BleKey with READ (raw hex)
  watch.py cmd AABBCC...             send a raw payload (key+flag+data hex)
"""
import sys
import struct
import time
from datetime import datetime, timedelta

from ab_l2 import (AB, handshake, _find, decode_activity, KEY_NAMES,
                   K_POWER, K_FIRMWARE, K_ACTIVITY, K_REAL_TIME_HR, K_NOTIFICATION,
                   F_UPDATE, F_READ, F_CREATE)

K_TIME = 0x0201
K_FIND_WATCH = 0x0234
K_SLEEP = 0x0505
K_BLOOD_OX = 0x0509
K_HR_HISTORY = 0x0503
CATEGORY_MESSAGE = 127
CATEGORY_INCOMING_CALL = 1

_EPOCH2000 = datetime(2000, 1, 1)
# sleep stages (BleSleep: mMode) -- SDK constants
SLEEP_STAGE = {1: "deep", 2: "light", 3: "awake", 9: "REM", 17: "start", 34: "end"}


def _ts(sec):
    return _EPOCH2000 + timedelta(seconds=sec)


def decode_series(data, label, unit, item_len=6):
    """6-byte record stream [ts BE32][value u8][pad] -- HR / SpO2 (BleHeartRate/BleBloodOxygen)."""
    if not data:
        print(f"{label}: no records (watch not worn / no measurement taken)"); return
    n = len(data) // item_len
    print(f"{label}: {n} records")
    for i in range(0, n * item_len, item_len):
        t = struct.unpack(">I", data[i:i + 4])[0]
        print(f"  {_ts(t):%Y-%m-%d %H:%M} = {data[i + 4]} {unit}")


def decode_sleep(data):
    """7-byte record stream [ts BE32][mMode][mSoft][mStrong] -- BleSleep."""
    if not data:
        print("sleep: no records (watch not worn during sleep)"); return
    n = len(data) // 7
    print(f"sleep: {n} segments")
    for i in range(0, n * 7, 7):
        t = struct.unpack(">I", data[i:i + 4])[0]
        mode, soft, strong = data[i + 4], data[i + 5], data[i + 6]
        st = SLEEP_STAGE.get(mode, f"mode{mode}")
        print(f"  {_ts(t):%m-%d %H:%M}  {st:7s} (soft={soft} strong={strong})")


# --- helpers ----------------------------------------------------------------
def _session(wait_info=False):
    ab = AB()
    handshake(ab, wait_info=wait_info)
    return ab


def _fix(s, n):
    b = s.encode("utf-8")[:n]
    return b + b"\x00" * (n - len(b))


def _bletime(t):
    return bytes([t.year - 2000, t.month, t.day, t.hour, t.minute, t.second])


def _big_read(key, label, timeout=8.0, tries=3):
    """Big read (fresh session each try): the read is the FIRST thing after the handshake.
    Because of the flow-control quirk it can go unanswered, so retry until a response
    arrives (b'' counts as a valid "no records" answer)."""
    for _ in range(tries):
        ab = _session()
        ab.send(key, F_READ)
        data = _find(ab.collect(timeout), key)
        ab.close()
        if data is not None:          # b'' = valid "no records"; None = no response
            return data
        time.sleep(0.5)
    print(f"{label}: no response ({tries} tries)")
    return None


# --- commands ---------------------------------------------------------------
def cmd_info(a):
    ab = AB()
    fr = handshake(ab, wait_info=True)   # catches the 158B device-info push
    ab.send(K_POWER, F_READ)
    fr += ab.collect(3.0)
    bat = _find(fr, K_POWER)
    info = next((f["payload"] for f in fr if len(f["payload"]) > 100), None)
    if info:
        txt = "".join(chr(b) if 32 <= b < 127 else " " for b in info)
        keys, i = [], 8
        while i + 1 < len(info) and info[i] == 0x05:
            keys.append((info[i] << 8) | info[i + 1]); i += 2
        print("device :", " ".join(txt.split()))
        print("data   :", ", ".join(KEY_NAMES.get(k, hex(k)) for k in keys))
    if bat:
        print(f"battery: {bat[0]}%")
    ab.close()


def cmd_battery(a):
    ab = _session()
    ab.send(K_POWER, F_READ)
    d = _find(ab.collect(3.0), K_POWER)
    print(f"battery = {d[0]}%" if d else "no response")
    ab.close()


def cmd_firmware(a):
    ab = _session()
    ab.send(K_FIRMWARE, F_READ)
    d = _find(ab.collect(3.0), K_FIRMWARE)
    print(f"firmware = {d[0]}.{d[1]}.{d[2]}" if d and len(d) >= 3 else "no response")
    ab.close()


def cmd_steps(a):
    d = _big_read(K_ACTIVITY, "steps")
    if d:
        decode_activity(d)


def cmd_hr(a):
    ab = _session()
    print("measuring live HR (~12s)... watch must be worn.")
    ab.send(K_REAL_TIME_HR, F_UPDATE, bytes([1]))
    d = _find(ab.collect(12.0), K_REAL_TIME_HR)
    print(f"HR = {d[-1]} bpm (raw {d.hex(' ')})" if d and len(d) else
          "no HR value (normal if the watch is not worn)")
    ab.send(K_REAL_TIME_HR, F_UPDATE, bytes([0]))
    ab.collect(1.0)
    ab.close()


def cmd_settime(a):
    when = datetime.now()
    if a:
        try:
            when = datetime.strptime(" ".join(a), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            print("date format: YYYY-mm-dd HH:MM:SS"); return
    ab = _session()
    ab.send(K_TIME, F_UPDATE, _bletime(when))
    fr = ab.collect(3.0)
    ok = _find(fr, K_TIME)
    print(f"clock set: {when:%Y-%m-%d %H:%M:%S}"
          + (f"  (ack {ok.hex(' ')})" if ok is not None else "  (no ack)"))
    ab.close()


def cmd_vibrate(a):
    sec = float(a[0]) if a else 3.0
    ab = _session()
    ab.send(K_FIND_WATCH, F_UPDATE, bytes([1]))      # start
    ab.collect(1.0)
    print(f"vibration started ({sec:.0f}s)... (NOTE: FIND_WATCH is a no-op on this firmware)")
    ab.collect(sec)
    ab.send(K_FIND_WATCH, F_UPDATE, bytes([0]))      # stop
    ab.collect(1.0)
    print("vibration stopped")
    ab.close()


def _notif(category, pkg, title, content):
    return (bytes([category]) + _bletime(datetime.now())
            + _fix(pkg, 32) + _fix(title, 32) + content.encode("utf-8")[:250])


def cmd_notify(a):
    title = a[0] if len(a) > 0 else "Reference client"
    content = a[1] if len(a) > 1 else "Hello from a third-party client"
    ab = _session()
    ab.send(K_NOTIFICATION, F_UPDATE, _notif(CATEGORY_MESSAGE, "com.whatsapp", title, content))
    ack = _find(ab.collect(4.0), K_NOTIFICATION)
    print(f"notification sent: '{title}' / '{content}'"
          + ("  (ack)" if ack is not None else ""))
    ab.close()


def cmd_call(a):
    name = a[0] if len(a) > 0 else "Caller"
    number = a[1] if len(a) > 1 else "+90 555 000 0000"
    data = _notif(CATEGORY_INCOMING_CALL, "com.android.incallui", name, number)
    ab = _session()
    ab.send(K_NOTIFICATION, F_UPDATE, data)
    ab.collect(2.0)
    ab.send(K_NOTIFICATION, F_UPDATE, data)   # call screen + vibration
    ab.collect(2.0)
    print(f"incoming call sent: '{name}' / '{number}'  (call screen + vibration)")
    ab.close()


def cmd_sleep(a):
    decode_sleep(_big_read(K_SLEEP, "sleep", timeout=8.0))


def cmd_spo2(a):
    decode_series(_big_read(K_BLOOD_OX, "SpO2", timeout=8.0), "SpO2", "%")


def cmd_hr_history(a):
    decode_series(_big_read(K_HR_HISTORY, "HR history", timeout=8.0), "HR history", "bpm")


def cmd_raw_read(a):
    if not a:
        print("usage: watch.py raw-read 0x0503"); return
    key = int(a[0], 0)
    d = _big_read(key, KEY_NAMES.get(key, hex(key)), timeout=8.0)
    if d is not None:
        print(f"{KEY_NAMES.get(key, hex(key))} ({len(d)}B): {d.hex(' ')}")


def cmd_cmd(a):
    if not a:
        print("usage: watch.py cmd 05021000...  (key2B + flag1B + data, hex)"); return
    raw = bytes.fromhex(a[0].replace(" ", ""))
    key = (raw[0] << 8) | raw[1]
    ab = _session()
    ab.send(key, raw[2], raw[3:])
    ab.show(ab.collect(5.0))
    ab.close()


COMMANDS = {
    "info": cmd_info,
    "battery": cmd_battery, "batarya": cmd_battery,
    "firmware": cmd_firmware,
    "steps": cmd_steps, "adim": cmd_steps, "adım": cmd_steps,
    "hr": cmd_hr, "nabiz": cmd_hr, "nabız": cmd_hr,
    "settime": cmd_settime, "saat-ayarla": cmd_settime,
    "vibrate": cmd_vibrate, "titret": cmd_vibrate,
    "notify": cmd_notify, "bildirim": cmd_notify,
    "call": cmd_call, "cagri": cmd_call, "çağrı": cmd_call,
    "sleep": cmd_sleep, "uyku": cmd_sleep,
    "spo2": cmd_spo2,
    "hr-history": cmd_hr_history, "nabiz-gecmis": cmd_hr_history, "nabız-geçmiş": cmd_hr_history,
    "raw-read": cmd_raw_read, "raw-oku": cmd_raw_read,
    "cmd": cmd_cmd,
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print(__doc__); return
    cmd = sys.argv[1]
    fn = COMMANDS.get(cmd)
    if not fn:
        print(f"unknown command: {cmd}\n"); print(__doc__); return
    fn(sys.argv[2:])


if __name__ == "__main__":
    main()
