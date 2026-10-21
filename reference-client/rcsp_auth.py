#!/usr/bin/env python3
"""JieLi RCSP (ae00) auth + command example, over the raw-L2CAP ATT transport.

This is the *other* channel (not the AB protocol in ab_l2.py). It is used for
firmware/OTA and device info, and unlike AB it REQUIRES a challenge-response auth.

The RCSP block cipher / auth handshake is NOT reimplemented here. It is imported from
`qix_ble` in ElectronicCats/jieli-ble-badge-research (reverse-engineered there, verified
byte-exact against this device's libjl_auth.so). Point PYTHONPATH at that repo's
tools/qix-ble/ to run this. The AB client (ab_l2.py / watch.py) needs none of this.

6-step handshake over ae01 (write) / ae02 (notify), RAW (not RCSP-framed):
  1 host -> ae01: 00 + random16
  2 dev  -> ae02: 01 + enc(random)
  3 host -> ae01: 02 "pass"
  4 dev  -> ae02: 00 + challenge16
  5 host -> ae01: 01 + enc(challenge)
  6 dev  -> ae02: 02 "pass"   (auth OK)

After auth: RCSP frame = FE DC BA | flag | cmd | len(BE16) | body | EF.
  command body = [op_code_sn][payload], flag 0xC0
  response body = [status][op_code_sn][info], flag 0x00
"""
import struct, sys, os

from l2cap_att import ATT, ADDR

# RCSP auth + framing come from the badge-research qix_ble package. Set this to that repo's
# tools/qix-ble/ (or put it on PYTHONPATH yourself).
_QIX = os.environ.get("QIX_BLE_PATH")
if _QIX:
    sys.path.insert(0, _QIX)
from qix_ble.auth import JliCipher, AuthSession     # noqa: E402
from qix_ble.rcsp_frame import RcspFrame            # noqa: E402

UUID_AE01, UUID_AE02 = 0xae01, 0xae02


class L2capAe00Transport:
    """Adapter so qix_ble.AuthSession can talk over our raw-L2CAP ATT."""

    def __init__(self, att, ae01_vh, ae02_vh):
        self.att, self.ae01, self.ae02 = att, ae01_vh, ae02_vh

    def send_to_ae01(self, data):
        self.att.write_cmd(self.ae01, data)

    def recv_ae02_raw(self, timeout=5.0):
        return self.att.recv_notif(self.ae02, timeout)


def connect_and_auth(addr=ADDR):
    """L2CAP connect + discover ae01/ae02 + enable notify + RCSP auth. Returns (att, ae01, ae02)."""
    att = ATT(addr)
    att.exchange_mtu()
    chars = att.discover_chars()
    ae01 = next((vh for vh, u, p in chars if u == UUID_AE01), None)
    ae02 = next((vh for vh, u, p in chars if u == UUID_AE02), None)
    if not ae01 or not ae02:
        att.close(); raise RuntimeError("ae01/ae02 characteristics not found")
    cccd = att.find_cccd(ae02 + 1, ae02 + 3) or (ae02 + 1)
    att.enable_notify(cccd)
    AuthSession(L2capAe00Transport(att, ae01, ae02)).do_handshake()
    return att, ae01, ae02


def recv_rcsp_frame(att, handle, timeout=5.0):
    """Reassemble ae02 notifications into one RCSP frame (may be fragmented)."""
    import time
    buf = bytearray()
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        try:
            buf += att.recv_notif(handle, max(0.2, timeout - (time.monotonic() - t0)))
        except TimeoutError:
            break
        frame, rest = RcspFrame.from_bytes_stream(buf)
        if frame is not None:
            return frame
        buf = bytearray(rest)
    return None


def rcsp_cmd(att, ae01, ae02, cmd, body=b"", sn=0x01, timeout=5.0):
    """Send an RCSP command (flag 0xC0, body=[sn]+body); return the response RcspFrame or None."""
    req = RcspFrame(flag=0xC0, cmd=cmd, payload=bytes([sn]) + bytes(body)).encode()
    att.write_cmd(ae01, req)
    return recv_rcsp_frame(att, ae02, timeout=timeout)


# -- GET_TARGET_FEATURE (0x03) attribute table --------------------------------
# Source: SDK rcsp_feature.h (FEATURE_ATTR_TYPE_*) + rcsp_feature.c (value formats).
# Request: body = [op_code_sn][mask BE32][A_platform(1)]; mask=0xffffffff -> all.
# Response: body = [status][op_code_sn][LTV...]; LTV = [len][type][value], value=len-1 bytes.
FEATURE_ATTR_NAMES = {
    0: "PROTOCOL_VERSION", 1: "SYS_INFO", 2: "EDR_ADDR", 3: "PLATFORM",
    4: "FUNCTION_INFO", 5: "DEV_VERSION", 6: "SDK_TYPE", 7: "UBOOT_VERSION",
    8: "DOUBLE_PARTITION", 9: "UPDATE_STATUS", 10: "DEV_VID_PID", 11: "DEV_AUTHKEY",
    12: "DEV_PROCODE", 13: "DEV_MAX_MTU", 17: "CONNECT_BLE_ONLY",
    18: "BT_EMITTER_INFO", 19: "MD5_GAME_SUPPORT", 21: "FILE_TRANSFER_INFO",
}


def parse_ltv(info):
    """Decode an LTV stream into [(type, value)]. [len][type][value], stride=len+1."""
    out, i = [], 0
    while i < len(info):
        length = info[i]
        if length == 0 or i + 1 >= len(info):
            break
        t = info[i + 1]
        v = bytes(info[i + 2:i + 1 + length])     # value = (len-1) bytes
        out.append((t, v))
        i += length + 1
    return out


def get_target_info(att, ae01, ae02, sn=0x01):
    """Send RCSP GET_TARGET_FEATURE (0x03), parse the LTV response -> device info."""
    # body after op_code_sn = [mask BE32 = all][A_platform=0]
    r = rcsp_cmd(att, ae01, ae02, 0x03, bytes.fromhex("ffffffff00"), sn=sn)
    if not r:
        print("[!] no GET_TARGET_FEATURE response"); return False
    p = r.payload
    if len(p) < 2:
        print("[!] response too short"); return False
    status, rsn, info = p[0], p[1], p[2:]
    print(f"    status=0x{status:02x} ({'OK' if status == 0 else 'ERR'})  sn=0x{rsn:02x}")
    for t, v in parse_ltv(info):
        name = FEATURE_ATTR_NAMES.get(t, f"attr_{t}")
        print(f"      [{t:2d}] {name:16s} = {v.hex(' ')}")
    return True


def main():
    print(f"[*] connecting + auth: {ADDR}")
    att, ae01, ae02 = connect_and_auth(ADDR)
    print(f">>> AUTH OK (ae01=0x{ae01:04x} ae02=0x{ae02:04x}) <<<")
    get_target_info(att, ae01, ae02)
    att.close()


if __name__ == "__main__":
    main()
