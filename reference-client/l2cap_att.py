#!/usr/bin/env python3
"""Raw L2CAP ATT client for dual-mode JieLi watches — no BlueZ, no deps (stdlib only).

Opens a raw L2CAP socket on the fixed ATT channel (CID 4) and speaks ATT directly,
bypassing BlueZ (which is flaky on these same-MAC BLE+BR/EDR watches). Needs CAP_NET_RAW
(or root) on a normal host.

Key quirk handled here: the watch sends its OWN `Exchange MTU Request` (02 00 02), so every
transaction reads until the expected opcode, answering that request and queueing stray
notifications in between.

Used as the transport by both the AB-protocol client (ab_l2.py) and an RCSP client.
"""
import socket, struct, time, os, ctypes, ctypes.util

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

ADDR = "9C:B0:1D:8A:A7:2C"                      # example DSMART R18; override per device
AF_BLUETOOTH, BTPROTO_L2CAP, ATT_CID, BDADDR_LE_PUBLIC = 31, 0, 4, 1
OUR_MTU = 247

UUID_CHAR_DECL, UUID_CCCD = 0x2803, 0x2902

# ATT opcodes
OP_ERROR, OP_MTU_REQ, OP_MTU_RSP = 0x01, 0x02, 0x03
OP_RBT_REQ, OP_RBT_RSP = 0x08, 0x09
OP_WRITE_REQ, OP_WRITE_RSP = 0x12, 0x13
OP_WRITE_CMD = 0x52
OP_NOTIFY = 0x1b


def _sockaddr_l2(bdaddr, cid, btype):
    ba = bytes(int(x, 16) for x in bdaddr.split(":"))[::-1] if bdaddr else b"\x00" * 6
    return struct.pack("<HH6sHBx", AF_BLUETOOTH, 0, ba, cid, btype)


def _uuid16(val):
    if len(val) == 2:
        return struct.unpack("<H", val)[0]
    if len(val) == 16:                          # 0000xxxx-0000-1000-8000-00805f9b34fb
        return struct.unpack("<H", val[12:14])[0]
    return None


class ATT:
    """Raw L2CAP ATT client (CID 4, LE public), resilient to the watch's own MTU request."""

    def __init__(self, addr=ADDR):
        self.s = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
        fd = self.s.fileno()
        b = _sockaddr_l2(None, ATT_CID, BDADDR_LE_PUBLIC)
        if _libc.bind(fd, b, len(b)) != 0:
            e = ctypes.get_errno(); raise OSError(e, f"bind: {os.strerror(e)}")
        c = _sockaddr_l2(addr, ATT_CID, BDADDR_LE_PUBLIC)
        if _libc.connect(fd, c, len(c)) != 0:
            e = ctypes.get_errno(); raise OSError(e, f"connect: {os.strerror(e)}")
        self.mtu = 23
        self._notif = []

    def _raw_recv(self, timeout):
        self.s.settimeout(timeout)
        try:
            return self.s.recv(max(self.mtu, 256))
        except socket.timeout:
            return None

    def _handle_unsolicited(self, p):
        op = p[0]
        if op == OP_MTU_REQ:                    # watch asks for MTU -> answer it
            self.s.send(bytes([OP_MTU_RSP]) + struct.pack("<H", OUR_MTU))
            return True
        if op == OP_NOTIFY:                      # notification -> queue
            h = struct.unpack("<H", p[1:3])[0]
            self._notif.append((h, p[3:]))
            return True
        if op == OP_MTU_RSP:
            return True
        return False

    def txn(self, req, expect, timeout=4.0):
        """Send req, read until opcode==expect (or an ATT Error) arrives."""
        self.s.send(req)
        t0 = time.monotonic()
        while time.monotonic() - t0 < timeout:
            p = self._raw_recv(max(0.2, timeout - (time.monotonic() - t0)))
            if not p:
                continue
            if p[0] == expect or p[0] == OP_ERROR:
                return p
            self._handle_unsolicited(p)
        return None

    def exchange_mtu(self, want=OUR_MTU):
        p = self.txn(bytes([OP_MTU_REQ]) + struct.pack("<H", want), OP_MTU_RSP)
        if p and p[0] == OP_MTU_RSP:
            self.mtu = min(want, struct.unpack("<H", p[1:3])[0])
        return self.mtu

    def discover_chars(self):
        """Enumerate every characteristic -> [(value_handle, uuid16, props)]."""
        chars, start = [], 0x0001
        while start <= 0xffff:
            req = bytes([OP_RBT_REQ]) + struct.pack("<HHH", start, 0xffff, UUID_CHAR_DECL)
            p = self.txn(req, OP_RBT_RSP)
            if not p or p[0] != OP_RBT_RSP:
                break
            ln = p[1]; last = start
            for i in range(2, len(p) - ln + 1, ln):
                decl_h = struct.unpack("<H", p[i:i+2])[0]
                props = p[i+2]
                vh = struct.unpack("<H", p[i+3:i+5])[0]
                chars.append((vh, _uuid16(p[i+5:i+ln]), props))
                last = decl_h
            if last <= start:
                break
            start = last + 1
        return chars

    def find_cccd(self, after, before):
        req = bytes([OP_RBT_REQ]) + struct.pack("<HHH", after, before, UUID_CCCD)
        p = self.txn(req, OP_RBT_RSP)
        if p and p[0] == OP_RBT_RSP:
            return struct.unpack("<H", p[2:4])[0]
        return None

    def enable_notify(self, cccd):
        req = bytes([OP_WRITE_REQ]) + struct.pack("<H", cccd) + b"\x01\x00"
        p = self.txn(req, OP_WRITE_RSP)
        return bool(p and p[0] == OP_WRITE_RSP)

    def write_cmd(self, handle, val):           # Write Command (no response)
        self.s.send(bytes([OP_WRITE_CMD]) + struct.pack("<H", handle) + val)

    def recv_notif(self, handle, timeout=5.0):
        for i, (h, v) in enumerate(self._notif):
            if h == handle:
                return self._notif.pop(i)[1]
        t0 = time.monotonic()
        while time.monotonic() - t0 < timeout:
            p = self._raw_recv(max(0.1, timeout - (time.monotonic() - t0)))
            if not p:
                continue
            if p[0] == OP_NOTIFY:
                h = struct.unpack("<H", p[1:3])[0]
                if h == handle:
                    return p[3:]
                self._notif.append((h, p[3:]))
            else:
                self._handle_unsolicited(p)
        raise TimeoutError(f"no notification on handle 0x{handle:04x}")

    def close(self):
        try: self.s.close()
        except Exception: pass
