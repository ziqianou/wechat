#!/usr/bin/env python3
"""
Reassemble TCP flows from a pcap and parse WeChat mmtls records / HTTP framing.
Usage: python3 pcap_mmtls.py <file.pcap> [filter_ip]
"""
import sys, struct
from collections import defaultdict
from mmtls_parser import parse_records, parse_http, MMTLS_VERSION

class PcapReader:
    def __init__(self, path):
        self.f = open(path, "rb")
        hdr = self.f.read(24)
        magic, vmaj, vmin, tz, sig, snaplen, net = struct.unpack("<IHHiIII", hdr)
        self.linktype = net
        self.pcapng = False
        self.cur = []
    def packets(self):
        while True:
            rec = self.f.read(16)
            if not rec:
                break
            if len(rec) < 16:
                break
            ts_s, ts_us, cap, orig = struct.unpack("<IIII", rec)
            data = self.f.read(cap)
            if len(data) < cap:
                break
            yield (ts_s, ts_us), data

def parse_eth(data):
    if len(data) < 14:
        return None, None, None, None
    eth = data[14:]
    ihl = (eth[0] & 0x0f) * 4
    if eth[0] >> 4 != 4:
        return None, None, None, None
    total = struct.unpack(">H", eth[2:4])[0]
    proto = eth[9]
    if proto != 6:
        return None, None, None, None
    tcp = eth[ihl:]
    off = (tcp[12] >> 4) * 4
    sport, dport = struct.unpack(">HH", tcp[0:4])
    seq, ack = struct.unpack(">II", tcp[4:12])
    flags = tcp[13]
    src = ".".join(map(str, eth[12:16]))
    dst = ".".join(map(str, eth[16:20]))
    payload = tcp[off:]
    return (src, sport, dst, dport), seq, flags, payload

def parse_sll2(data):
    # Linux cooked v2
    proto = struct.unpack(">H", data[0:2])[0]
    if proto != 0x0800:
        return None, None, None, None
    ihl = (data[16] & 0x0f) * 4
    if data[16] >> 4 != 4:
        return None, None, None, None
    pproto = data[23]
    if pproto != 6:
        return None, None, None, None
    tcp = data[16 + ihl:]
    off = (tcp[12] >> 4) * 4
    sport, dport = struct.unpack(">HH", tcp[0:4])
    seq, ack = struct.unpack(">II", tcp[4:12])
    flags = tcp[13]
    src = ".".join(map(str, data[26:30]))
    dst = ".".join(map(str, data[30:34]))
    payload = tcp[off:]
    return (src, sport, dst, dport), seq, flags, payload

def reassemble(path, filter_ip=None):
    """Return dict: (dir_key) -> bytearray stream"""
    pr = PcapReader(path)
    conns = {}
    order = []
    for (ts, _), data in pr.packets():
        if pr.linktype == 1:      # EN10MB
            parsed = parse_eth(data)
        elif pr.linktype == 276:  # LINUX_SLL2
            parsed = parse_sll2(data)
        else:
            continue
        if parsed[0] is None:
            continue
        (src, sport, dst, dport), seq, flags, payload = parsed
        if filter_ip and filter_ip not in (src, dst):
            continue
        if sport > dport:
            skey = ("C", src, dst, sport, dport)
        else:
            skey = ("S", dst, src, dport, sport)
        ck = skey[1:]
        if ck not in conns:
            conns[ck] = {}
            order.append(ck)
        conns[ck].setdefault(skey[0], []).append((seq, payload))
    for ck in order:
        # find client tuple = endpoint with higher local port
        cdir = conns[ck]
        # ck = (client, server, cport, sport)
        cl, sv, cp, sp = ck
        cbuf = bytearray()
        sbuf = bytearray()
        for dirn, pkts in (("C", cdir.get("C", [])), ("S", cdir.get("S", []))):
            pkts.sort(key=lambda x: x[0])
            for seq, payload in pkts:
                if dirn == "C":
                    cbuf.extend(payload)
                else:
                    sbuf.extend(payload)
        label = f"CLIENT {cl}:{cp} -> SERVER {sv}:{sp}"
        yield label, bytes(cbuf), bytes(sbuf)

def main():
    path = sys.argv[1]
    fip = sys.argv[2] if len(sys.argv) > 2 else None
    print(f"=== flows in {path} ===")
    for label, cbuf, sbuf in reassemble(path, fip):
        print(f"\n----- flow {label}  C={len(cbuf)} S={len(sbuf)} bytes -----")
        print("  -- CLIENT -> SERVER --")
        if cbuf:
            if b"\r\n\r\n" in cbuf and cbuf.lstrip().startswith((b"GET ", b"POST ", b"PUT ", b"HTTP/")):
                parse_http(cbuf)
            else:
                idx = cbuf.find(MMTLS_VERSION)
                start = max(0, idx - 1) if idx > 0 else 0
                parse_records(cbuf[start:start+2048], "raw")
                if start > 0:
                    print(f"  (skipped {start} leading bytes)")
        print("  -- SERVER -> CLIENT --")
        if sbuf:
            head = sbuf[:4096]
            if b"\r\n\r\n" in head and head.startswith(b"HTTP/"):
                parse_http(head)
            else:
                idx = sbuf.find(MMTLS_VERSION)
                start = max(0, idx - 1) if idx > 0 else 0
                parse_records(sbuf[start:start+2048], "raw")
                if start > 0:
                    print(f"  (skipped {start} leading bytes)")

if __name__ == "__main__":
    main()
