#!/usr/bin/env python3
"""
WeChat mmtls AES-128-GCM decryptor.
Decrypts captured app-data records offline using the session key + IV
(extracted via gdb hardware breakpoints).

Usage: python3 -u mmtls_decrypt.py <pcap> <flow_ip> [key_hex] [iv_hex]

Parameters (verified for the session that was captured):
  key = 181a2fc86c40946b33690cfa922dbbd0
  iv  = 15b41b09b48cd8cd0e7a3777
  nonce = IV XOR record_seq(12B BE)
  aad   = record_seq(8B BE) + 5-byte record header
"""
import sys, struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY = bytes.fromhex(sys.argv[3] if len(sys.argv) > 3 else "181a2fc86c40946b33690cfa922dbbd0")
IV  = bytes.fromhex(sys.argv[4] if len(sys.argv) > 4 else "15b41b09b48cd8cd0e7a3777")

def extract_records(pcap, flow):
    hdr = open(pcap, "rb").read(24)
    if len(hdr) < 24: return []
    lt = struct.unpack("<I", hdr[20:24])[0]
    recs = []
    with open(pcap, "rb") as f:
        f.seek(24)
        while True:
            rh = f.read(16)
            if len(rh) < 16: break
            cap = struct.unpack("<I", rh[8:12])[0]
            data = f.read(cap)
            if len(data) < cap: break
            r = parse_packet(data, lt)
            if not r: continue
            (s, sp, d, dp), payload = r
            if flow not in (s, d) or not payload: continue
            off = 0
            while off + 5 <= len(payload):
                typ, ver, ln = payload[off], payload[off+1:off+3], struct.unpack(">H", payload[off+3:off+5])[0]
                if ver != b"\xf1\x04": break
                if off + 5 + ln > len(payload): break
                if typ == 0x17:
                    recs.append((sp > dp, payload[off:off+5+ln]))
                off += 5 + ln
    return recs

def parse_packet(data, lt):
    if lt == 276:
        ip = data[20:]
        if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6: return None
        tcp = ip[(ip[0] & 0x0f) * 4:]
        src, dst = ip[12:16], ip[16:20]
    elif lt == 1:
        eth = data[14:]
        if len(eth) < 20 or eth[0] >> 4 != 4 or eth[9] != 6: return None
        tcp = eth[(eth[0] & 0x0f) * 4:]
        src, dst = eth[12:16], eth[16:20]
    else:
        return None
    if len(tcp) < 20: return None
    sport, dport = struct.unpack(">HH", tcp[0:4])
    off = (tcp[12] >> 4) * 4
    return (".".join(map(str, src)), sport, ".".join(map(str, dst)), dport), tcp[off:]

def decrypt(rec, seq):
    hdr, body = rec[:5], rec[5:]
    aad = seq.to_bytes(8, "big") + hdr
    nonce = bytes([IV[j] ^ (seq.to_bytes(12, "big")[j]) for j in range(12)])
    return AESGCM(KEY).decrypt(nonce, body, aad)

def main():
    pcap, flow = sys.argv[1], sys.argv[2]
    recs = extract_records(pcap, flow)
    print(f"[*] {len(recs)} appdata records, key={KEY.hex()}")
    aes = AESGCM(KEY)
    ok = 0
    for d, rec in recs:
        if len(rec) < 21: continue
        for seq in range(0, 100000):
            try:
                pt = decrypt(rec, seq)
                ok += 1
                a = "".join(chr(c) if 32 <= c < 127 else "." for c in pt[:80])
                print(f"[OK] dirC={d} seq={seq} len={len(pt)} hdr={rec[:5].hex()}")
                print(f"     {a}")
                break
            except Exception:
                pass
    print(f"[*] decrypted {ok}/{len(recs)}")

if __name__ == "__main__":
    main()
