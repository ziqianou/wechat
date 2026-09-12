#!/usr/bin/env python3
"""
Find the mmtls cipher_state object (vtable in module data + contains session
key material), dump its layout, and try decrypting captured records using the
keys/ivs found INSIDE the object (tests the real layout, no guessing).
Usage: python3 -u find_cipher.py <pid> <pcap> <flow>
"""
import sys, struct, ctypes, time
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM

libc = ctypes.CDLL("libc.so.6", use_errno=True)
def read_remote(pid, addr, size):
    local = ctypes.create_string_buffer(size)
    iov_l = (ctypes.c_void_p * 2)(ctypes.addressof(local), size)
    iov_r = (ctypes.c_void_p * 2)(addr, size)
    n = libc.process_vm_readv(pid, iov_l, 1, iov_r, 1, 0)
    return local.raw[:n] if n > 0 else None

def maps(pid):
    out = []
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            p = line.split()
            s, e = p[0].split("-")
            out.append((int(s, 16), int(e, 16), p[1]))
    return out

def get_base(pid):
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            p = line.split()
            if len(p) >= 5 and p[2] == "00000000" and p[3] == "08:13":
                return int(p[0].split("-")[0], 16)
    return 0

def extract_records(pcap, flow):
    hdr = open(pcap, "rb").read(24)
    if len(hdr) < 24: return []
    lt = struct.unpack("<I", hdr[20:24])[0]
    recs = []
    import scan_key
    with open(pcap, "rb") as f:
        f.seek(24)
        while True:
            rh = f.read(16)
            if len(rh) < 16: break
            cap = struct.unpack("<I", rh[8:12])[0]
            data = f.read(cap)
            if len(data) < cap: break
            r = scan_key.parse_packet(data, lt)
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

def ent(buf):
    if not buf: return 0
    return len(set(buf))

def main():
    pid = int(sys.argv[1]); pcap = sys.argv[2]; flow = sys.argv[3]
    records = extract_records(pcap, flow)
    print(f"[*] {len(records)} records", flush=True)
    base = get_base(pid)
    print(f"[*] base={base:#x}", flush=True)
    # module data range (vtable targets)
    DLO, DHI = 0x8255a50, 0x8740000
    # scan anon rw + [heap] for objects with vtable in module data AND high-entropy key-like bytes
    regions = [m for m in maps(pid) if "rw" in m[2]]
    cands = []
    t0 = time.time()
    for (s, e, _) in regions:
        size = min(e - s, 1 << 22)
        data = read_remote(pid, s, size)
        if data is None: continue
        n = len(data)
        i = 0
        while i + 0x100 < n:
            v = struct.unpack("<Q", data[i:i+8])[0]
            if base + DLO <= v < base + DHI:
                # object with key-like high-entropy 32B at a few candidate offsets
                for ko in (0x8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50):
                    if i + ko + 64 < n:
                        k1 = data[i+ko:i+ko+32]
                        k2 = data[i+ko+32:i+ko+64]
                        if ent(k1) >= 24 and ent(k2) >= 24:
                            cands.append((s + i, ko, v, k1.hex(), k2.hex()))
                            break
            i += 8
        if time.time() - t0 > 115: break
    print(f"[*] {len(cands)} cipher_state candidates", flush=True)
    # try decrypting records with each candidate's keys (as encrypt/decrypt keys)
    for addr, ko, v, h1, h2 in cands[:8]:
        k1 = bytes.fromhex(h1); k2 = bytes.fromhex(h2)
        print(f"  obj={addr:#x} key_off=+{ko:#x} vtable={v:#x} key1={h1[:16]}... key2={h2[:16]}...", flush=True)
        # read surrounding for iv candidates
        obj = read_remote(pid, addr, 0xC0)
        if not obj: continue
        for ki, kk in ((1, k1), (2, k2)):
            for cipher in ("chacha", "aes256"):
                try:
                    cobj = ChaCha20Poly1305(kk) if cipher == "chacha" else AESGCM(kk)
                except Exception:
                    continue
                for ivo in (ko+32, ko+64, ko+76, ko+48, ko+12):
                    if ivo + 12 <= len(obj):
                        iv = obj[ivo:ivo+12]
                        for seq in range(0, 64):
                            nonce = bytes(iv[j] ^ seq.to_bytes(12, "big")[j] for j in range(12))
                            for d, rec in records[-2:]:
                                for aad_ok, aad in ((True, rec[:5]), (False, b"")):
                                    try:
                                        pt = cobj.decrypt(nonce, rec[5:], aad)
                                        print(f"    [HIT] key#{ki} {cipher} iv@+{ivo:#x} seq={seq} aad_header={aad_ok} pt={pt[:32].hex()} [{''.join(chr(c) if 32<=c<127 else '.' for c in pt[:32])}]", flush=True)
                                        return
                                    except Exception:
                                        pass
    print("[*] no hit", flush=True)

if __name__ == "__main__":
    main()
