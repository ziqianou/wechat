#!/usr/bin/env python3
"""
Parallel passive WeChat mmtls key scanner v3.
- ciphers: ChaCha20-Poly1305 (32B) + AES-256-GCM (32B) + AES-128-GCM (16B)
- single-window candidates (no forced key-pair contiguity)
- isolation filter vs media/compressed
- region min size 4KB (0x1000)
- two-stage seq: phase1 0..15 fast, phase2 full depth
Usage: python3 -u scan_key.py <pid> <pcap> <flow>
"""
import sys, struct, ctypes, time, os
from multiprocessing import Pool
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM

MAXSEQ = int(os.environ.get("MAXSEQ", "1024"))
ENABLE_IVXOR = os.environ.get("IVXOR", "1") == "1"
SCAN16 = os.environ.get("SCAN16", "0") == "1"
PHASE = os.environ.get("PHASE", "12")
ISOLATE = os.environ.get("ISOLATE", "1") == "1"
CUR_MAXSEQ = 16

libc = ctypes.CDLL("libc.so.6", use_errno=True)

def read_remote(pid, addr, size):
    local = ctypes.create_string_buffer(size)
    iov_l = (ctypes.c_void_p * 2)(ctypes.addressof(local), size)
    iov_r = (ctypes.c_void_p * 2)(addr, size)
    n = libc.process_vm_readv(pid, iov_l, 1, iov_r, 1, 0)
    return local.raw[:n] if n > 0 else None

def get_regions(pid):
    regions = []
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            p = line.split()
            s, e = p[0].split("-")
            s, e = int(s, 16), int(e, 16)
            if "rw" not in p[1]:
                continue
            # scan ALL writable regions: anonymous + file-backed (.bss/.data)
            regions.append((s, e, p[5] if len(p) > 5 else "[anon]"))
    big = [r for r in regions if r[1] - r[0] >= 0x1000]
    big.sort(key=lambda r: (r[2] not in ("[heap]", "[anon]"), -(r[1] - r[0])))
    return big

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

def decrypt_with(cobj, nonce, aad, body):
    if len(body) < 17: return None
    try:
        return cobj.decrypt(nonce, body, aad)
    except Exception:
        return None

def gen_nonces(seq, ivs):
    nb12 = seq.to_bytes(12, "big")
    nb12le = seq.to_bytes(12, "little")
    nb8 = seq.to_bytes(8, "big") + b"\x00\x00\x00\x00"
    nb8le = seq.to_bytes(8, "little") + b"\x00\x00\x00\x00"
    yield "seq12", nb12
    yield "seq12le", nb12le
    yield "seq8", nb8
    yield "seq8le", nb8le
    if ENABLE_IVXOR:
        for iv in ivs:
            if len(iv) == 12:
                yield "ivxor", bytes(iv[j] ^ nb12[j] for j in range(12))
                yield "ivxorle", bytes(iv[j] ^ nb12le[j] for j in range(12))

def make_objs(key):
    """Return list of (name, cipher_obj) for a key candidate."""
    objs = []
    if len(key) == 32:
        for nm, cls in (("chacha", ChaCha20Poly1305), ("aes256", AESGCM)):
            try: objs.append((nm, cls(key)))
            except Exception: pass
        for half in (key[:16], key[16:]):
            try: objs.append(("aes128", AESGCM(half)))
            except Exception: pass
    elif len(key) == 16:
        try: objs.append(("aes128", AESGCM(key)))
        except Exception: pass
    return objs

def test_key(key, records, max_seq, ivs):
    objs = make_objs(key)
    if not objs: return None
    # fast-path: try the most recent few records first (current session),
    # then the first. AEAD tag verification is decisive (2^-128).
    test_recs = list(records[-3:]) + [records[0]]
    for ridx, (isc0, rec0) in enumerate(test_recs):
        hdr0, body0 = rec0[:5], rec0[5:]
        # HYP: body = [12B nonce][ct||tag]
        if len(body0) >= 28:
            rn = body0[:12]
            for aad_ok, aad in ((True, hdr0), (False, b"")):
                for cname, cobj in objs:
                    pt = decrypt_with(cobj, rn, aad, body0[12:])
                    if pt is not None:
                        return [(ridx, isc0, -1, aad_ok, "recnonce", cname, pt)]
            # HYP: body = [12B nonce][tag16][ct]
            if len(body0) >= 44:
                rn = body0[:12]
                ct_tag = body0[28:] + body0[12:28]
                for aad_ok, aad in ((True, hdr0), (False, b"")):
                    for cname, cobj in objs:
                        pt = decrypt_with(cobj, rn, aad, ct_tag)
                        if pt is not None:
                            return [(ridx, isc0, -1, aad_ok, "recnonce_tagfirst", cname, pt)]
        # HYP: body = [4B counter][ct||tag] / [8B counter][ct||tag]
        for cpre in (4, 8):
            if len(body0) >= cpre + 17:
                b = body0[cpre:]
                for aad_ok, aad in ((True, hdr0), (False, b"")):
                    for seq in range(max_seq):
                        for mode, nb in gen_nonces(seq, ivs):
                            for cname, cobj in objs:
                                pt = decrypt_with(cobj, nb, aad, b)
                                if pt is not None:
                                    return [(ridx, isc0, seq, aad_ok, f"cpre{cpre}:"+mode, cname, pt)]
        # HYP: body = [tag16][ct]
        if len(body0) >= 33:
            ct_tag = body0[16:] + body0[:16]
            for aad_ok, aad in ((True, hdr0), (False, b"")):
                for seq in range(max_seq):
                    for mode, nb in gen_nonces(seq, ivs):
                        for cname, cobj in objs:
                            pt = decrypt_with(cobj, nb, aad, ct_tag)
                            if pt is not None:
                                return [(ridx, isc0, seq, aad_ok, "tagfirst:"+mode, cname, pt)]
        # seq-based hypotheses (standard ct||tag)
        for aad_ok, aad in ((True, hdr0), (False, b"")):
            for seq in range(max_seq):
                for mode, nb in gen_nonces(seq, ivs):
                    for cname, cobj in objs:
                        pt0 = decrypt_with(cobj, nb, aad, body0)
                        if pt0 is None:
                            continue
                        return [(ridx, isc0, seq, aad_ok, mode, cname, pt0)]
    return None

def isolation_ok(data, o):
    if not ISOLATE:
        return True
    pre = data[max(0, o-64):o]
    post = data[o+64:o+128]
    if len(pre) >= 32 and len(post) >= 32:
        if len(set(pre)) >= 20 and len(set(post)) >= 20:
            return False
    return True

def scan_region(args):
    import numpy as np
    pid, s, e, records = args
    chunk = 1 << 22
    off = 0
    n_cand = 0
    while off < e - s:
        size = min(chunk, e - s - off)
        data = read_remote(pid, s + off, size)
        if data is not None and len(data) >= 64:
            nz = sum(1 for b in data[::4096] if b != 0)
            if nz >= 3:
                a = np.frombuffer(data, dtype=np.uint8)
                n_w = (len(data) - 64) // 8 + 1
                blk32 = np.lib.stride_tricks.as_strided(a, shape=(n_w, 32), strides=(8, 1))
                s32 = np.sort(blk32, axis=1)
                d32 = (s32[:, 1:] != s32[:, :-1]).sum(axis=1) + 1
                blk16 = np.lib.stride_tricks.as_strided(a, shape=(n_w, 16), strides=(8, 1))
                s16 = np.sort(blk16, axis=1)
                d16 = (s16[:, 1:] != s16[:, :-1]).sum(axis=1) + 1
                # 32-byte candidates
                for i in np.nonzero(d32 >= 27)[0]:
                    i = int(i); o = i * 8
                    if not isolation_ok(data, o): continue
                    n_cand += 1
                    ivs = (data[max(0, o-16):max(0, o-4)], data[o+32:o+44], data[o+48:o+60],
                           data[o+64:o+76], data[o+76:o+88], data[max(0, o-12):max(0, o)],
                           data[o+12:o+24], data[o+44:o+56])
                    r = test_key(data[o:o+32], records, CUR_MAXSEQ, ivs)
                    if r:
                        return (s + off + o, data[o:o+32], r, n_cand)
                # isolated 16-byte candidates (AES-128) — only if enabled
                if SCAN16:
                    for i in np.nonzero((d16 >= 13) & (d32 < 27))[0]:
                        i = int(i); o = i * 8
                        if not isolation_ok(data, o): continue
                        n_cand += 1
                        ivs = (data[max(0, o-16):max(0, o-4)], data[o+16:o+28], data[o+32:o+44],
                               data[max(0, o-12):max(0, o)], data[o+12:o+24])
                        r = test_key(data[o:o+16], records, CUR_MAXSEQ, ivs)
                        if r:
                            return (s + off + o, data[o:o+16], r, n_cand)
        off += size
    return None

def main():
    pid = int(sys.argv[1]); pcap = sys.argv[2]; flow = sys.argv[3]
    records = extract_records(pcap, flow)
    print(f"[*] {len(records)} records", flush=True)
    if not records: return
    print(f"[*] rec#0 dirC={records[0][0]} hdr={records[0][1][:5].hex()} len={len(records[0][1])}", flush=True)
    regions = get_regions(pid)
    total = sum(e - s for s, e, _ in regions)
    print(f"[*] {len(regions)} regions, {total/1e6:.0f} MB, heap first", flush=True)
    tasks = [(pid, s, e, records) for s, e, _ in regions]
    nproc = min(os.cpu_count() or 4, 16)
    print(f"[*] {nproc} workers, ciphers=chacha/aes256/aes128", flush=True)
    t0 = time.time()
    global CUR_MAXSEQ
    for phase, seqlim in ((1, 16), (2, MAXSEQ)):
        if str(phase) not in PHASE:
            continue
        if phase == 2 and MAXSEQ <= 16:
            break
        CUR_MAXSEQ = seqlim
        print(f"[*] phase {phase}: seq 0..{seqlim-1}", flush=True)
        with Pool(nproc) as pool:
            done = 0
            for res in pool.imap_unordered(scan_region, tasks, chunksize=1):
                if res:
                    addr, key, hits, n_cand = res
                    k, isc, seq, aad_ok, mode, cname, pt = hits[0]
                    print(f"\n[FOUND] addr={addr:#x} records_hit={len(hits)} dirC={isc} seq={seq} aad_header={aad_ok} mode={mode} cipher={cname} phase={phase}", flush=True)
                    print(f"   key={key.hex()}", flush=True)
                    print(f"   candidates={n_cand}", flush=True)
                    for h in hits[:6]:
                        print(f"   rec#{h[0]} dirC={h[1]} seq={h[2]} cipher={h[5]} pt={h[6][:48].hex()}", flush=True)
                    print(f"   elapsed={time.time()-t0:.1f}s", flush=True)
                    pool.terminate()
                    return
                done += 1
                if done % 10 == 0:
                    print(f"[*] phase {phase} scanned {done}/{len(tasks)} regions ...", flush=True)
    print(f"[*] done, no key, elapsed={time.time()-t0:.1f}s", flush=True)

if __name__ == "__main__":
    main()
