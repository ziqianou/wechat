#!/usr/bin/env python3
"""
Passive cipher-state vtable resolver.
Scans WeChat heap for objects whose vtable (in .data.rel.ro) resolves its
+0x10 slot (Encrypt) to a code address, handling both:
  - absolute 8-byte vtable entries
  - GCC -fpack-relative-vtables (4-byte signed offsets)
Usage: python3 -u find_encrypt.py <pid>
"""
import sys, struct, ctypes, time

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
            s, e = int(s, 16), int(e, 16)
            path = p[5] if len(p) > 5 else ""
            out.append((s, e, p[1], path))
    return out

CODE_LO, CODE_HI = 0x3680000, 0x9000000   # wechat VA range (module-relative)
RELO_LO, RELO_HI = 0x8255a50, 0x85a2b98    # .data.rel.ro (module-relative)

def main():
    pid = int(sys.argv[1])
    mm = [m for m in maps(pid) if "rw" in m[2]]  # ALL writable mappings
    # module base = mapping with file offset 0
    base = 0
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            p = line.split()
            if len(p) >= 5 and p[2] == "00000000" and p[3] == "08:13":
                base = int(p[0].split("-")[0], 16)
                break
    print(f"[*] module base = {base:#x}", flush=True)
    # module data ranges (module-relative): .data.rel.ro + .data
    RELO_LO, RELO_HI = 0x8255a50, 0x8700000
    t0 = time.time()
    found = []
    total_read = 0
    for (s, e, _, _) in mm:
        size = min(e - s, 1 << 24)
        data = read_remote(pid, s, size)
        if data is None:
            continue
        total_read += len(data)
        n = len(data)
        i = 0
        while i + 0x20 < n:
            v = struct.unpack("<Q", data[i:i+8])[0]
            if base + RELO_LO <= v < base + RELO_HI:
                relo_data = read_remote(pid, v, 0x20)
                if relo_data and len(relo_data) >= 0x18:
                    i4 = struct.unpack("<i", relo_data[0x10:0x14])[0]
                    q8 = struct.unpack("<Q", relo_data[0x10:0x18])[0]
                    cands = []
                    if base + CODE_LO <= q8 < base + CODE_HI:
                        cands.append(("abs8", q8))
                    rt = (v + 0x10) + i4
                    if base + CODE_LO <= rt < base + CODE_HI:
                        cands.append(("rel4", rt))
                    for kind, enc in cands:
                        found.append((v, kind, enc))
                        if len(found) <= 200:
                            print(f"  vtable={v:#x} [{kind}] Encrypt@0x{enc:#x} rva=0x{enc-base:#x}", flush=True)
            i += 8
        if time.time() - t0 > 110:
            break
    print(f"[*] done, {len(found)} candidates, read {total_read/1e6:.0f} MB, {time.time()-t0:.0f}s", flush=True)

if __name__ == "__main__":
    main()
