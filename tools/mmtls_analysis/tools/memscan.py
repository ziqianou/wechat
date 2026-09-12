#!/usr/bin/env python3
"""
Passive WeChat memory reader: read process memory via process_vm_readv (no injection).
Scans for ChaCha20-Poly1305 session key candidates in the mmtls connection state.
"""
import ctypes, os, struct, sys, json

libc = ctypes.CDLL("libc.so.6", use_errno=True)

def read_remote(pid, addr, size):
    """Read up to size bytes at addr via process_vm_readv. Returns bytes or None."""
    local = ctypes.create_string_buffer(size)
    local_iov = (ctypes.c_void_p * 2)(ctypes.addressof(local), size)
    remote_iov = (ctypes.c_void_p * 2)(addr, size)
    n = libc.process_vm_readv(pid, local_iov, 1, remote_iov, 1, 0)
    if n < 0:
        return None
    return local.raw[:n]

def maps(pid):
    out = []
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            parts = line.split()
            rng = parts[0].split("-")
            start, end = int(rng[0], 16), int(rng[1], 16)
            perms = parts[1]
            if len(parts) >= 6:
                ino = parts[4]
                path = parts[5] if len(parts) > 5 else ""
            else:
                ino, path = "0", ""
            out.append((start, end, perms, ino, path))
    return out

def scan(pid, size_limit=1 << 26):
    """Scan anonymous rw regions for candidate 32-byte keys, testing AEAD-verification."""
    regions = [m for m in maps(pid)
               if "rw" in m[2] and m[3] == "0" and m[4] == ""]
    print(f"[*] {len(regions)} anonymous rw regions")
    total = sum(e - s for s, e, _, _, _ in regions)
    print(f"[*] total virtual: {total/1e6:.0f} MB")

if __name__ == "__main__":
    pid = int(sys.argv[1])
    scan(pid)
