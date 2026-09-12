#!/usr/bin/env python3
"""Minimal Windows minidump parser: extract exception + faulting module."""
import struct, sys

def parse(path):
    data = open(path, 'rb').read()
    if data[0:4] != b'MDMP':
        print("not a minidump"); return
    off = 4
    ver, streams, ts, _, _, flags = struct.unpack_from('<IIIIII', data, off)
    off += 24
    dirs = []
    for i in range(streams):
        stype, ssize, soff = struct.unpack_from('<III', data, off)
        off += 12
        dirs.append((stype, soff, ssize))
    modules = []   # (base, size, name)
    exc = None
    for stype, soff, ssize in dirs:
        if stype == 0:  # ModuleListStream
            n = struct.unpack_from('<I', data, soff)[0]
            p = soff + 4
            for i in range(n):
                base, size, _, _, _, _, name_rva = struct.unpack_from('<QQIIIII', data, p)
                p += 108
                name = ""
                nr = soff + name_rva - 4  # relative to stream start? actually rva is global
                nr = name_rva
                try:
                    end = data.index(b'\x00', nr)
                    name = data[nr:end].decode('utf-16-le', 'ignore')
                except Exception:
                    pass
                modules.append((base, size, name))
                p += 4  # checksum? adjust
        elif stype == 6:  # ExceptionStream
            tid, _ = struct.unpack_from('<II', data, soff)
            # EXCEPTION_RECORD: code(4) flags(4) rec(8) addr(8) params...
            code, eflags, _, addr = struct.unpack_from('<IIQI', data, soff + 8)
            exc = (tid, code, addr)
    print("== modules ==")
    for base, size, name in modules:
        print("  %#x  %#x  %s" % (base, size, name))
    print("== exception ==")
    if exc:
        tid, code, addr = exc
        print("  thread=%d code=0x%08x addr=%#x" % (tid, code, addr))
        for base, size, name in modules:
            if base <= addr < base + size:
                print("  -> in %s + %#x" % (name, addr - base))
                break

if __name__ == '__main__':
    parse(sys.argv[1])
