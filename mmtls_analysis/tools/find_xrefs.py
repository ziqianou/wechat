#!/usr/bin/env python3
"""Find xrefs to given strings in a stripped ELF binary (x86-64, RIP-relative). Fast."""
import re, struct
from elftools.elf.elffile import ELFFile

BIN = "/opt/wechat/wechat"
TARGETS = [
    b"mmtls writev size=%_",
    b"handle mmtls recv buf time %_",
    b"mmtls_record_reader.cpp",
    b"mmtls_client_channel.cpp",
    b"response mmtls over http",
    b"mmtls encoder version:%_",
    b"mmtls_psk.cpp",
    b"mmtls client channel::",
]

with open(BIN, "rb") as f:
    elf = ELFFile(f)
    segs = []
    for seg in elf.iter_segments():
        if seg["p_type"] == "PT_LOAD":
            segs.append((seg["p_vaddr"], seg.data()))

    found = {}
    for t in TARGETS:
        addrs = []
        for (vaddr, data) in segs:
            start = 0
            while True:
                i = data.find(t, start)
                if i < 0:
                    break
                addrs.append(vaddr + i)
                start = i + 1
        print(f"{t.decode():45s} -> {[hex(a) for a in addrs]}")
        found[t] = addrs

    text = None
    for sec in elf.iter_sections():
        if sec.name == ".text":
            text = sec
            break
    tb = text.data()
    tv = text["sh_addr"]

    # one pass: collect all rip-relative lea/mov targets
    pat = re.compile(
        rb"\x48[\x8D\x8B][\x05\x0D\x15\x1D\x25\x2D\x35\x3D].{4}"
        rb"|\x4C\x8D[\x05\x0D\x15\x1D\x25\x2D\x35\x3D].{4}"
    )
    all_xrefs = {}
    for m in pat.finditer(tb):
        disp = struct.unpack("<i", m.group()[-4:])[0]
        target = tv + m.start() + 7 + disp
        all_xrefs.setdefault(target, []).append(tv + m.start())

    print("\n== xrefs in .text ==")
    for t, addrs in found.items():
        if not addrs:
            continue
        xs = []
        for a in addrs:
            xs.extend(all_xrefs.get(a, []))
        xs = sorted(set(xs))
        print(f"{t.decode():45s} xrefs({len(xs)}): {[hex(x) for x in xs[:25]]}")
