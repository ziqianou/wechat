#!/usr/bin/env python3
"""Disassemble a window around given VAs in the wechat binary."""
import sys
from capstone import *
from capstone.x86 import *
from elftools.elf.elffile import ELFFile

BIN = "/opt/wechat/wechat"

def load():
    f = open(BIN, "rb")
    elf = ELFFile(f)
    for sec in elf.iter_sections():
        if sec.name == ".text":
            return sec
    return None

def va_to_offset(text, va):
    return va - text["sh_addr"]

def disasm(text, va, size, md):
    off = va_to_offset(text, va)
    code = text.data()[off:off + size]
    for ins in md.disasm(code, va):
        print(f"0x{ins.address:08x}: {ins.mnemonic:<8s} {ins.op_str}")

def main():
    targets = []
    for a in sys.argv[1:]:
        if ":" in a:
            va, w = a.split(":")
            targets.append((int(va, 16), int(w)))
        else:
            targets.append((int(a, 16), 128))
    text = load()
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for va, w in targets:
        print(f"\n========== 0x{va:x} (+-{w}) ==========")
        disasm(text, va - w, 2 * w, md)

if __name__ == "__main__":
    main()
