import struct, sys

from capstone import *
from capstone.arm64_const import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM
from elftools.elf.elffile import ELFFile

def find_string_vas(path, needles):
    with open(path, 'rb') as f:
        elf = ELFFile(f)
        results = {}
        for sec in elf.iter_sections():
            if sec['sh_type'] != 'SHT_PROGBITS':
                continue
            sec_data = sec.data()
            for needle in needles:
                idx = sec_data.find(needle)
                if idx != -1:
                    va = sec['sh_addr'] + idx
                    results.setdefault(needle, va)
        return results

def get_exec_segments(path):
    segs = []
    with open(path, 'rb') as f:
        elf = ELFFile(f)
        for sec in elf.iter_sections():
            if sec['sh_type'] == 'SHT_PROGBITS' and sec['sh_flags'] & 0x4:  # SHF_EXECINSTR
                segs.append((sec.data(), sec['sh_addr']))
    return segs

def find_xrefs_in(code, code_base, target_va):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    page_val = {}
    xrefs = []
    for insn in md.disasm(code, code_base):
        try:
            if insn.mnemonic == 'adrp':
                reg = insn.operands[0].reg
                page_val[reg] = insn.operands[1].imm & ~0xfff
            elif insn.mnemonic == 'add' and len(insn.operands) >= 3:
                if insn.operands[1].type == ARM64_OP_REG:
                    src = insn.operands[1].reg
                    if src in page_val and insn.operands[2].type == ARM64_OP_IMM:
                        full = page_val[src] + insn.operands[2].imm
                        if full == target_va:
                            xrefs.append(insn.address)
            elif insn.mnemonic == 'ldr' and len(insn.operands) >= 2:
                # ldr x, [xN, #imm] where xN is adrp'd page
                if insn.operands[1].type == ARM64_OP_MEM:
                    m = insn.operands[1].mem
                    if m.base in page_val:
                        full = page_val[m.base] + (m.disp or 0)
                        if full == target_va:
                            xrefs.append(insn.address)
        except Exception:
            pass
        if insn.mnemonic == 'ret':
            page_val.clear()
    return xrefs

if __name__ == '__main__':
    path = sys.argv[1]
    needles = [n.encode() for n in sys.argv[2:]]
    str_vas = find_string_vas(path, needles)
    segs = get_exec_segments(path)
    print(f"exec segments: {len(segs)}")
    for needle_b in str_vas:
        target = str_vas[needle_b]
        print(f"\nstring: {needle_b.decode()!r}  VA={target:#x}")
        total = 0
        for (code, base) in segs:
            xs = find_xrefs_in(code, base, target)
            total += len(xs)
            for x in xs:
                print(f"    xref VA {x:#x}")
        print(f"  total xrefs: {total}")
