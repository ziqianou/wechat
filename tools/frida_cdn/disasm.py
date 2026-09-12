import sys
from capstone import *
from capstone.arm64_const import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM
from elftools.elf.elffile import ELFFile

def get_text(path):
    with open(path, 'rb') as f:
        elf = ELFFile(f)
        for sec in elf.iter_sections():
            if sec['sh_type'] == 'SHT_PROGBITS' and sec['sh_flags'] & 0x4:
                return sec.data(), sec['sh_addr']
    return None, None

def find_func_start(code, base, addr, maxback=0x2000):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True
    idx = addr - base
    insns = []
    start = max(0, idx - maxback)
    for insn in md.disasm(code[start:idx+4], base + start):
        insns.append(insn)
    # scan backwards for last 'ret' or function prologue before addr
    prologue = None
    for insn in reversed(insns):
        if insn.mnemonic == 'ret':
            return insn.address + 4
        if insn.mnemonic == 'stp' and 'x29' in insn.op_str and 'x30' in insn.op_str:
            prologue = insn.address
            continue
        if insn.mnemonic == 'sub' and 'sp' in insn.op_str and insn.operands[0].type == ARM64_OP_REG and insn.operands[0].reg == 31:
            # sub sp, sp, #imm
            if prologue is not None:
                return prologue
    if prologue:
        return prologue
    return addr - 64

if __name__ == '__main__':
    path = sys.argv[1]
    target = int(sys.argv[2], 16)
    back = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x80
    forward = int(sys.argv[4], 16) if len(sys.argv) > 4 else 0x100
    code, base = get_text(path)
    start = find_func_start(code, base, target)
    print(f"func start ~ {start:#x}")
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    s = start - base
    for insn in md.disasm(code[s:s+forward], start):
        marker = ' <<<' if insn.address == target else ''
        print(f"{insn.address:#10x}  {insn.mnemonic:8s} {insn.op_str}{marker}")
