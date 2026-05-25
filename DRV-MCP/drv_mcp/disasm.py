"""
disasm.py
=========

Capstone wrapper. We disassemble bytes read through the CR3 R/W pipeline
— capstone never touches the target process directly, so no syscalls
that anti-cheat could fingerprint.

x86/x64 only (it's the only thing the driver targets). Falls back to a
helpful error if ``capstone`` isn't installed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

try:
    import capstone
    _HAVE_CAPSTONE = True
except ImportError:        # pragma: no cover
    capstone = None        # type: ignore
    _HAVE_CAPSTONE = False


@dataclass
class Instruction:
    address:  int
    size:     int
    bytes_:   bytes
    mnemonic: str
    op_str:   str

    def __str__(self) -> str:
        return (f"0x{self.address:016X}  "
                f"{self.bytes_.hex(' '):<24s}  "
                f"{self.mnemonic} {self.op_str}".rstrip())


def have_capstone() -> bool:
    return _HAVE_CAPSTONE


def disassemble(code: bytes, base_address: int = 0,
                mode: str = "x64", max_instructions: int = 64) -> list[Instruction]:
    """
    Disassemble ``code`` starting at ``base_address``. ``mode`` is
    ``"x64"`` or ``"x86"``. Returns up to ``max_instructions`` decoded
    instructions; stops early if capstone runs out of valid input.
    """
    if not _HAVE_CAPSTONE:
        raise RuntimeError(
            "capstone is not installed — run `pip install capstone` "
            "(or pip install -r requirements.txt) to enable disassembly"
        )
    if mode == "x64":
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    elif mode == "x86":
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    else:
        raise ValueError(f"mode must be 'x64' or 'x86', got {mode!r}")

    cs.detail = False
    out: list[Instruction] = []
    for insn in cs.disasm(code, base_address):
        out.append(Instruction(
            address=insn.address,
            size=insn.size,
            bytes_=bytes(insn.bytes),
            mnemonic=insn.mnemonic,
            op_str=insn.op_str,
        ))
        if len(out) >= max_instructions:
            break
    return out


def format_listing(insns: list[Instruction]) -> str:
    return "\n".join(str(i) for i in insns)
