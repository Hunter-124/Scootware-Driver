"""
pe.py
=====

Parse Portable Executable headers from raw bytes. No I/O of its own —
it gets fed bytes via a ``read(addr, size)`` callable so we can plug it
on top of the CR3 R/W primitives without the parser caring where the
bytes come from.

We only handle PE32+ (x64). The driver targets 64-bit Windows, so that's
the only image format we'll see in practice.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Callable, Optional

# ─── PE constants ──────────────────────────────────────────────────────
DOS_MAGIC          = b'MZ'
PE_MAGIC           = b'PE\x00\x00'
OPT_MAGIC_PE32     = 0x10B
OPT_MAGIC_PE32PLUS = 0x20B

# Data directory indices we care about
DIR_EXPORT          = 0
DIR_IMPORT          = 1
DIR_RESOURCE        = 2
DIR_EXCEPTION       = 3
DIR_SECURITY        = 4
DIR_BASERELOC       = 5
DIR_DEBUG           = 6
DIR_TLS             = 9
DIR_LOAD_CONFIG     = 10
DIR_DELAY_IMPORT    = 13

_DIR_NAMES = {
    0:  "Export",   1: "Import",       2:  "Resource",   3:  "Exception",
    4:  "Security", 5: "BaseReloc",    6:  "Debug",      7:  "Architecture",
    8:  "GlobalPtr",9: "TLS",         10:  "LoadConfig",11:  "BoundImport",
    12: "IAT",     13: "DelayImport", 14:  "COMDescriptor",
}

# Section characteristics flags we name
IMAGE_SCN_CNT_CODE                = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA    = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA  = 0x00000080
IMAGE_SCN_MEM_EXECUTE             = 0x20000000
IMAGE_SCN_MEM_READ                = 0x40000000
IMAGE_SCN_MEM_WRITE               = 0x80000000


ReadFn = Callable[[int, int], bytes]


# ─── Dataclasses ───────────────────────────────────────────────────────
@dataclass
class DataDirectory:
    rva:  int
    size: int


@dataclass
class Section:
    name:               str
    virtual_size:       int
    virtual_address:    int   # RVA
    raw_size:           int
    raw_pointer:        int
    characteristics:    int

    @property
    def is_code(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_CNT_CODE)

    @property
    def is_executable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)

    @property
    def is_writable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_WRITE)

    def perms_str(self) -> str:
        bits = []
        bits.append('R' if self.characteristics & IMAGE_SCN_MEM_READ      else '-')
        bits.append('W' if self.characteristics & IMAGE_SCN_MEM_WRITE     else '-')
        bits.append('X' if self.characteristics & IMAGE_SCN_MEM_EXECUTE   else '-')
        return ''.join(bits)


@dataclass
class PEInfo:
    image_base:           int
    e_lfanew:             int
    machine:              int
    num_sections:         int
    size_of_image:        int
    size_of_headers:      int
    entry_point_rva:      int
    is_64bit:             bool
    subsystem:            int
    dll_characteristics:  int
    data_directories:     list[DataDirectory] = field(default_factory=list)
    sections:             list[Section]       = field(default_factory=list)


@dataclass
class ExportEntry:
    name:    Optional[str]
    ordinal: int
    rva:     int
    va:      int
    is_forwarder: bool = False
    forwarder:    Optional[str] = None


@dataclass
class ImportFunction:
    name:       Optional[str]   # None when imported by ordinal
    ordinal:    Optional[int]
    iat_va:     int             # where the resolved address lives in IAT
    bound_va:   int             # current value at IAT (resolved import)


@dataclass
class ImportModule:
    dll_name:    str
    functions:   list[ImportFunction] = field(default_factory=list)


# ─── Parser ────────────────────────────────────────────────────────────
class PEParser:
    """Parses PE headers using a caller-supplied byte reader."""

    def __init__(self, read_fn: ReadFn, image_base: int):
        self._read = read_fn
        self.base  = image_base

    # ── Helpers ────────────────────────────────────────────────────────
    def _rva(self, rva: int, size: int) -> bytes:
        return self._read(self.base + rva, size)

    # ── Header parsing ─────────────────────────────────────────────────
    def parse_headers(self) -> PEInfo:
        # DOS header — we only need e_lfanew at offset 0x3C.
        dos = self._read(self.base, 0x40)
        if dos[:2] != DOS_MAGIC:
            raise ValueError(
                f"Not a PE image (got {dos[:2]!r}, expected b'MZ') at "
                f"base 0x{self.base:X}"
            )
        e_lfanew = struct.unpack_from('<I', dos, 0x3C)[0]
        if e_lfanew > 0x10000:
            raise ValueError(f"Unreasonable e_lfanew=0x{e_lfanew:X}")

        # NT signature (4) + IMAGE_FILE_HEADER (20) + IMAGE_OPTIONAL_HEADER64
        # without data dirs (0x70 = 112) + 16 data directories (16 * 8 = 128) = 264.
        # PE32 only needs 248; we read the larger size to cover both. Read
        # past the end of valid headers is harmless because the loader maps
        # the entire SizeOfHeaders page anyway.
        nt_block = self._read(self.base + e_lfanew, 4 + 20 + 0x70 + 16 * 8)
        if nt_block[:4] != PE_MAGIC:
            raise ValueError(
                f"Not a PE image (no 'PE\\0\\0' signature at base+0x{e_lfanew:X})"
            )

        # IMAGE_FILE_HEADER (20 bytes)
        (machine, num_sections, _timestamp, _sym_ptr, _sym_count,
         opt_size, _chars) = struct.unpack_from('<HHIIIHH', nt_block, 4)

        # Optional header magic at offset 4 + 20 = 24
        opt_magic = struct.unpack_from('<H', nt_block, 24)[0]
        is_64bit  = (opt_magic == OPT_MAGIC_PE32PLUS)

        if is_64bit:
            # IMAGE_OPTIONAL_HEADER64
            entry_rva    = struct.unpack_from('<I', nt_block, 24 + 0x10)[0]
            image_base   = struct.unpack_from('<Q', nt_block, 24 + 0x18)[0]
            size_of_img  = struct.unpack_from('<I', nt_block, 24 + 0x38)[0]
            size_of_hdrs = struct.unpack_from('<I', nt_block, 24 + 0x3C)[0]
            subsystem    = struct.unpack_from('<H', nt_block, 24 + 0x44)[0]
            dll_char     = struct.unpack_from('<H', nt_block, 24 + 0x46)[0]
            num_dirs     = struct.unpack_from('<I', nt_block, 24 + 0x6C)[0]
            dd_off       = 24 + 0x70
        else:
            # IMAGE_OPTIONAL_HEADER32
            entry_rva    = struct.unpack_from('<I', nt_block, 24 + 0x10)[0]
            image_base   = struct.unpack_from('<I', nt_block, 24 + 0x1C)[0]
            size_of_img  = struct.unpack_from('<I', nt_block, 24 + 0x38)[0]
            size_of_hdrs = struct.unpack_from('<I', nt_block, 24 + 0x3C)[0]
            subsystem    = struct.unpack_from('<H', nt_block, 24 + 0x44)[0]
            dll_char     = struct.unpack_from('<H', nt_block, 24 + 0x46)[0]
            num_dirs     = struct.unpack_from('<I', nt_block, 24 + 0x5C)[0]
            dd_off       = 24 + 0x60

        num_dirs = min(num_dirs, 16)
        directories = []
        for i in range(num_dirs):
            rva, size = struct.unpack_from('<II', nt_block, dd_off + i * 8)
            directories.append(DataDirectory(rva=rva, size=size))
        # Pad to 16 so callers can always index by DIR_*
        while len(directories) < 16:
            directories.append(DataDirectory(rva=0, size=0))

        # Section headers start at e_lfanew + 0x18 (sig+file_header end) + opt_size
        section_table_off = e_lfanew + 0x18 + opt_size
        section_bytes = self._read(self.base + section_table_off,
                                   num_sections * 40)
        sections = []
        for i in range(num_sections):
            off = i * 40
            name_raw = section_bytes[off:off + 8]
            name = name_raw.rstrip(b'\x00').decode('latin-1')
            (vsize, vaddr, raw_size, raw_ptr,
             _ptr_reloc, _ptr_lineno, _num_reloc, _num_lineno,
             characteristics) = struct.unpack_from('<IIII IIHHI', section_bytes, off + 8)
            sections.append(Section(
                name=name, virtual_size=vsize, virtual_address=vaddr,
                raw_size=raw_size, raw_pointer=raw_ptr,
                characteristics=characteristics))

        return PEInfo(
            image_base=image_base,
            e_lfanew=e_lfanew,
            machine=machine,
            num_sections=num_sections,
            size_of_image=size_of_img,
            size_of_headers=size_of_hdrs,
            entry_point_rva=entry_rva,
            is_64bit=is_64bit,
            subsystem=subsystem,
            dll_characteristics=dll_char,
            data_directories=directories,
            sections=sections,
        )

    # ── Export directory ───────────────────────────────────────────────
    def parse_exports(self, info: Optional[PEInfo] = None) -> list[ExportEntry]:
        info = info or self.parse_headers()
        exp = info.data_directories[DIR_EXPORT]
        if not exp.rva or not exp.size:
            return []

        # IMAGE_EXPORT_DIRECTORY = 40 bytes
        hdr = self._rva(exp.rva, 40)
        (_chars, _ts, _maj, _min, _name_rva, ordinal_base,
         num_funcs, num_names, addr_of_funcs, addr_of_names,
         addr_of_ord) = struct.unpack_from('<IIHHIIIIIII', hdr, 0)

        # Read all three tables
        func_rvas = list(struct.unpack(
            f'<{num_funcs}I', self._rva(addr_of_funcs, num_funcs * 4)))
        name_rvas = list(struct.unpack(
            f'<{num_names}I', self._rva(addr_of_names, num_names * 4)))
        ord_arr   = list(struct.unpack(
            f'<{num_names}H', self._rva(addr_of_ord, num_names * 2)))

        # Map ordinal index → name
        idx_to_name: dict[int, str] = {}
        for i, name_rva in enumerate(name_rvas):
            name = self._read_cstring(self.base + name_rva, 256)
            idx_to_name[ord_arr[i]] = name

        exp_start = exp.rva
        exp_end   = exp.rva + exp.size

        out: list[ExportEntry] = []
        for i, func_rva in enumerate(func_rvas):
            if func_rva == 0:
                continue
            ordinal = ordinal_base + i
            name = idx_to_name.get(i)
            is_forwarder = exp_start <= func_rva < exp_end
            forwarder = None
            if is_forwarder:
                forwarder = self._read_cstring(self.base + func_rva, 256)
                va = 0
            else:
                va = self.base + func_rva
            out.append(ExportEntry(
                name=name, ordinal=ordinal, rva=func_rva, va=va,
                is_forwarder=is_forwarder, forwarder=forwarder))
        return out

    # ── Import directory ───────────────────────────────────────────────
    def parse_imports(self, info: Optional[PEInfo] = None) -> list[ImportModule]:
        info = info or self.parse_headers()
        imp = info.data_directories[DIR_IMPORT]
        if not imp.rva or not imp.size:
            return []

        # IMAGE_IMPORT_DESCRIPTOR = 20 bytes, array terminated by zero entry
        modules: list[ImportModule] = []
        desc_off = 0
        is_64 = info.is_64bit
        thunk_size = 8 if is_64 else 4
        ordinal_flag = (1 << 63) if is_64 else (1 << 31)
        thunk_fmt = '<Q' if is_64 else '<I'

        # Read up to 256 descriptors (more than any sane image)
        for _ in range(256):
            desc_bytes = self._rva(imp.rva + desc_off, 20)
            (olt, _ts, _fc, name_rva, ft) = struct.unpack('<IIIII', desc_bytes)
            if olt == 0 and name_rva == 0 and ft == 0:
                break
            dll_name = self._read_cstring(self.base + name_rva, 256)
            mod = ImportModule(dll_name=dll_name)

            # Walk the lookup table (prefer OriginalFirstThunk; fall back to FirstThunk)
            lookup_rva = olt if olt else ft
            iat_va_base = self.base + ft
            j = 0
            while True:
                thunk = self._rva(lookup_rva + j * thunk_size, thunk_size)
                v = struct.unpack(thunk_fmt, thunk)[0]
                if v == 0:
                    break
                iat_slot_va = iat_va_base + j * thunk_size
                bound = struct.unpack(thunk_fmt, self._read(iat_slot_va, thunk_size))[0]
                if v & ordinal_flag:
                    ordinal = v & 0xFFFF
                    mod.functions.append(ImportFunction(
                        name=None, ordinal=ordinal,
                        iat_va=iat_slot_va, bound_va=bound))
                else:
                    # v points to IMAGE_IMPORT_BY_NAME { Hint(2), Name(cstring) }
                    hint_name_rva = v
                    name = self._read_cstring(self.base + hint_name_rva + 2, 256)
                    mod.functions.append(ImportFunction(
                        name=name, ordinal=None,
                        iat_va=iat_slot_va, bound_va=bound))
                j += 1
                if j > 8192:
                    break
            modules.append(mod)
            desc_off += 20
        return modules

    # ── Symbol resolution ──────────────────────────────────────────────
    def resolve_export(self, name: str,
                       info: Optional[PEInfo] = None) -> Optional[ExportEntry]:
        info = info or self.parse_headers()
        for e in self.parse_exports(info):
            if e.name == name:
                return e
        return None

    # ── Internal byte readers ──────────────────────────────────────────
    def _read_cstring(self, va: int, max_len: int = 256) -> str:
        raw = self._read(va, max_len)
        nul = raw.find(b'\x00')
        if nul >= 0:
            raw = raw[:nul]
        return raw.decode('latin-1', errors='replace')


def directory_name(index: int) -> str:
    return _DIR_NAMES.get(index, f"Dir{index}")
