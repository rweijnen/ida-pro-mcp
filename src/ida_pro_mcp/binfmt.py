"""Lightweight binary format detection.

Stdlib only -- runs in the proxy, before any IDA instance exists, which is exactly when
an agent needs to decide whether to specify loader options.

This is deliberately not a full parser. It answers one question: does IDA's loader
already know what this is (in which case do NOT pass -p/-b, the loader handles it), or
is it a headerless blob (in which case the caller must supply processor/base or get a
silently wrong database)?
"""

import os
import struct

# ELF e_machine -> (processor sname, note)
_ELF_MACHINES = {
    0x02: "sparcb",
    0x03: "metapc",
    0x08: "mips",       # endianness resolved from EI_DATA below
    0x14: "ppc",
    0x15: "ppc",
    0x16: "s390",
    0x28: "arm",
    0x2A: "sh3",
    0x32: "ia64l",
    0x33: "tricore",
    0x3E: "metapc",
    0x53: "avr",
    0x5A: "m32r",
    0x6A: "QDSP6",
    0x8C: "tricore",
    0xB7: "arm",        # AArch64
    0xF3: "riscv",
}

_ELF_64_MACHINES = {0x3E, 0xB7, 0x32}

# PE IMAGE_FILE_MACHINE_* -> processor sname
_PE_MACHINES = {
    0x014C: ("metapc", 32),
    0x8664: ("metapc", 64),
    0x0200: ("ia64l", 64),
    0x01C0: ("arm", 32),
    0x01C4: ("arm", 32),     # ARMNT / Thumb-2
    0xAA64: ("arm", 64),
    0x0166: ("mipsl", 32),
    0x0266: ("mipsl", 32),
    0x01F0: ("ppc", 32),
    0x0EBC: ("ebc", 64),
    0x5032: ("riscv", 32),
    0x5064: ("riscv", 64),
}

_MACHO_CPUS = {
    0x00000007: ("metapc", 32),
    0x01000007: ("metapc", 64),
    0x0000000C: ("arm", 32),
    0x0100000C: ("arm", 64),
    0x00000012: ("ppc", 32),
    0x01000012: ("ppc", 64),
}


def probe_binary(path: str) -> dict:
    """Identify a binary's format and the processor IDA's loader will select.

    Returns a dict with:
        format: "PE" | "ELF" | "Mach-O" | "Java" | "Dalvik" | "unknown"
        recognized: bool -- True if IDA's loader will handle it unaided
        processor / bits / endian: best-effort detection (None when unknown)
        advice: what the caller should do about loader options
    """
    if not os.path.isfile(path):
        return {"error": f"File not found: {path}"}

    size = os.path.getsize(path)
    with open(path, "rb") as f:
        head = f.read(4096)

    result = _sniff(head, size)
    result["path"] = path
    result["filesize"] = size

    if result["recognized"]:
        result["advice"] = (
            "Recognized format -- do NOT pass processor, file_type or load_base. "
            "IDA's loader selects these correctly, and overriding them is more likely "
            "to corrupt the load than improve it."
        )
    else:
        result["advice"] = (
            "Headerless/unrecognized. IDA will load it with default settings "
            "(binary loader, metapc, base 0) which is almost certainly wrong and fails "
            "SILENTLY. Pass file_type='binary' plus the correct processor and "
            "load_base. Use list_processors to find the processor name."
        )
    return result


def _sniff(head: bytes, size: int) -> dict:
    def r(fmt, off):
        try:
            return struct.unpack_from(fmt, head, off)[0]
        except struct.error:
            return None

    # ELF
    if head[:4] == b"\x7fELF":
        is64 = head[4] == 2
        little = head[5] == 1
        end = "<" if little else ">"
        machine = r(end + "H", 18)
        proc = _ELF_MACHINES.get(machine)
        if proc == "mips":
            proc = "mipsl" if little else "mipsb"
        elif proc == "arm" and not little:
            proc = "armb"
        elif proc == "ppc" and little:
            proc = "ppcl"
        return {
            "format": "ELF",
            "recognized": True,
            "processor": proc,
            "bits": 64 if (is64 or machine in _ELF_64_MACHINES) else 32,
            "endian": "little" if little else "big",
            "detail": f"e_machine={machine:#x}",
        }

    # PE (MZ + PE\0\0 at e_lfanew)
    if head[:2] == b"MZ":
        e_lfanew = r("<I", 0x3C)
        if e_lfanew and e_lfanew + 6 < len(head) and head[e_lfanew:e_lfanew + 4] == b"PE\0\0":
            machine = r("<H", e_lfanew + 4)
            proc, bits = _PE_MACHINES.get(machine, (None, None))
            return {
                "format": "PE",
                "recognized": True,
                "processor": proc,
                "bits": bits,
                "endian": "little",
                "detail": f"IMAGE_FILE_MACHINE={machine:#06x}",
            }
        return {
            "format": "MZ",
            "recognized": True,
            "processor": "metapc",
            "bits": 16,
            "endian": "little",
            "detail": "DOS MZ executable (no PE header)",
        }

    # Mach-O
    magic = r("<I", 0)
    if magic in (0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE):
        swapped = magic in (0xCEFAEDFE, 0xCFFAEDFE)
        end = ">" if swapped else "<"
        cpu = r(end + "I", 4)
        proc, bits = _MACHO_CPUS.get(cpu, (None, None))
        return {
            "format": "Mach-O",
            "recognized": True,
            "processor": proc,
            "bits": bits,
            "endian": "little",
            "detail": f"cputype={cpu:#x}",
        }
    if magic in (0xBEBAFECA, 0xCAFEBABE) and size > 8:
        # Ambiguous: Mach-O fat binary and Java .class share CAFEBABE.
        return {
            "format": "Mach-O (fat) or Java class",
            "recognized": True,
            "processor": None,
            "bits": None,
            "endian": None,
            "detail": "CAFEBABE -- IDA's loader disambiguates",
        }

    if head[:4] == b"dex\n":
        return {"format": "Dalvik", "recognized": True, "processor": "dalvik",
                "bits": 32, "endian": "little", "detail": "DEX"}

    # Nothing matched.
    lead = head[:16]
    filler = None
    if lead == b"\xff" * 16:
        filler = "0xFF (erased flash)"
    elif lead == b"\x00" * 16:
        filler = "0x00"
    return {
        "format": "unknown",
        "recognized": False,
        "processor": None,
        "bits": None,
        "endian": None,
        "detail": (
            f"No recognized magic; leading bytes look like {filler}"
            if filler
            else f"No recognized magic; starts with {lead.hex(' ')}"
        ),
    }
