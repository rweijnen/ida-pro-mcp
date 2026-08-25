"""Curated table of IDA processor types.

Stdlib only -- imported by `server.py` (the proxy, outside IDA) and `loader_args.py`.
Must never import IDA modules.

NOTE: This table is curated rather than enumerated because IDA 9.4 exposes no way to
list processors from Python. `idp_desc_t` (with exactly the fields wanted: `path`,
`family`, `names` -> `idp_name_t.sname`/`lname`/`hidden`) *is* wrapped, but nothing
returns a populated one -- `get_idp_descs()` exists in the C++ SDK's loader.hpp and was
never exposed. A `grep` for it across the whole IDA 9.4 python/ tree returns zero hits.

Listing IDA's procs/ directory is NOT a substitute: module filename != processor name.
x86's module is `pc` but the names are `metapc`, `8086`, `p3`, `athlon`, ...; `mc68k`
covers `68000`, `68020`, `colfire`. Worse, `pc` looks plausible and collides with
PowerPC.

If a future IDA exposes get_idp_descs(), this table can be replaced by enumeration.

Source: https://docs.hex-rays.com/ida-actions/options#processor-type
        https://docs.hex-rays.com/ida-actions/options#arm-processor-specifics
"""

# ARM is the only module accepting a -p option suffix. Grammar verified on IDA 9.4:
# the first token must be a base architecture or a core name; modifiers follow,
# ';'-separated. A modifier alone is rejected, and ANY unrecognised token is FATAL --
# IDA aborts rather than ignoring it. So these lists are the validation whitelist.
_ARM_VARIANTS = [
    "ARMv4", "ARMv4T", "ARMv5T", "ARMv5TE", "ARMv5TEJ",
    "ARMv6", "ARMv6T2", "ARMv6M",
    "ARMv7-A", "ARMv7-R", "ARMv7-M", "ARMv7E-M",
    "ARMv8-A", "ARMv8-M", "ARMv8-R",
]

_ARM_CORES = [
    "ARM7TDMI", "ARM720T", "ARM920T", "ARM926EJ-S", "ARM946E-S",
    "ARM1136J-S", "ARM1176JZ-S", "PXA270", "StrongARM",
    "Cortex-M0", "Cortex-M3", "Cortex-M4", "Cortex-M7",
    "Cortex-R4", "Cortex-A8", "Cortex-A9", "Cortex-A15", "Cortex-A53",
]

_ARM_MODIFIERS = [
    "NEON", "NEON-FMA", "NoNEON",
    "VFPv1", "VFPv2", "VFPv3", "VFPv4", "NoVFP",
    "Thumb", "Thumb-2", "NoThumb",
    "ARM", "NoARM",
    "XScale",
    "WMMXv1", "WMMXv2", "NoWMMX",
]

_ARM_OPTIONS = {
    "separator": ";",
    "variants": _ARM_VARIANTS,
    "cores": _ARM_CORES,
    "modifiers": _ARM_MODIFIERS,
    # `armmeta` is documented as "decode all known instructions" but is REJECTED by
    # IDA 9.4 in every casing tested, so it cannot be the "core unknown" default.
    "unknown_core_default": "ARMv7-A",
    "example": "arm:ARMv7-A;NEON;VFPv3",
}


def _p(sname, lname, family, bits, endian, **extra):
    return dict(sname=sname, lname=lname, family=family, bits=bits, endian=endian, **extra)


_TABLE = [
    # x86 / x64
    _p("metapc", "Intel 80x86 (generic, recommended)", "x86", [16, 32, 64], "little"),
    _p("8086", "Intel 8086", "x86", [16], "little"),
    _p("80386p", "Intel 80386 (protected mode)", "x86", [32], "little"),
    _p("80486p", "Intel 80486 (protected mode)", "x86", [32], "little"),
    _p("p3", "Intel Pentium III", "x86", [32], "little"),
    _p("p4", "Intel Pentium 4", "x86", [32], "little"),
    _p("athlon", "AMD Athlon", "x86", [32], "little"),

    # ARM
    _p("arm", "ARM (little-endian)", "ARM", [32, 64], "little",
       options=_ARM_OPTIONS,
       notes=[
           "AArch64 requires the code segment set to 64-bit; it is not a -p option.",
           "Thumb mode is the T segment register, set AFTER load and BEFORE defining "
           "code -- changing T destroys instructions in the affected range.",
       ]),
    _p("armb", "ARM (big-endian)", "ARM", [32, 64], "big", options=_ARM_OPTIONS),

    # MIPS
    _p("mipsl", "MIPS (little-endian)", "MIPS", [32, 64], "little"),
    _p("mipsb", "MIPS (big-endian)", "MIPS", [32, 64], "big"),
    _p("mipsrl", "MIPS RSP (little-endian)", "MIPS", [32], "little"),
    _p("mipsr", "MIPS RSP (big-endian)", "MIPS", [32], "big"),
    _p("r5900l", "MIPS R5900 (little-endian)", "MIPS", [32, 64], "little"),

    # PowerPC
    _p("ppc", "PowerPC (big-endian)", "PowerPC", [32, 64], "big"),
    _p("ppcl", "PowerPC (little-endian)", "PowerPC", [32, 64], "little"),

    # Automotive / embedded
    _p("tricore", "Infineon TriCore", "TriCore", [32], "little",
       notes=[
           "Device selection (TC1xxx / TC2xx / TC3xx / TC4x) is a DEVICE= config "
           "directive, not a -p option. The module default is tc1xxx/tc1766, so a "
           "TC3xx image gets a TC1766 memory map unless the device is set.",
       ]),
    _p("sh3", "Hitachi/Renesas SH-3 (little-endian)", "SuperH", [32], "little"),
    _p("sh3b", "Hitachi/Renesas SH-3 (big-endian)", "SuperH", [32], "big"),
    _p("sh4", "Hitachi/Renesas SH-4 (little-endian)", "SuperH", [32], "little"),
    _p("sh4b", "Hitachi/Renesas SH-4 (big-endian)", "SuperH", [32], "big"),
    _p("m32r", "Mitsubishi M32R", "M32R", [32], "big"),
    _p("avr", "Atmel AVR", "AVR", [8], "little"),
    _p("msp430", "TI MSP430", "MSP430", [16], "little"),
    _p("m740", "Mitsubishi 740", "740", [8], "little"),
    _p("78k0", "NEC 78K/0", "78K", [8], "little"),
    _p("h8300", "Hitachi H8/300", "H8", [16], "big"),
    _p("6811", "Motorola 68HC11", "68HC", [8], "big"),
    _p("z80", "Zilog Z80", "Z80", [8], "little"),
    _p("8051", "Intel 8051", "8051", [8], "little"),
    _p("c166", "Infineon C166", "C166", [16], "little"),
    _p("QDSP6", "Qualcomm Hexagon (QDSP6)", "Hexagon", [32], "little"),
    _p("arc", "ARC", "ARC", [32], "little"),
    _p("ebc", "EFI Byte Code", "EBC", [32, 64], "little"),

    # Motorola 68k
    _p("68000", "Motorola 68000", "68K", [32], "big"),
    _p("68010", "Motorola 68010", "68K", [32], "big"),
    _p("68020", "Motorola 68020", "68K", [32], "big"),
    _p("68040", "Motorola 68040", "68K", [32], "big"),
    _p("68330", "Motorola 68330", "68K", [32], "big"),
    # Note the capitalisation: IDA rejects "colfire" (as the docs spell it) and
    # "coldfire"; the accepted name is "ColdFire".
    _p("ColdFire", "Motorola ColdFire", "68K", [32], "big"),

    # Other
    _p("sparcb", "SPARC (big-endian)", "SPARC", [32, 64], "big"),
    _p("alphal", "DEC Alpha (little-endian)", "Alpha", [64], "little"),
    _p("alphab", "DEC Alpha (big-endian)", "Alpha", [64], "big"),
    _p("ia64l", "Intel Itanium IA-64 (little-endian)", "IA64", [64], "little"),
    _p("ia64b", "Intel Itanium IA-64 (big-endian)", "IA64", [64], "big"),
    _p("hppa", "HP PA-RISC", "PA-RISC", [32, 64], "big"),
    # These require their own loader and cannot be combined with -Tbinary; the format
    # is detected from the file, so -p should not be specified for them at all.
    _p("java", "Java bytecode", "Java", [32], "big", requires_own_loader=True),
    _p("dalvik", "Android Dalvik", "Dalvik", [32], "little", requires_own_loader=True),
]

#: Lookup by lowercased short name.
PROCESSORS = {entry["sname"].lower(): entry for entry in _TABLE}


def list_processors(family: str | None = None) -> list[dict]:
    """Return the curated processor table, optionally filtered by family."""
    if family is None:
        return list(_TABLE)
    needle = family.lower()
    return [e for e in _TABLE if e["family"].lower() == needle]


def split_processor_spec(spec: str) -> tuple[str, str | None]:
    """Split "arm:ARMv7-A;NEON" into ("arm", "ARMv7-A;NEON")."""
    sname, sep, options = spec.partition(":")
    if not sep:
        return sname.strip(), None
    return sname.strip(), options.strip()


def validate_arm_options(entry: dict, options: str) -> None:
    """Validate an ARM -p option string against the known grammar.

    IDA aborts fatally on an unrecognised token rather than ignoring it, so this runs
    before the value ever reaches IDA.

    Raises:
        LoaderArgError: with a message naming the offending token.
    """
    from .loader_args import LoaderArgError  # local import: avoids a cycle

    opts = entry["options"]
    tokens = [t.strip() for t in options.split(opts["separator"])]
    if not tokens or not tokens[0]:
        raise LoaderArgError(
            f"Empty option string for {entry['sname']!r}. "
            f"Example: {opts['example']!r}"
        )

    heads = {t.lower(): t for t in opts["variants"] + opts["cores"]}
    mods = {t.lower(): t for t in opts["modifiers"]}

    head = tokens[0]
    if head.lower() not in heads:
        if head.lower() in mods:
            raise LoaderArgError(
                f"{head!r} is a modifier and cannot appear first. The first token must "
                f"be a base architecture or core name. Example: {opts['example']!r}"
            )
        raise LoaderArgError(
            f"Unknown ARM architecture/core {head!r}. "
            f"Valid architectures: {', '.join(opts['variants'])}. "
            f"Valid cores: {', '.join(opts['cores'])}."
        )

    for tok in tokens[1:]:
        if tok.lower() not in mods:
            raise LoaderArgError(
                f"Unknown ARM option {tok!r}. Valid modifiers: "
                f"{', '.join(opts['modifiers'])}."
            )
