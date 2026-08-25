"""IDA loader command-line argument construction.

Stdlib only -- imported by both `server.py` (the proxy, which runs outside IDA) and
`idalib_server.py`. Must never import IDA modules.

The same argument strings work for `ida.exe` argv and for
`idapro.open_database(args=...)`, so this is written once and shared.

Verified against IDA 9.4; see docs/headless-loading-plan.md for the test results
behind the encoding rules below.
"""

from .processors import PROCESSORS, split_processor_spec, validate_arm_options

# -b takes PARAGRAPHS, not bytes: byte address = value * 16.
PARAGRAPH_SIZE = 16


class LoaderArgError(ValueError):
    """Invalid loader arguments. Message is intended to be shown to the caller."""


def _hex(value: int) -> str:
    return format(value, "x")


def build_loader_args(
    processor: str | None = None,
    file_type: str | None = None,
    load_base: int | None = None,
    entry_point: int | None = None,
    device: str | None = None,
    idb_path: str | None = None,
    fresh_db: bool = False,
    extra: list[str] | None = None,
) -> list[str]:
    """Build IDA loader command-line arguments.

    Args:
        processor: Processor spec, e.g. "metapc", "tricore", or "arm:ARMv7-A;NEON".
            Only the ARM module accepts an option suffix.
        file_type: Loader/format prefix for -T, e.g. "binary" for a headerless blob.
        load_base: Byte address to load at. Must be 16-byte aligned, since -b encodes
            paragraphs.
        entry_point: Initial entry point / IP for -i.
        device: MCU device / chip variant, e.g. "tc37x", emitted as -DDEVICE=. Use the
            LEAF name, not the group path ("tc37x", not "tc3xx/tc37x"). "NONE" selects
            no device. Callers should validate against list_devices first: IDA ignores
            an unknown device silently, producing a database with no memory map.
        idb_path: Write the database here (-o) instead of alongside the input file.
            Lets the same binary be opened more than once -- each instance needs its
            own database file, since IDA locks the one it has open.
        fresh_db: Discard any existing database first (-c).
        extra: Raw arguments appended verbatim. Escape hatch; not validated.

    Returns:
        Argument list, suitable for subprocess argv or for joining into the `args`
        string of `idapro.open_database`.

    Raises:
        LoaderArgError: On invalid input. Note that IDA treats a bad -p option string
            as FATAL rather than ignoring it, so validating here is what stops a bad
            agent-supplied value from taking IDA down.
    """
    args: list[str] = []

    if fresh_db:
        args.append("-c")

    if file_type is not None:
        file_type = file_type.strip()
        if not file_type:
            raise LoaderArgError("file_type must be a non-empty string")
        args.append(f"-T{file_type}")

    if processor is not None:
        args.append(f"-p{_validated_processor(processor)}")

    if load_base is not None:
        if load_base < 0:
            raise LoaderArgError(f"load_base must be non-negative, got {load_base:#x}")
        if load_base % PARAGRAPH_SIZE:
            raise LoaderArgError(
                f"load_base {load_base:#x} is not {PARAGRAPH_SIZE}-byte aligned. "
                f"IDA's -b flag encodes paragraphs (byte address = value * "
                f"{PARAGRAPH_SIZE}), so unaligned bases cannot be expressed."
            )
        args.append(f"-b{_hex(load_base // PARAGRAPH_SIZE)}")

    if entry_point is not None:
        if entry_point < 0:
            raise LoaderArgError(
                f"entry_point must be non-negative, got {entry_point:#x}"
            )
        args.append(f"-i{_hex(entry_point)}")

    if device is not None:
        device = device.strip()
        if not device:
            raise LoaderArgError("device must be a non-empty string")
        if "/" in device:
            raise LoaderArgError(
                f"device {device!r} looks like a group path. IDA matches the leaf name "
                f"only -- use {device.rsplit('/', 1)[-1]!r}."
            )
        args.append(f"-DDEVICE={device}")

    if idb_path is not None:
        idb_path = idb_path.strip()
        if not idb_path:
            raise LoaderArgError("idb_path must be a non-empty string")
        args.append(f"-o{idb_path}")

    if extra:
        args.extend(extra)

    return args


def _validated_processor(spec: str) -> str:
    """Validate a processor spec and return it normalized."""
    spec = spec.strip()
    if not spec:
        raise LoaderArgError("processor must be a non-empty string")

    sname, options = split_processor_spec(spec)

    entry = PROCESSORS.get(sname.lower())
    if entry is None:
        raise LoaderArgError(
            f"Unknown processor {sname!r}. Use list_processors to see valid names. "
            f"Note that processor names are not the same as the module filenames in "
            f"IDA's procs/ directory (x86's module is 'pc', but the name is 'metapc')."
        )

    if options is None:
        return entry["sname"]

    if not entry.get("options"):
        raise LoaderArgError(
            f"Processor {entry['sname']!r} does not accept -p options; only the ARM "
            f"module does. Got {spec!r}."
        )

    validate_arm_options(entry, options)  # raises LoaderArgError on bad tokens
    return f"{entry['sname']}:{options}"


def format_args(args: list[str]) -> str:
    """Join loader args into the single string `idapro.open_database(args=...)` takes.

    For subprocess use pass the list directly to Popen instead -- never through a
    shell, since ARM option strings contain ';' which PowerShell treats as a statement
    separator.
    """
    return " ".join(args)
