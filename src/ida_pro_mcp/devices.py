"""MCU device (chip variant) discovery from IDA's processor config files.

Stdlib only -- runs in the proxy, outside IDA.

Many MCU processor modules cover a family whose members differ in memory layout and
peripheral registers. IDA calls this the "device", and it is selected by the DEVICE
config parameter, NOT by a -p option:

    ida -ptricore -DDEVICE=tc37x input_file

Per ida.cfg: "By default, at the database creation time, IDA displays a dialog box with
the list of the available devices for the current processor. The DEVICE parameter can be
used to skip this dialog and silently use the specified device."

That dialog is invisible under -A, so without an explicit DEVICE the module's `.default`
is used -- e.g. a TriCore TC3xx image silently gets a TC1766 memory map.

Verified on IDA 9.4 with a TriCore image:

    (no DEVICE)            -> 10 segments, including TC1766_ED   [wrong]
    -DDEVICE=tc37x         -> 57 segments                        [correct]
    -DDEVICE=tc39xX        -> 75 segments                        [correct]
    -DDEVICE=tc3xx/tc37x   ->  1 segment   (path form not accepted)
    -DDEVICE=bogus999      ->  1 segment   (SILENTLY ignored)

Note the last line: unlike a bad ARM -p option (which is fatal), an unknown device is
silently ignored and yields a database with no memory map at all. Validating the name
before spawning is therefore essential.
"""

import os

#: Processors whose config file is not named after the processor itself.
#: IDA names these files after the *module*, not the processor name.
_CFG_OVERRIDES = {
    "8051": "i51",
    "sh3b": "sh3",
    "sh4": "sh3",
    "sh4b": "sh3",
    "ppcl": "ppc",
    "armb": "arm",
}


def cfg_name_for(processor: str) -> str:
    """Config file basename (without .cfg) for a processor name."""
    return _CFG_OVERRIDES.get(processor, processor)


def parse_device_cfg(path: str) -> dict:
    """Parse device names out of an IDA processor config file.

    Device sections begin with a line like `.tc3xx/tc37x` at column 0, and a section may
    declare several comma-separated aliases. The default is `.default <name>`.

    IDA matches on the LEAF name (`tc37x`), not the full path (`tc3xx/tc37x`).

    Returns:
        {"devices": [...], "default": str | None, "groups": {group: [leaf, ...]}}
    """
    devices: list[str] = []
    groups: dict[str, list[str]] = {}
    default = None
    seen = set()

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line.startswith("."):
                    continue
                body = line[1:].strip()
                if not body:
                    continue
                if body.lower().startswith("default"):
                    parts = body.split(None, 1)
                    if len(parts) > 1:
                        default = parts[1].strip().rsplit("/", 1)[-1]
                    continue
                for entry in body.split(","):
                    entry = entry.strip()
                    if not entry:
                        continue
                    group, _, leaf = entry.rpartition("/")
                    leaf = leaf or entry
                    if leaf not in seen:
                        seen.add(leaf)
                        devices.append(leaf)
                    if group:
                        groups.setdefault(group, [])
                        if leaf not in groups[group]:
                            groups[group].append(leaf)
    except OSError:
        return {"devices": [], "default": None, "groups": {}}

    return {"devices": devices, "default": default, "groups": groups}


def list_devices(ida_dir: str, processor: str) -> dict:
    """List selectable devices for a processor.

    Args:
        ida_dir: IDA installation directory.
        processor: IDA processor name, e.g. "tricore".

    Returns:
        A dict with "devices", "default" and "groups", or "error"/"devices": [] when the
        processor has no device configuration.
    """
    cfg = os.path.join(ida_dir, "cfg", f"{cfg_name_for(processor)}.cfg")
    if not os.path.isfile(cfg):
        return {
            "devices": [],
            "default": None,
            "groups": {},
            "note": f"No device configuration for {processor!r} ({cfg} not found). "
                    f"This processor does not use device selection.",
        }
    result = parse_device_cfg(cfg)
    result["cfg_path"] = cfg
    if not result["devices"]:
        result["note"] = (
            f"{os.path.basename(cfg)} defines no devices; this processor does not use "
            f"device selection."
        )
    return result
