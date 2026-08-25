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


def device_areas(cfg_path: str, device: str) -> list[str] | None:
    """Return the memory-area names a device section declares.

    Area lines look like:

        area DATA CPU2_DSPR       0x50000000:0x50018000   CPU2 Data Scratch Pad SRAM

    IDA turns each into a segment, so these names are exactly what should appear in the
    database if the device actually applied.

    Returns:
        The area names; an empty list if the device exists but declares none (e.g.
        TriCore's "generic" chipsets); or None if there is no such device section at
        all. Matching is case-sensitive, as IDA's is.
    """
    areas: list[str] = []
    in_section = False
    found_section = False
    try:
        with open(cfg_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("."):
                    body = line[1:].strip()
                    if body.lower().startswith("default"):
                        continue
                    leaves = {
                        e.strip().rsplit("/", 1)[-1]
                        for e in body.split(",")
                        if e.strip()
                    }
                    in_section = device in leaves
                    found_section = found_section or in_section
                    continue
                if in_section and line.startswith("area "):
                    parts = line.split()
                    if len(parts) >= 3:
                        areas.append(parts[2])
    except OSError:
        return None
    return areas if found_section else None


def check_device_applied(
    ida_dir: str, processor: str, device: str, segment_names: list[str]
) -> dict:
    """Check whether a requested device actually took effect in a loaded database.

    IDA silently ignores an unknown device, and the device name is not recorded
    anywhere readable in the database (verified on 9.4: no netnode holds it, and
    inf_get_procname() reports only the processor). So the only way to tell is to
    compare the loaded segments against the areas the device's config section declares.

    Returns a dict with "applied" (bool | None when undeterminable) and "detail".
    """
    if device.upper() == "NONE":
        return {
            "status": "applied",
            "applied": True,
            "detail": "DEVICE=NONE requested; no areas expected.",
        }

    cfg = os.path.join(ida_dir, "cfg", f"{cfg_name_for(processor)}.cfg")
    if not os.path.isfile(cfg):
        return {
            "status": "undeterminable",
            "applied": None,
            "detail": f"No device config for {processor!r}; nothing to verify against.",
        }

    expected = device_areas(cfg, device)

    if expected is None:
        parsed = parse_device_cfg(cfg)
        close = [d for d in parsed["devices"] if d.lower() == device.lower()]
        hint = (
            f" Did you mean {close[0]!r}? Device names are case-sensitive."
            if close
            else ""
        )
        return {
            "status": "unknown_device",
            "applied": False,
            "detail": (
                f"No device named {device!r} exists in "
                f"{os.path.basename(cfg)}, so IDA cannot have applied it.{hint}"
            ),
        }

    if not expected:
        return {
            "status": "undeterminable",
            "applied": None,
            "detail": (
                f"Device {device!r} exists but declares no memory areas (generic "
                f"chipsets do this), so its presence cannot be confirmed from the "
                f"segment map."
            ),
        }

    present = set(segment_names)
    missing = [a for a in expected if a not in present]
    found = len(expected) - len(missing)

    if found == 0:
        return {
            "status": "not_applied",
            "applied": False,
            "expected_areas": len(expected),
            "found_areas": 0,
            "detail": (
                f"Device {device!r} declares {len(expected)} memory areas but NONE are "
                f"present in the database. IDA ignored the device. The database has no "
                f"peripheral map and register names will be missing -- reload with a "
                f"corrected device."
            ),
        }

    if missing:
        return {
            "status": "mismatch",
            "applied": False,
            "expected_areas": len(expected),
            "found_areas": found,
            "missing": missing[:20],
            "detail": (
                f"Device mismatch: only {found}/{len(expected)} areas for {device!r} "
                f"are present. A DIFFERENT device's map is loaded -- related chips "
                f"share many area names, so a partial match means the database was "
                f"built for another variant of this family."
            ),
        }

    return {
        "status": "applied",
        "applied": True,
        "expected_areas": len(expected),
        "found_areas": found,
        "detail": f"Device {device!r} applied: all {len(expected)} areas present.",
    }


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
