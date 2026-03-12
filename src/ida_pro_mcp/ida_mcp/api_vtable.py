"""VTableExplorer integration - C++ vtable discovery and analysis.

Exposes the VTableExplorer IDA plugin's IDC functions as MCP tools.
All tools gracefully handle the case where the plugin is not loaded.
"""

import json
from typing import Annotated, Any

import idc

from .rpc import tool
from .sync import IDAError, idaread
from .utils import normalize_list_input, paginate, parse_address, pattern_filter

# Fields to keep in compact vtable_scan results
_SCAN_COMPACT_KEYS = {"address", "class_name", "func_count", "is_abstract", "derived_count"}


def _eval_vtable_idc(expr: str) -> Any:
    """Call a VTableExplorer IDC function and parse the JSON result.

    Raises IDAError if the plugin is not loaded or the call fails.
    """
    result = idc.eval_idc(expr)
    if result is None or result == 0:
        raise IDAError("VTableExplorer plugin not loaded")
    try:
        return json.loads(result)
    except (json.JSONDecodeError, TypeError) as e:
        raise IDAError(f"VTableExplorer returned invalid JSON: {e}")


def _compact_scan_entry(entry: dict) -> dict:
    """Strip low-value fields from a vtable scan entry."""
    return {k: v for k, v in entry.items() if k in _SCAN_COMPACT_KEYS}


def _compact_vtable_entry(entry: dict) -> dict:
    """Strip slot_addr from a vtable function entry."""
    return {k: v for k, v in entry.items() if k != "slot_addr"}


@tool
@idaread
def vtable_scan(
    filter: Annotated[str, "Optional glob pattern to filter class names"] = "",
    count: Annotated[int, "Maximum results (0 = all)"] = 50,
    offset: Annotated[int, "Starting index"] = 0,
) -> dict:
    """List C++ virtual tables discovered by VTableExplorer plugin.

    Requires the VTableExplorer plugin to be loaded."""
    data = _eval_vtable_idc("VTableExplorer_Scan()")
    if not isinstance(data, list):
        raise IDAError("VTableExplorer_Scan() did not return a list")
    data = pattern_filter(data, filter, "class_name")
    data = [_compact_scan_entry(e) for e in data]
    return paginate(data, offset, count)


@tool
@idaread
def vtable_entries(
    addrs: Annotated[list[str] | str, "VTable address(es)"],
) -> list[dict]:
    """Get virtual function entries for specific vtable(s).

    Requires the VTableExplorer plugin to be loaded."""
    items = normalize_list_input(addrs)
    results = []
    for addr_str in items:
        try:
            ea = parse_address(addr_str)
            data = _eval_vtable_idc(f"VTableExplorer_Entries({ea:#x})")
            # Compact: strip slot_addr from entries, keep class_name for context
            entries = [_compact_vtable_entry(e) for e in data.get("entries", [])]
            results.append({
                "addr": f"{ea:#x}",
                "class_name": data.get("class_name", ""),
                "entries": entries,
            })
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})
    return results


@tool
@idaread
def vtable_compare(
    derived: Annotated[str, "Derived class vtable address"],
    base: Annotated[str, "Base class vtable address"],
) -> dict:
    """Compare derived and base class vtables to find overridden/new virtual functions.

    Requires the VTableExplorer plugin to be loaded."""
    derived_ea = parse_address(derived)
    base_ea = parse_address(base)
    return _eval_vtable_idc(
        f'VTableExplorer_Compare({derived_ea:#x}, {base_ea:#x})'
    )


@tool
@idaread
def vtable_hierarchy(
    class_name: Annotated[str, "Class name to query"],
) -> dict:
    """Get inheritance hierarchy for a C++ class.

    Requires the VTableExplorer plugin to be loaded."""
    # Escape quotes in class name for IDC string literal
    safe_name = class_name.replace("\\", "\\\\").replace('"', '\\"')
    return _eval_vtable_idc(f'VTableExplorer_Hierarchy("{safe_name}")')
