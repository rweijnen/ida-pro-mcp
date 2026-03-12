"""VTableExplorer integration - C++ vtable discovery and analysis.

Exposes the VTableExplorer IDA plugin's IDC functions as MCP tools.
All tools gracefully handle the case where the plugin is not loaded.
"""

import json
from typing import Annotated, Any

import idc

from .rpc import tool
from .sync import IDAError, idasync
from .utils import normalize_list_input, paginate, parse_address, pattern_filter


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


@tool
@idasync
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
    return paginate(data, offset, count)


@tool
@idasync
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
            results.append({"addr": f"{ea:#x}", "entries": data})
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})
    return results


@tool
@idasync
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
@idasync
def vtable_hierarchy(
    class_name: Annotated[str, "Class name to query"],
) -> dict:
    """Get inheritance hierarchy for a C++ class.

    Requires the VTableExplorer plugin to be loaded."""
    # Escape quotes in class name for IDC string literal
    safe_name = class_name.replace("\\", "\\\\").replace('"', '\\"')
    return _eval_vtable_idc(f'VTableExplorer_Hierarchy("{safe_name}")')
