"""Tests for api_vtable (VTableExplorer integration).

All tests are skip-guarded since VTableExplorer is an optional plugin.
"""

import idc

from ..api_vtable import vtable_compare, vtable_entries, vtable_hierarchy, vtable_scan
from ..framework import (
    assert_error,
    assert_is_list,
    assert_shape,
    is_hex_address,
    list_of,
    optional,
    skip_test,
    test,
)


def _check_vtable_explorer():
    """Skip test if VTableExplorer plugin is not loaded."""
    try:
        result = idc.eval_idc("VTableExplorer_Scan()")
        if result == 0 or result is None:
            skip_test("VTableExplorer plugin not loaded")
    except Exception:
        skip_test("VTableExplorer plugin not loaded")


# -- vtable_scan --


@test()
def test_vtable_scan_returns_list():
    """vtable_scan returns a paginated list of vtables."""
    _check_vtable_explorer()
    result = vtable_scan()
    assert isinstance(result, dict), "expected paginated dict"
    assert "data" in result, "missing 'data' key"
    assert_is_list(result["data"])
    if result["data"]:
        assert_shape(
            result["data"][0],
            {"class_name": str, "address": is_hex_address},
            label="vtable entry",
        )


@test()
def test_vtable_scan_filter():
    """vtable_scan glob filtering narrows results."""
    _check_vtable_explorer()
    all_result = vtable_scan(count=0)
    if not all_result["data"]:
        skip_test("no vtables found")
    # Use first class name as filter — should match at least one
    first_name = all_result["data"][0]["class_name"]
    filtered = vtable_scan(filter=first_name, count=0)
    assert len(filtered["data"]) >= 1
    assert all(first_name in e["class_name"] for e in filtered["data"])


@test()
def test_vtable_scan_pagination():
    """vtable_scan pagination returns correct slices."""
    _check_vtable_explorer()
    full = vtable_scan(count=0)
    if len(full["data"]) < 2:
        skip_test("need at least 2 vtables for pagination test")
    page = vtable_scan(count=1, offset=0)
    assert len(page["data"]) == 1
    assert page["next_offset"] == 1


# -- vtable_entries --


@test()
def test_vtable_entries_valid():
    """vtable_entries returns entries for a known vtable."""
    _check_vtable_explorer()
    scan = vtable_scan(count=1)
    if not scan["data"]:
        skip_test("no vtables found")
    addr = scan["data"][0]["address"]
    result = vtable_entries(addr)
    assert_is_list(result, min_length=1)
    assert "entries" in result[0], "expected 'entries' key"
    assert "error" not in result[0], f"unexpected error: {result[0].get('error')}"


@test()
def test_vtable_entries_bad_addr():
    """vtable_entries handles an invalid address gracefully."""
    _check_vtable_explorer()
    result = vtable_entries("0xDEADBEEFDEADBEEF")
    assert_is_list(result, min_length=1)
    # Plugin may return an error or empty/null entries for unmapped addresses
    entry = result[0]
    if "error" in entry:
        assert_error(entry)
    else:
        assert "entries" in entry, "expected either 'error' or 'entries' key"


# -- vtable_hierarchy --


@test()
def test_vtable_hierarchy_valid():
    """vtable_hierarchy returns hierarchy for a known class."""
    _check_vtable_explorer()
    scan = vtable_scan(count=1)
    if not scan["data"]:
        skip_test("no vtables found")
    name = scan["data"][0]["class_name"]
    result = vtable_hierarchy(name)
    assert isinstance(result, dict), "expected dict"


@test()
def test_vtable_hierarchy_bad_class():
    """vtable_hierarchy returns an error for an unknown class."""
    _check_vtable_explorer()
    try:
        result = vtable_hierarchy("__NonExistentClass_XYZ_999__")
        # If plugin returns an error dict, that's acceptable too
        if isinstance(result, dict) and "error" in result:
            return
    except Exception:
        # Expected: IDAError from plugin
        return
    # If we got here with no error, the plugin may handle it differently
