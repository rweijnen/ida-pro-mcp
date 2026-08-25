"""Core API Functions - IDB metadata and basic queries"""

import re
import time
from typing import Annotated

import idaapi
import idautils
import ida_auto
import ida_idp
import ida_nalt

from .rpc import tool
from .sync import idaread, idasync
from .zeromcp.jsonrpc import get_current_cancel_event

# Cached strings list: [(ea, text), ...]
_strings_cache: list[tuple[int, str]] | None = None


def _get_strings_cache() -> list[tuple[int, str]]:
    """Get cached strings, building cache on first access."""
    global _strings_cache
    if _strings_cache is None:
        _strings_cache = [(s.ea, str(s)) for s in idautils.Strings() if s is not None]
    return _strings_cache


def invalidate_strings_cache():
    """Clear the strings cache (call after IDB changes)."""
    global _strings_cache
    _strings_cache = None


# ============================================================================
# Auto-analysis progress
# ============================================================================

_AUTO_STATES = {
    ida_auto.st_Ready: "ready",
    ida_auto.st_Think: "thinking",
    ida_auto.st_Waiting: "waiting",
    ida_auto.st_Work: "working",
}

# Queue types, in roughly the order auto-analysis works through them. AU_FINAL is
# the last pass, so reaching it means analysis is nearly done.
_AUTO_QUEUES = {
    ida_auto.AU_NONE: "none",
    ida_auto.AU_UNK: "make-unknown",
    ida_auto.AU_CODE: "make-code",
    ida_auto.AU_WEAK: "weak-code",
    ida_auto.AU_PROC: "make-procedure",
    ida_auto.AU_TAIL: "function-tails",
    ida_auto.AU_FCHUNK: "function-chunks",
    ida_auto.AU_USED: "reanalyze-operands",
    ida_auto.AU_TYPE: "apply-types",
    ida_auto.AU_LIBF: "flirt-signatures",
    ida_auto.AU_LBF2: "flirt-signatures-2",
    ida_auto.AU_LBF3: "flirt-signatures-3",
    ida_auto.AU_CHLB: "load-signatures",
    ida_auto.AU_FINAL: "final-pass",
}


class _AnalysisTracker(ida_idp.IDB_Hooks):
    """Records analysis lifecycle events as they happen.

    Polling can only report the state at sample time; these events give the exact
    moment analysis finished even when nobody was watching. That is what makes
    analysis_status cheap enough to check casually instead of blocking on a wait.
    """

    def __init__(self):
        super().__init__()
        self.loaded_at: float | None = None
        self.completed_at: float | None = None
        self.completions: int = 0

    def loader_finished(self, *args):
        self.loaded_at = time.time()
        self.completed_at = None
        return 0

    def auto_empty_finally(self, *args):
        self.completed_at = time.time()
        self.completions += 1
        return 0


_tracker: _AnalysisTracker | None = None


def install_analysis_tracker() -> bool:
    """Install the analysis lifecycle hook. Idempotent."""
    global _tracker
    if _tracker is not None:
        return True
    try:
        tracker = _AnalysisTracker()
        if not tracker.hook():
            return False
        _tracker = tracker
        return True
    except Exception as e:  # hooks are best-effort; status still works without them
        print(f"[MCP] Could not install analysis tracker: {e}")
        return False


def _is_gui() -> bool:
    """True in GUI IDA, false under idalib/headless.

    The distinction matters for waiting: in the GUI the UI thread drives the
    analysis queue, so polling makes progress. Under idalib nothing drives it --
    auto_is_ok() stays false indefinitely until auto_wait() is called, which is
    what actually advances the queue.
    """
    try:
        return bool(idaapi.is_idaq())
    except Exception:
        return False


@idasync
def _auto_wait_blocking() -> None:
    """Drive the analysis queue to completion (headless only).

    Safe under idalib, which is single-threaded anyway. Never use this in the
    GUI: it would occupy the main thread for the whole analysis, freezing the UI
    and stalling every other request behind the lock.
    """
    ida_auto.auto_wait()


@idaread
def _auto_snapshot() -> dict:
    """Read auto-analysis state. Runs briefly on the IDA main thread."""
    display = ida_auto.auto_display_t()
    have_display = ida_auto.get_auto_display(display)

    ea = display.ea if have_display else idaapi.BADADDR
    queue = display.type if have_display else ida_auto.AU_NONE
    state = display.state if have_display else ida_auto.st_Ready

    snapshot = {
        "complete": bool(ida_auto.auto_is_ok()),
        "enabled": bool(ida_auto.is_auto_enabled()),
        "state": _AUTO_STATES.get(state, f"unknown({state})"),
        "queue": _AUTO_QUEUES.get(queue, f"unknown({queue})"),
        "queue_id": int(queue),
        "current_ea": None if ea == idaapi.BADADDR else hex(ea),
        "final_pass": queue == ida_auto.AU_FINAL,
    }

    if _tracker is not None:
        now = time.time()
        if _tracker.completed_at is not None:
            snapshot["completed_at"] = _tracker.completed_at
            snapshot["completed_sec_ago"] = round(now - _tracker.completed_at, 1)
        if _tracker.loaded_at is not None:
            reference = _tracker.completed_at or now
            snapshot["analysis_elapsed_sec"] = round(reference - _tracker.loaded_at, 1)

    return snapshot


@tool
def analysis_status() -> dict:
    """Report whether IDA's auto-analysis is still running, and what it is doing.

    This is cheap -- completion is recorded by an event hook, not measured by
    polling -- so it is fine to check whenever you want to know where things
    stand. It is the right tool for a long analysis: rather than waiting, do
    other work and check back.

    Returns `complete` (the thing you usually want), plus the current queue, the
    address being worked on, and `analysis_elapsed_sec`. A `current_ea` that
    keeps moving between calls means progress; one that is stuck does not.
    `final_pass` is true during the last queue, so analysis is nearly done.

    Results from other tools are incomplete while `complete` is false. For a
    short analysis, wait_for_analysis avoids checking repeatedly.
    """
    return _auto_snapshot()


@tool
def wait_for_analysis(
    timeout_sec: Annotated[float, "Give up after this long (seconds)"] = 120.0,
    poll_interval: Annotated[float, "Seconds between checks"] = 0.5,
) -> dict:
    """Wait, up to timeout_sec, for IDA's auto-analysis to finish.

    Convenience for the common case where analysis takes seconds to a couple of
    minutes: one call instead of checking repeatedly. Call it after loading a
    binary, and after operations that queue more work (define_func, patch,
    undefine, or a rebase).

    DO NOT use this to sit out a long analysis. Large or complex binaries can
    take a very long time, and nothing useful happens while you wait. If this
    returns timed_out=true, switch to checking analysis_status between other
    work rather than calling this again in a loop -- completion is recorded by
    an event hook, so that check is cheap and exact.

    Returns the final analysis_status plus how long the wait took. A timeout
    returns timed_out=true rather than raising, with the partial state still
    visible; analysis is not affected either way and keeps running.

    In GUI IDA this does NOT hold the main thread: it samples the analysis state
    briefly and sleeps in between, so other requests and the UI stay responsive
    while it waits.

    Headless (idalib) works differently. Nothing drives the analysis queue there,
    so polling would never finish; the wait instead runs to completion in one
    call and timeout_sec does not apply.
    """
    if timeout_sec <= 0:
        return {"error": "timeout_sec must be positive"}
    poll_interval = min(max(poll_interval, 0.05), 5.0)

    if not _is_gui():
        started = time.monotonic()
        _auto_wait_blocking()
        snapshot = _auto_snapshot()
        return {
            **snapshot,
            "waited_sec": round(time.monotonic() - started, 2),
            "timed_out": False,
            "mode": "headless-blocking",
            "note": (
                "Headless: analysis was driven to completion with auto_wait(); "
                "timeout_sec does not apply in this mode."
            ),
        }

    cancel_event = get_current_cancel_event()
    started = time.monotonic()
    deadline = started + timeout_sec

    while True:
        snapshot = _auto_snapshot()
        elapsed = time.monotonic() - started

        if snapshot["complete"]:
            return {**snapshot, "waited_sec": round(elapsed, 2), "timed_out": False}

        if cancel_event is not None and cancel_event.is_set():
            return {
                **snapshot,
                "waited_sec": round(elapsed, 2),
                "timed_out": False,
                "cancelled": True,
            }

        if time.monotonic() >= deadline:
            return {
                **snapshot,
                "waited_sec": round(elapsed, 2),
                "timed_out": True,
                "note": (
                    f"Analysis still running after {timeout_sec:g}s and may take much "
                    f"longer. Do not keep waiting -- get on with other work and call "
                    f"analysis_status when you need to know, which is cheap. Tool "
                    f"results are incomplete until it reports complete."
                ),
            }

        time.sleep(min(poll_interval, max(0.0, deadline - time.monotonic())))


# Cached function list: [Function(...), ...]
_funcs_cache: list | None = None  # list[Function], forward ref to avoid circular import


def _get_funcs_cache():
    """Get cached function list, building cache on first access."""
    global _funcs_cache
    if _funcs_cache is None:
        _funcs_cache = [get_function(addr) for addr in idautils.Functions()]
    return _funcs_cache


def invalidate_funcs_cache():
    """Clear the function cache (call after renames or function changes)."""
    global _funcs_cache
    _funcs_cache = None


# Cached globals list: [Global(...), ...]
_globals_cache: list | None = None  # list[Global], forward ref to avoid circular import


def _get_globals_cache():
    """Get cached globals list, building cache on first access."""
    global _globals_cache
    if _globals_cache is None:
        _globals_cache = [
            Global(addr=hex(addr), name=name)
            for addr, name in idautils.Names()
            if not idaapi.get_func(addr) and name is not None
        ]
    return _globals_cache


def invalidate_globals_cache():
    """Clear the globals cache (call after renames or data changes)."""
    global _globals_cache
    _globals_cache = None


def init_caches():
    """Build caches on plugin startup."""
    t0 = time.perf_counter()
    strings = _get_strings_cache()
    t1 = time.perf_counter()
    print(f"[MCP] Cached {len(strings)} strings in {(t1 - t0) * 1000:.0f}ms")

    funcs = _get_funcs_cache()
    t2 = time.perf_counter()
    print(f"[MCP] Cached {len(funcs)} functions in {(t2 - t1) * 1000:.0f}ms")

    globals_ = _get_globals_cache()
    t3 = time.perf_counter()
    print(f"[MCP] Cached {len(globals_)} globals in {(t3 - t2) * 1000:.0f}ms")


@tool
@idasync
def refresh_caches() -> dict:
    """Force-refresh all caches (strings, functions, globals).

    Call this after bulk modifications (e.g. py_eval scripts that create
    or rename functions) to ensure list_funcs/list_globals return fresh data.
    """
    invalidate_strings_cache()
    invalidate_funcs_cache()
    invalidate_globals_cache()

    t0 = time.perf_counter()
    strings = _get_strings_cache()
    t1 = time.perf_counter()
    funcs = _get_funcs_cache()
    t2 = time.perf_counter()
    globals_ = _get_globals_cache()
    t3 = time.perf_counter()

    return {
        "strings": len(strings),
        "functions": len(funcs),
        "globals": len(globals_),
        "time_ms": round((t3 - t0) * 1000),
    }


from .utils import (
    Function,
    ConvertedNumber,
    Global,
    Import,
    Page,
    NumberConversion,
    ListQuery,
    normalize_list_input,
    normalize_dict_list,
    get_function,
    paginate,
    pattern_filter,
)


# ============================================================================
# Core API Functions
# ============================================================================


def _parse_func_query(query: str) -> int:
    """Fast path for common function query patterns. Returns ea or BADADDR."""
    q = query.strip()

    # 0x<hex> - direct address
    if q.startswith("0x") or q.startswith("0X"):
        try:
            return int(q, 16)
        except ValueError:
            pass

    # sub_<hex> - IDA auto-named function
    if q.startswith("sub_"):
        try:
            return int(q[4:], 16)
        except ValueError:
            pass

    return idaapi.BADADDR


@tool
@idaread
def lookup_funcs(
    queries: Annotated[list[str] | str, "Address(es) or name(s)"],
) -> list[dict]:
    """Get functions by address or name (auto-detects)"""
    queries = normalize_list_input(queries)

    # Treat empty/"*" as "all functions" - but add limit
    if not queries or (len(queries) == 1 and queries[0] in ("*", "")):
        all_funcs = []
        for addr in idautils.Functions():
            all_funcs.append(get_function(addr))
            if len(all_funcs) >= 1000:
                break
        return [{"query": "*", "fn": fn, "error": None} for fn in all_funcs]

    results = []
    for query in queries:
        try:
            # Fast path: 0x<ea> or sub_<ea>
            ea = _parse_func_query(query)

            # Slow path: name lookup
            if ea == idaapi.BADADDR:
                ea = idaapi.get_name_ea(idaapi.BADADDR, query)

            if ea != idaapi.BADADDR:
                func = get_function(ea, raise_error=False)
                if func:
                    results.append({"query": query, "fn": func, "error": None})
                else:
                    results.append(
                        {"query": query, "fn": None, "error": "Not a function"}
                    )
            else:
                results.append({"query": query, "fn": None, "error": "Not found"})
        except Exception as e:
            results.append({"query": query, "fn": None, "error": str(e)})

    return results


@tool
def int_convert(
    inputs: Annotated[
        list[NumberConversion] | NumberConversion,
        "Convert numbers to various formats (hex, decimal, binary, ascii)",
    ],
) -> list[dict]:
    """Convert numbers to different formats"""
    inputs = normalize_dict_list(inputs, lambda s: {"text": s, "size": 64})

    results = []
    for item in inputs:
        text = item.get("text", "")
        size = item.get("size")

        try:
            value = int(text, 0)
        except ValueError:
            results.append(
                {"input": text, "result": None, "error": f"Invalid number: {text}"}
            )
            continue

        if not size:
            size = 0
            n = abs(value)
            while n:
                size += 1
                n >>= 1
            size += 7
            size //= 8

        try:
            bytes_data = value.to_bytes(size, "little", signed=True)
        except OverflowError:
            results.append(
                {
                    "input": text,
                    "result": None,
                    "error": f"Number {text} is too big for {size} bytes",
                }
            )
            continue

        ascii_str = ""
        for byte in bytes_data.rstrip(b"\x00"):
            if byte >= 32 and byte <= 126:
                ascii_str += chr(byte)
            else:
                ascii_str = None
                break

        results.append(
            {
                "input": text,
                "result": ConvertedNumber(
                    decimal=str(value),
                    hexadecimal=hex(value),
                    bytes=bytes_data.hex(" "),
                    ascii=ascii_str,
                    binary=bin(value),
                ),
                "error": None,
            }
        )

    return results


@tool
@idaread
def list_funcs(
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "List functions with optional filtering and pagination",
    ],
) -> list[Page[Function]]:
    """List functions"""
    queries = normalize_dict_list(
        queries, lambda s: {"offset": 0, "count": 50, "filter": s}
    )
    all_functions = _get_funcs_cache()

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter(all_functions, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


@tool
@idaread
def list_globals(
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "List global variables with optional filtering and pagination",
    ],
) -> list[Page[Global]]:
    """List globals"""
    queries = normalize_dict_list(
        queries, lambda s: {"offset": 0, "count": 50, "filter": s}
    )
    all_globals = _get_globals_cache()

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter(all_globals, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


@tool
@idaread
def imports(
    offset: Annotated[int, "Offset"],
    count: Annotated[int, "Count (0=all)"],
) -> Page[Import]:
    """List imports"""
    nimps = ida_nalt.get_import_module_qty()

    rv = []
    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i)
        if not module_name:
            module_name = "<unnamed>"

        def imp_cb(ea, symbol_name, ordinal, acc):
            if not symbol_name:
                symbol_name = f"#{ordinal}"
            acc += [Import(addr=hex(ea), imported_name=symbol_name, module=module_name)]
            return True

        def imp_cb_w_context(ea, symbol_name, ordinal):
            return imp_cb(ea, symbol_name, ordinal, rv)

        ida_nalt.enum_import_names(i, imp_cb_w_context)

    return paginate(rv, offset, count)


@tool
@idaread
def find_regex(
    pattern: Annotated[str, "Regex pattern to search for in strings"],
    limit: Annotated[int, "Max matches (default: 30, max: 500)"] = 30,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> dict:
    """Search strings with case-insensitive regex patterns"""
    if limit <= 0:
        limit = 30
    if limit > 500:
        limit = 500

    matches = []
    regex = re.compile(pattern, re.IGNORECASE)
    strings = _get_strings_cache()

    skipped = 0
    more = False
    for ea, text in strings:
        if regex.search(text):
            if skipped < offset:
                skipped += 1
                continue
            if len(matches) >= limit:
                more = True
                break
            matches.append({"addr": hex(ea), "string": text})

    return {
        "n": len(matches),
        "matches": matches,
        "cursor": {"next": offset + limit} if more else {"done": True},
    }
