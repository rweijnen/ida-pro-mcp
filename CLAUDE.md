# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

IDA Pro MCP Server: exposes IDA Pro / idalib functionality to MCP clients.

Main pieces:
- `src/ida_pro_mcp/server.py`: MCP server entrypoint
- `src/ida_pro_mcp/idalib_server.py`: headless idalib server
- `src/ida_pro_mcp/ida_mcp/`: IDA/plugin-side APIs

Proxy-side modules (stdlib only, **must never import IDA**) — `server.py` runs outside
IDA, so anything it needs lives here rather than in `ida_mcp/`:
- `loader_args.py`: builds IDA loader command-line args (`-p`, `-T`, `-b`, `-i`, `-DDEVICE=`, `-o`, `-c`).
  The same strings work for `ida.exe` argv and `idapro.open_database(args=...)`.
- `processors.py`: curated processor-name table. Curated because IDA 9.4 exposes no way
  to enumerate processors from Python (`idp_desc_t` is wrapped, `get_idp_descs()` is not).
  Names are case-sensitive and are NOT the `procs/` filenames (x86's module is `pc`, the
  name is `metapc`). Every name in it was validated by loading with `-p<name>`.
- `devices.py`: parses MCU device names from `cfg/<proc>.cfg`.
- `binfmt.py`: pre-load format detection (PE/ELF/Mach-O/DEX, plus blob detection).

Important API modules:
- `api_core.py`: IDB metadata, functions, strings, imports, auto-analysis progress
- `api_analysis.py`: decompilation, disassembly, xrefs, paths, pattern search
- `api_memory.py`: bytes/ints/strings, patching
- `api_types.py`: structs, type inference, type application
- `api_modify.py`: comments, renaming, asm patching, ARM Thumb mode (`T` register)
- `api_stack.py`: stack frame operations
- `api_debug.py`: debugger control, unsafe / low priority for tests
- `api_python.py`: execute Python in IDA context
- `api_resources.py`: `ida://` MCP resources
- `api_vtable.py`: vtable scanning, entries, hierarchy (requires VTableExplorer plugin)

## Core implementation rules

### IDA thread safety
All IDA SDK calls must run on the main thread.

Read-only tools use the shared read lock (`@idaread`); mutating tools use the exclusive write lock (`@idasync`). Prefer `@idaread` where possible to allow concurrent reads.

```python
from .rpc import tool
from .sync import idasync, idaread

@tool
@idaread          # shared lock — use for read-only queries
def my_query(...):
    ...

@tool
@idasync          # exclusive write lock — use for mutations
def my_mutation(...):
    ...
```

A `@tool` without one of these runs on the HTTP handler thread, where SDK calls return
wrong answers rather than failing. `idaapi.is_idaq()` in particular returns False from a
worker thread even in the GUI — read it inside an `@idaread` helper, never directly.

### Loading binaries headlessly

`load_binary` spawns IDA with `-A` (autonomous: no dialogs, default answer to each).
For PE/ELF/Mach-O pass only the path — the loader picks correctly and overriding is more
likely to corrupt the load. For a raw blob the defaults (binary loader, `metapc`, base 0)
are wrong and fail **silently**, so call `probe_binary` first.

Gotchas, all verified on IDA 9.4 and all silent failures if ignored:
- `-b` takes **paragraphs**, not bytes: `-b0x8000000` yields base `0x80000000`.
  `get_imagebase()` reads 0 for binary loads — check the segment start instead.
- ARM is the only module accepting `-p` options. Grammar is `<arch-or-core>[;<mod>...]`,
  semicolon-separated; a bad token is **fatal**, so validate before spawning.
  `armmeta` is documented but rejected by 9.4.
- MCU device selection is `-DDEVICE=<leaf-name>`, not a `-p` option, and an unknown
  device is **ignored silently**, producing a database with no memory map. IDA does not
  record which device it used, so it cannot be verified afterwards — check the segment
  map. Without an explicit device the module default is used (tc1766 for TriCore).
- Loader options against an existing database make IDA `exit(1)` with no message; they
  apply only at database creation. Use `fresh_db=True` or `idb_path`.
- ARM/Thumb is the `T` segment register, set after load and **before** defining code.
  Cortex-M variants (`-parm:ARMv7-M`) already default it to Thumb.

### API conventions
- Prefer batch-first APIs.
- Many functions accept either a comma-separated string or a list.
- Use full type hints and `Annotated[...]` descriptions.
- The function docstring becomes the MCP tool description.

Example:
```python
def my_api(addrs: Annotated[str, "Addresses (0x401000, main) or list"]) -> list[dict]:
    ...
```

### Common helpers
- Parse addresses with `parse_address()`
- Normalize batch input with `normalize_list_input()` / `normalize_dict_list()`
- Use shared pagination / filtering helpers from `utils.py`

### Unsafe operations
Debugger or destructive operations should be marked unsafe:
```python
from .rpc import tool, unsafe

@unsafe
@tool
@idasync
def dangerous_op(...):
    ...
```

## Development commands

### Run
```bash
uv run ida-pro-mcp
uv run ida-pro-mcp --transport http://127.0.0.1:8744/sse
uv run idalib-mcp --host 127.0.0.1 --port 8745 path/to/binary
uv run idalib-mcp --isolated-contexts --host 127.0.0.1 --port 8745 path/to/binary
uv run ida-pro-mcp --unsafe
```

### MCP inspector
```bash
uv run mcp dev src/ida_pro_mcp/server.py
```

### Install / uninstall

To install or update from the GitHub repo and register the IDA plugin + MCP clients:
```bash
pip install https://github.com/rweijnen/ida-pro-mcp/archive/refs/heads/main.zip
ida-pro-mcp --install claude --scope global --transport stdio
```

The `--transport stdio` flag is required so Claude runs `server.py` as a subprocess (the proxy layer). Without it you get a direct HTTP connection to IDA that lacks `load_binary`, `list_instances`, and other proxy-side tools.

**IDA must be restarted after `--install`** for the plugin to take effect.

To uninstall:
```bash
ida-pro-mcp --uninstall claude --scope global
```

## Testing and coverage

### Run tests
Use the headless test runner:
```bash
uv run ida-mcp-test tests/crackme03.elf -q
uv run ida-mcp-test tests/typed_fixture.elf -q
uv run ida-mcp-test tests/crackme03.elf -c api_analysis
uv run ida-mcp-test tests/typed_fixture.elf -p "*stack*"
```

Notes:
- Use `uv run ...`
- Non-interactive output should show failures only plus a summary
- Binary-specific tests should use `@test(binary="...")` with the executable basename
- `--isolated-contexts` gives each idalib-mcp request its own IDA context (stateless, safe for concurrent use)

### Coverage
Measure coverage across both maintained fixtures:
```bash
uv run coverage erase
uv run coverage run -m ida_pro_mcp.test tests/crackme03.elf -q
uv run coverage run --append -m ida_pro_mcp.test tests/typed_fixture.elf -q
uv run coverage report --show-missing
```

Current fixture intent:
- `tests/crackme03.elf`: compact general regression fixture
- `tests/typed_fixture.elf`: typed globals / structs / locals / stack coverage fixture

### Test framework helpers
From `framework.py`:
- `assert_shape(value, schema)` — validates nested dicts/lists; use `optional()`, `list_of()`, `one_of()` as schema matchers
- `assert_ok(result)` / `assert_error(result)` — validates tool response status
- `get_any_function()`, `get_named_function(name)`, `get_data_address()` — returns addresses from the loaded binary

### Test expectations
- Prefer semantic assertions, not weak "field exists" checks
- Prefer round-trip tests for mutating APIs
- If tests expose clearly wrong API behavior, fix the API instead of weakening the test
- Focus on IDA-facing modules, not server/config plumbing
- Expect some IDA / Hex-Rays variance; guarded assertions or runtime skips are acceptable when justified

### Generic-test sanity check
When adding generic tests, also try a non-fixture binary to avoid ELF-specific assumptions:
```bash
uv run ida-mcp-test "C:\CodeBlocks\x64dbg\bin\x64\x64dbg.dll" -q
```

## Scope priorities

High priority:
- `api_analysis.py`
- `api_types.py`
- `api_modify.py`
- `api_stack.py`
- `api_memory.py`
- `api_core.py`
- `api_resources.py`
- `api_vtable.py`
- `utils.py`
- `framework.py`

Lower priority:
- `api_debug.py`
- MCP transport / hosting details
- install / config mutation logic

## Practical notes

- Server/plugin Python: 3.11+
- IDA Pro 8.3+; 9.0 recommended
- IDA Free is not supported
- If IDA uses the wrong Python, use `idapyswitch`
