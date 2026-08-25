# IDA Pro MCP (Fork)

Fork of [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) with additional features:

- **Auto-start plugin** — MCP server starts automatically when IDA opens (no Ctrl+Alt+M needed)
- **`load_binary` tool** — AI clients can spawn new IDA instances directly, without dialogs
- **Raw binary loading** — specify processor, image base, file type and MCU device, so firmware
  dumps and headerless blobs can be loaded headlessly (`probe_binary`, `list_processors`, `list_devices`)
- **ARM Thumb control** — `get_thumb` / `set_thumb` / `set_default_thumb` for Cortex-M firmware
- **Analysis progress** — `analysis_status` / `wait_for_analysis` report whether auto-analysis
  is done, which queue it is in, and where it is working
- **Multi-instance improvements** — more reliable discovery with increased probe timeout
- **Large response pagination** — `decompile`, `get_bytes`, and `xrefs_to_field` support `max_lines`/`offset` for incremental reading
- **Read/write lock splitting** — read-only tools use `MFF_READ` (shared lock) instead of `MFF_WRITE`, reducing contention under concurrent access
- **VTableExplorer integration** — MCP tools for C++ vtable analysis (requires [VTableExplorer](https://github.com/K4ryuu/IDA-VTableExplorer) plugin)
- **Connection pooling & timeout fixes** — HTTP keep-alive and aligned client/server timeouts

Simple [MCP Server](https://modelcontextprotocol.io/introduction) to allow vibe reversing in IDA Pro.

https://github.com/user-attachments/assets/6ebeaa92-a9db-43fa-b756-eececce2aca0

The binaries and prompt for the video are available in the [mcp-reversing-dataset](https://github.com/mrexodia/mcp-reversing-dataset) repository.

## Prerequisites

- [Python](https://www.python.org/downloads/) (**3.11 or higher**)
  - Use `idapyswitch` to switch to the newest Python version
- [IDA Pro](https://hex-rays.com/ida-pro) (8.3 or higher, 9 recommended), **IDA Free is not supported**
- Supported MCP Client (pick one you like)
  - [Amazon Q Developer CLI](https://aws.amazon.com/q/developer/)
  - [Augment Code](https://www.augmentcode.com/)
  - [Claude](https://claude.ai/download)
  - [Claude Code](https://www.anthropic.com/code)
  - [Cline](https://cline.bot)
  - [Codex](https://github.com/openai/codex)
  - [Copilot CLI](https://docs.github.com/en/copilot)
  - [Crush](https://github.com/charmbracelet/crush)
  - [Cursor](https://cursor.com)
  - [Gemini CLI](https://google-gemini.github.io/gemini-cli/)
  - [Kilo Code](https://www.kilocode.com/)
  - [Kiro](https://kiro.dev/)
  - [LM Studio](https://lmstudio.ai/)
  - [Opencode](https://opencode.ai/)
  - [Qodo Gen](https://www.qodo.ai/)
  - [Qwen Coder](https://qwenlm.github.io/qwen-code-docs/)
  - [Roo Code](https://roocode.com)
  - [Trae](https://trae.ai/)
  - [VS Code](https://code.visualstudio.com/)
  - [VS Code Insiders](https://code.visualstudio.com/insiders)
  - [Warp](https://www.warp.dev/)
  - [Windsurf](https://windsurf.com)
  - [Zed](https://zed.dev/)
  - [Other MCP Clients](https://modelcontextprotocol.io/clients#example-clients): Run `ida-pro-mcp --config` to get the JSON config for your client.

## Installation

Install this fork of the IDA Pro MCP package:

```sh
pip uninstall ida-pro-mcp
pip install https://github.com/rweijnen/ida-pro-mcp/archive/refs/heads/main.zip
```

To install the upstream version instead, use `https://github.com/mrexodia/ida-pro-mcp/archive/refs/heads/main.zip`.

Configure the MCP servers and install the IDA Plugin:

```
ida-pro-mcp --install
```

This installs with the **stdio** transport, which runs `server.py` as a subprocess so the
proxy layer is active. The proxy is what provides `load_binary`, `list_instances`,
`switch_instance`, `probe_binary`, `list_processors` and `list_devices` — a direct HTTP
connection to the IDA plugin does not have them. Only override with `--transport` if you
specifically want that direct connection.

**Important**: Make sure you completely restart IDA and your MCP client for the installation to take effect. Some clients (like Claude) run in the background and need to be quit from the tray icon.

https://github.com/user-attachments/assets/65ed3373-a187-4dd5-a807-425dca1d8ee9

The MCP plugin **auto-starts** when IDA opens — no manual activation needed. The HTTP server starts immediately, and caches are initialized automatically when a binary is loaded. You can still use Ctrl+Alt+M to toggle the server on/off if needed.

## Prompt Engineering

LLMs are prone to hallucinations and you need to be specific with your prompting. For reverse engineering the conversion between integers and bytes are especially problematic. Below is a minimal example prompt, feel free to start a discussion or open an issue if you have good results with a different prompt:

```md
Your task is to analyze a crackme in IDA Pro. You can use the MCP tools to retrieve information. In general use the following strategy:

- Inspect the decompilation and add comments with your findings
- Rename variables to more sensible names
- Change the variable and argument types if necessary (especially pointer and array types)
- Change function names to be more descriptive
- If more details are necessary, disassemble the function and add comments with your findings
- NEVER convert number bases yourself. Use the `int_convert` MCP tool if needed!
- Do not attempt brute forcing, derive any solutions purely from the disassembly and simple python scripts
- Create a report.md with your findings and steps taken at the end
- When you find a solution, prompt to user for feedback with the password you found
```

This prompt was just the first experiment, please share if you found ways to improve the output!

Another prompt by [@can1357](https://github.com/can1357):

```md
Your task is to create a complete and comprehensive reverse engineering analysis. Reference AGENTS.md to understand the project goals and ensure the analysis serves our purposes.

Use the following systematic methodology:

1. **Decompilation Analysis**
   - Thoroughly inspect the decompiler output
   - Add detailed comments documenting your findings
   - Focus on understanding the actual functionality and purpose of each component (do not rely on old, incorrect comments)

2. **Improve Readability in the Database**
   - Rename variables to sensible, descriptive names
   - Correct variable and argument types where necessary (especially pointers and array types)
   - Update function names to be descriptive of their actual purpose

3. **Deep Dive When Needed**
   - If more details are necessary, examine the disassembly and add comments with findings
   - Document any low-level behaviors that aren't clear from the decompilation alone
   - Use sub-agents to perform detailed analysis

4. **Important Constraints**
   - NEVER convert number bases yourself - use the int_convert MCP tool if needed
   - Use MCP tools to retrieve information as necessary
   - Derive all conclusions from actual analysis, not assumptions

5. **Documentation**
   - Produce comprehensive RE/*.md files with your findings
   - Document the steps taken and methodology used
   - When asked by the user, ensure accuracy over previous analysis file
   - Organize findings in a way that serves the project goals outlined in AGENTS.md or CLAUDE.md
```

Live stream discussing prompting and showing some real-world malware analysis:

[![](https://img.youtube.com/vi/iFxNuk3kxhk/0.jpg)](https://www.youtube.com/watch?v=iFxNuk3kxhk)

## Tips for Enhancing LLM Accuracy

Large Language Models (LLMs) are powerful tools, but they can sometimes struggle with complex mathematical calculations or exhibit "hallucinations" (making up facts). Make sure to tell the LLM to use the `int_convert` MCP tool and you might also need [math-mcp](https://github.com/EthanHenrickson/math-mcp) for certain operations.

Another thing to keep in mind is that LLMs will not perform well on obfuscated code. Before trying to use an LLM to solve the problem, take a look around the binary and spend some time (automatically) removing the following things:

- String encryption
- Import hashing
- Control flow flattening
- Code encryption
- Anti-decompilation tricks

You should also use a tool like Lumina or FLIRT to try and resolve all the open source library code and the C++ STL, this will further improve the accuracy.

## Multi-Instance Support

The MCP server supports multiple IDA instances running simultaneously. Each IDA plugin auto-selects a free port starting from 13337 (scanning up to 13436). The MCP server discovers all running instances and routes tool calls to the active one.

**Instance management tools:**

| Tool | Description |
|------|-------------|
| `list_instances` | Discover and list all running IDA instances (binary name, port, processor, analysis status) |
| `switch_instance` | Switch active instance by port number or binary name substring |
| `get_active_instance` | Get info about the currently active instance |
| `load_binary` | Spawn a new IDA Pro instance with a binary, wait for it to come up, and make it active |

**Workflow:**

1. Open multiple binaries in separate IDA instances — the MCP plugin auto-starts in each
2. Or use `load_binary("/path/to/binary")` from the AI client to spawn a new IDA instance
3. Use `switch_instance(name="firmware")` or `switch_instance(port=13338)` to change the active one

**`load_binary` details:**

`load_binary` spawns IDA with `-A` (autonomous mode: no dialogs, default answer to each),
waits for the new instance to publish its port, makes it active, and returns
`status: "ready"` with the port, processor, bit width and analysis state. No polling is
needed. It reads the IDA installation path from `~/.ida_mcp/config.json`, written
automatically by the plugin on first load.

Startup typically takes 10-60s. Pass `wait=false` to return immediately instead, or raise
`wait_timeout` (default 180s) for very large binaries. Note the wait covers IDA *starting*,
not auto-analysis — see [Analysis Progress](#analysis-progress).

If the binary is already open in another instance, `load_binary` refuses and names the port
holding it, since IDA locks its database. Pass `new_instance=true` to open a second copy
with its own database file, which is useful for comparing two loads of the same image with
different settings.

When multiple instances are active, tool responses are tagged with `[instance: <binary> @ port <N>]` so the AI can verify it is querying the correct binary. The MCP server also injects instructions into the initialize response to guide AI clients on multi-instance workflow and effective use of IDA tools.

**Windows port safety:** On Windows, `SO_EXCLUSIVEADDRUSE` prevents multiple IDA instances from silently sharing the same port (a common `SO_REUSEADDR` pitfall on Windows).

## Loading Raw Binaries and Firmware

For PE, ELF and Mach-O, pass only the path — IDA's loader picks the processor and base
correctly, and overriding is more likely to corrupt the load than improve it.

Headerless images (firmware dumps, ROM images, shellcode) have nothing for IDA to detect,
so under `-A` it silently falls back to the binary loader, `metapc` and base 0 — producing
a confidently wrong database rather than an error. For those, supply the details:

```python
probe_binary("/path/to/firmware.bin")
# -> {"format": "unknown", "recognized": false,
#     "advice": "Headerless/unrecognized ... pass file_type='binary' plus ..."}

list_processors(family="TriCore")     # find the processor name
list_devices("tricore")               # find the MCU device

load_binary("/path/to/firmware.bin",
            processor="tricore", file_type="binary",
            load_base=0x80000000, device="tc37x")
```

| Tool | Description |
|------|-------------|
| `probe_binary` | Detect a file's format before loading, and whether loader options are needed |
| `list_processors` | Processor names for `processor=`, optionally filtered by family |
| `list_devices` | MCU device (chip variant) names for `device=`, per processor |

All three run in the MCP server itself, so they work with no IDA instance running — which
is when you need them, before deciding how to load.

**`load_binary` loader options**

| Option | Purpose |
|--------|---------|
| `processor` | Processor name, e.g. `tricore`, `mipsb`. ARM accepts options: `arm:ARMv7-A;NEON` |
| `file_type` | Loader/format prefix, e.g. `binary` for a headerless blob |
| `load_base` | Byte address to load at (must be 16-byte aligned) |
| `entry_point` | Initial entry point address |
| `device` | MCU device / chip variant, e.g. `tc37x` |
| `fresh_db` | Discard an existing database and re-analyze |
| `idb_path` | Write the database somewhere other than next to the input |

Things worth knowing, all of which fail quietly in IDA itself:

- **Loader options only apply when a database is created.** If one already exists, IDA
  exits without a message. `load_binary` checks first and tells you to use `fresh_db=true`.
- **An unknown MCU device is ignored silently**, giving a database with no memory map. The
  name is validated against IDA's config before spawning, but IDA does not record which
  device it used, so it cannot be confirmed afterwards — check the segment map looks like
  the chip you expect. Without an explicit device the module default is used, which for
  TriCore is a TC1766.
- **Processor names are case-sensitive** and are not the module filenames in IDA's `procs/`
  directory (x86's module is `pc`, but the name is `metapc`).
- **An invalid ARM `-p` option is fatal** to IDA, so `processor` is validated before the
  spawn.

## Large Response Pagination

Some tools produce large outputs that can overwhelm LLM context windows. The following tools support incremental reading via `max_lines` and `offset` parameters:

| Tool | Default lines | Pagination |
|------|--------------|------------|
| `decompile` | 200 | `max_lines` + `offset` for scrolling through long functions |
| `get_bytes` | Inline ≤4096 bytes | Larger reads saved to temp file |
| `xrefs_to_field` | All results | `offset` + `count` |

**Tip:** For unknown functions, start with `decompile(addr, max_lines=200)` to preview, then request more with `offset` if needed.

## Read/Write Lock Splitting

By default, all IDA SDK calls run on the main thread via `execute_sync()`. This fork splits tools into two lock modes:

- **`@idaread`** (MFF_READ, shared lock) — used by 37 read-only tools (xrefs, get_bytes, list_funcs, etc.). Multiple read operations can execute concurrently.
- **`@idasync`** (MFF_WRITE, exclusive lock) — used by 27 mutating tools (rename, patch, set_type, etc.). These still acquire an exclusive lock.

This reduces contention when multiple AI clients query the same IDA instance simultaneously. Read-only operations no longer block each other.

A handful of tools carry neither decorator, because they either need no IDA access
(`int_convert`), manage locking internally (`decompile`, `disasm`), or deliberately avoid
holding the lock while they wait (`analysis_status`, `wait_for_analysis`). Any new `@tool`
that touches the IDA SDK needs one of the two decorators: without it the call runs on the
HTTP handler thread, where SDK functions return wrong answers rather than failing.

## VTableExplorer Integration

If the [VTableExplorer](https://github.com/K4ryuu/IDA-VTableExplorer) IDA plugin is loaded, four additional MCP tools become available automatically:

| Tool | Description |
|------|-------------|
| `vtable_scan` | Scan all vtables in the binary (filterable by class name, paginated) |
| `vtable_entries` | Get vtable function entries for specific vtable address(es) |
| `vtable_compare` | Compare derived and base class vtables (overrides, new virtuals) |
| `vtable_hierarchy` | Get class hierarchy tree for a given class name |

The tools are always registered in the MCP tool list. If VTableExplorer isn't loaded, they return a clear error when called. Output uses a compact format by default to minimize token usage.

## SSE Transport & Headless MCP

You can run an SSE server to connect to the user interface like this:

```sh
uv run ida-pro-mcp --transport http://127.0.0.1:8744/sse
```

After installing [`idalib`](https://docs.hex-rays.com/user-guide/idalib) you can also run a headless SSE server:

```sh
uv run idalib-mcp --host 127.0.0.1 --port 8745 path/to/executable
```

_Note_: The `idalib` feature was contributed by [Willi Ballenthin](https://github.com/williballenthin).

## Headless idalib Session Model

Use `--isolated-contexts` to enable strict per-transport isolation:

```sh
uv run idalib-mcp --isolated-contexts --host 127.0.0.1 --port 8745 path/to/executable
```

### Why use `--isolated-contexts`?

Use it when multiple agents connect to the same `idalib-mcp` server and you want deterministic context isolation:

- Prevent one agent from changing another agent's active session accidentally.
- Run concurrent analyses safely (for example agent A on binary X and agent B on binary Y).
- Still allow intentional collaboration by binding multiple agents to the same open session ID.
- Improve reproducibility because each agent's context binding is explicit.

When `--isolated-contexts` is enabled:

- Each transport context has its own binding (`Mcp-Session-Id` for `/mcp`, `session` for `/sse`, `stdio:default` for stdio).
- Unbound contexts fail fast for IDB-dependent tools/resources.
- `idalib_switch(session_id)` and `idalib_open(...)` bind the caller context only.

### Streamable HTTP behavior

With `--isolated-contexts`, strict Streamable HTTP session semantics are enabled, including `Mcp-Session-Id` validation.

### Context tools

- `idalib_open(input_path, ...)`: Open binary and bind it to the active context policy.
  Note this does not yet accept the loader options (`processor`, `load_base`, `device`, …)
  that `load_binary` supports, so raw/headerless images are best loaded through GUI IDA.
- `idalib_switch(session_id)`: Rebind the active context policy to an existing session.
- `idalib_current()`: Return the session bound to the active context policy.
- `idalib_unbind()`: Remove the active context binding.
- `idalib_list()`: Includes `is_active`, `is_current_context`, and `bound_contexts`.


## MCP Resources

**Resources** represent browsable state (read-only data) following MCP's philosophy.

**Core IDB State:**
- `ida://idb/metadata` - IDB file info (database path, input file path, arch, base, size, hashes, processor, bits, analysis status)
- `ida://idb/segments` - Memory segments with permissions
- `ida://idb/entrypoints` - Entry points (main, TLS callbacks, etc.)

**UI State:**
- `ida://cursor` - Current cursor position and function
- `ida://selection` - Current selection range

**Type Information:**
- `ida://types` - All local types
- `ida://structs` - All structures/unions
- `ida://struct/{name}` - Structure definition with fields

**Lookups:**
- `ida://import/{name}` - Import details by name
- `ida://export/{name}` - Export details by name
- `ida://xrefs/from/{addr}` - Cross-references from address

## Core Functions

- `lookup_funcs(queries)`: Get function(s) by address or name (auto-detects, accepts list or comma-separated string).
- `int_convert(inputs)`: Convert numbers to different formats (decimal, hex, bytes, ASCII, binary).
- `list_funcs(queries)`: List functions (paginated, filtered).
- `list_globals(queries)`: List global variables (paginated, filtered).
- `imports(offset, count)`: List all imported symbols with module names (paginated).
- `decompile(addr)`: Decompile function at the given address.
- `disasm(addr)`: Disassemble function with full details (arguments, stack frame, etc).
- `xrefs_to(addrs)`: Get all cross-references to address(es).
- `xrefs_to_field(queries)`: Get cross-references to specific struct field(s).
- `callees(addrs)`: Get functions called by function(s) at address(es).

## Modification Operations

- `set_comments(items)`: Set comments at address(es) in both disassembly and decompiler views.
- `patch_asm(items)`: Patch assembly instructions at address(es).
- `declare_type(decls)`: Declare C type(s) in the local type library.
- `define_func(items)`: Define function(s) at address(es). Optionally specify `end` for explicit bounds.
- `define_code(items)`: Convert bytes to code instruction(s) at address(es).
- `undefine(items)`: Undefine item(s) at address(es), converting back to raw bytes. Optionally specify `end` or `size`.
- `refresh_caches()`: Force-refresh the strings/functions/globals caches after bulk changes.

## ARM Thumb Mode

ARM/Thumb is not a load option — IDA models it as a virtual segment register `T`
(0 = ARM, non-zero = Thumb). Getting it wrong is silent: the same bytes decode as
`PUSH {R7,LR}; MOV R7,SP` with Thumb and as `STRBTMI R11,[PC],-R0,LSL#11` with ARM.

- `get_thumb(addrs)`: Read the mode at address(es), with the covering range.
- `set_thumb(start, thumb, end=None)`: Set the mode over a range. Undefines code in the
  range by default, since changing `T` does not re-decode existing instructions.
- `set_default_thumb(addr, thumb)`: Set a segment's default mode, for uniformly-Thumb images.

**Set the mode before defining code.** Cortex-M variants (`processor="arm:ARMv7-M"`)
already default to Thumb, so these are for images that guess wrong or are mixed.

## Analysis Progress

Auto-analysis keeps running after a binary loads, and results from other tools are
incomplete until it finishes.

- `analysis_status()`: Whether analysis is complete, which queue it is in, the address
  being worked on, and elapsed time. Completion is recorded by an event hook rather than
  measured by polling, so this is cheap to call.
- `wait_for_analysis(timeout_sec=120)`: Wait for analysis to finish. Returns
  `timed_out: true` with partial state rather than raising.

For a long analysis, prefer `analysis_status` between other work over sitting in
`wait_for_analysis` — a `current_ea` that keeps moving means progress, one that is stuck
does not.

## Memory Reading Operations

- `get_bytes(addrs)`: Read raw bytes at address(es).
- `get_int(queries)`: Read integer values using ty (i8/u64/i16le/i16be/etc).
- `get_string(addrs)`: Read null-terminated string(s).
- `get_global_value(queries)`: Read global variable value(s) by address or name (auto-detects, compile-time values).

## Stack Frame Operations

- `stack_frame(addrs)`: Get stack frame variables for function(s).
- `declare_stack(items)`: Create stack variable(s) at specified offset(s).
- `delete_stack(items)`: Delete stack variable(s) by name.

## Structure Operations

- `read_struct(queries)`: Read structure field values at specific address(es).
- `search_structs(filter)`: Search structures by name pattern.

## Debugger Operations (Extension)

Debugger tools are hidden by default. Enable with `?ext=dbg` query parameter:

```
http://127.0.0.1:13337/mcp?ext=dbg
```

**Control:**
- `dbg_start()`: Start debugger process.
- `dbg_exit()`: Exit debugger process.
- `dbg_continue()`: Continue execution.
- `dbg_run_to(addr)`: Run to address.
- `dbg_step_into()`: Step into instruction.
- `dbg_step_over()`: Step over instruction.

**Breakpoints:**
- `dbg_bps()`: List all breakpoints.
- `dbg_add_bp(addrs)`: Add breakpoint(s).
- `dbg_delete_bp(addrs)`: Delete breakpoint(s).
- `dbg_toggle_bp(items)`: Enable/disable breakpoint(s).

**Registers:**
- `dbg_regs()`: All registers, current thread.
- `dbg_regs_all()`: All registers, all threads.
- `dbg_regs_remote(tids)`: All registers, specific thread(s).
- `dbg_gpregs()`: GP registers, current thread.
- `dbg_gpregs_remote(tids)`: GP registers, specific thread(s).
- `dbg_regs_named(names)`: Named registers, current thread.
- `dbg_regs_named_remote(tid, names)`: Named registers, specific thread.

**Stack & Memory:**
- `dbg_stacktrace()`: Call stack with module/symbol info.
- `dbg_read(regions)`: Read memory from debugged process.
- `dbg_write(regions)`: Write memory to debugged process.

## Advanced Analysis Operations

- `py_eval(code)`: Execute arbitrary Python code in IDA context (returns dict with result/stdout/stderr, supports Jupyter-style evaluation).

## Pattern Matching & Search

- `find_regex(queries)`: Search strings with case-insensitive regex (paginated).
- `find_bytes(patterns, limit=1000, offset=0)`: Find byte pattern(s) in binary (e.g., "48 8B ?? ??"). Max limit: 10000.
- `find(type, targets, limit=1000, offset=0)`: Advanced search (immediate values, strings, data/code references). Max limit: 10000.

## Control Flow Analysis

- `basic_blocks(addrs)`: Get basic blocks with successors and predecessors.

## Type Operations

- `set_type(edits)`: Apply type(s) to functions, globals, locals, or stack variables.
- `infer_types(addrs)`: Infer types at address(es) using Hex-Rays or heuristics.

## Export Operations

- `export_funcs(addrs, format)`: Export function(s) in specified format (json, c_header, or prototypes).

## Graph Operations

- `callgraph(roots, max_depth)`: Build call graph from root function(s) with configurable depth.

## Batch Operations

- `rename(batch)`: Unified batch rename operation for functions, globals, locals, and stack variables (accepts dict with optional `func`, `data`, `local`, `stack` keys).
- `patch(patches)`: Patch multiple byte sequences at once.
- `put_int(items)`: Write integer values using ty (i8/u64/i16le/i16be/etc).

**Key Features:**

- **Type-safe API**: All functions use strongly-typed parameters with TypedDict schemas for better IDE support and LLM structured outputs
- **Batch-first design**: Most operations accept both single items and lists
- **Consistent error handling**: All batch operations return `[{..., error: null|string}, ...]`
- **Cursor-based pagination**: Search functions return `cursor: {next: offset}` or `{done: true}` (default limit: 1000, enforced max: 10000 to prevent token overflow)
- **Performance**: Strings are cached with MD5-based invalidation to avoid repeated `build_strlist` calls in large projects
- **Token efficiency**: JSON responses to LLM clients are minified (~28% smaller for structured data like function lists)
- **Concurrency**: Read-only tools use shared locks (`MFF_READ`), allowing parallel reads from multiple clients
- **Pagination**: Large responses (decompilation, bytes, xrefs) support `max_lines`/`offset` to avoid context window overflow

## VTable Operations (requires VTableExplorer plugin)

- `vtable_scan(filter, count, offset)`: Scan all vtables, optionally filtered by class name pattern (paginated).
- `vtable_entries(addrs)`: Get vtable function entries for one or more vtable addresses.
- `vtable_compare(derived, base)`: Compare derived vs base class vtable (shows overrides and new virtuals).
- `vtable_hierarchy(class_name)`: Get inheritance hierarchy tree for a class.

## Comparison with other MCP servers

There are a few IDA Pro MCP servers floating around, but I created my own for a few reasons:

1. Installation should be fully automated.
2. The architecture of other plugins make it difficult to add new functionality quickly (too much boilerplate of unnecessary dependencies).
3. Learning new technologies is fun!

If you want to check them out, here is a list (in the order I discovered them):

- https://github.com/taida957789/ida-mcp-server-plugin (SSE protocol only, requires installing dependencies in IDAPython).
- https://github.com/fdrechsler/mcp-server-idapro (MCP Server in TypeScript, excessive boilerplate required to add new functionality).
- https://github.com/MxIris-Reverse-Engineering/ida-mcp-server (custom socket protocol, boilerplate).

Feel free to open a PR to add your IDA Pro MCP server here.

## Development

Adding new features is a super easy and streamlined process. All you have to do is add a new `@tool` function to the modular API files in `src/ida_pro_mcp/ida_mcp/api_*.py` and your function will be available in the MCP server without any additional boilerplate! Below is a video where I add the `get_metadata` function in less than 2 minutes (including testing):

https://github.com/user-attachments/assets/951de823-88ea-4235-adcb-9257e316ae64

To test the MCP server itself:

```sh
npx -y @modelcontextprotocol/inspector
```

This will open a web interface at http://localhost:5173 and allow you to interact with the MCP tools for testing.

For testing I create a symbolic link to the IDA plugin and then POST a JSON-RPC request directly to `http://localhost:13337/mcp`. After [enabling symbolic links](https://learn.microsoft.com/en-us/windows/apps/get-started/enable-your-device-for-development) you can run the following command:

```sh
uv run ida-pro-mcp --install
```

Generate the changelog of direct commits to `main`:

```sh
git log --first-parent --no-merges 1.2.0..main "--pretty=- %s"
```
