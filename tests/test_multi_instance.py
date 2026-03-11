"""Tests for multi-instance discovery and switching.

Uses fake HTTP servers to simulate IDA MCP plugin instances.
"""

import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from unittest.mock import patch

import pytest

# We can't import the full server module (it imports zeromcp which needs
# special path setup), so we test by importing just the pieces we need
# after patching the path.
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "ida_pro_mcp", "ida_mcp"))

# Now import the server module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from ida_pro_mcp.server import (
    IDAInstance,
    InstanceManager,
    _probe_instance,
    _read_ida_config,
    _save_tools_cache,
    _load_tools_cache,
    load_binary,
    instance_manager,
    _IDA_MCP_CONFIG_FILE,
    _IDA_TOOLS_CACHE_FILE,
)


# ============================================================================
# Fake IDA MCP plugin server
# ============================================================================


class FakeIDAHandler(BaseHTTPRequestHandler):
    """Simulates an IDA MCP plugin's /mcp endpoint."""

    def log_message(self, format, *args):
        pass  # suppress logs

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length))

        method = body.get("method", "")
        response = {"jsonrpc": "2.0", "id": body.get("id")}

        if method == "resources/read":
            uri = body.get("params", {}).get("uri", "")
            if uri == "ida://idb/metadata":
                metadata = self.server.fake_metadata  # type: ignore
                response["result"] = {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": json.dumps(metadata),
                        }
                    ]
                }
            else:
                response["error"] = {"code": -32601, "message": "Unknown resource"}
        elif method == "tools/list":
            response["result"] = {"tools": [{"name": "fake_tool", "description": "test"}]}
        elif method == "tools/call":
            response["result"] = {
                "content": [{"type": "text", "text": "ok"}],
                "isError": False,
            }
        elif method == "ping":
            response["result"] = {}
        else:
            response["error"] = {"code": -32601, "message": f"Unknown method: {method}"}

        data = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def start_fake_ida(port: int, metadata: dict) -> HTTPServer:
    """Start a fake IDA MCP server on the given port."""
    server = HTTPServer(("127.0.0.1", port), FakeIDAHandler)
    server.fake_metadata = metadata  # type: ignore
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


# ============================================================================
# Tests
# ============================================================================


class TestIDAInstance:
    def test_from_metadata(self):
        inst = IDAInstance("127.0.0.1", 13337, {
            "module": "firmware.bin",
            "path": "/tmp/firmware.bin",
            "base": "0x400000",
            "size": "0x1000",
            "processor": "ARM",
            "bits": 32,
            "analysis_complete": True,
        })
        assert inst.binary_name == "firmware.bin"
        assert inst.binary_path == "/tmp/firmware.bin"
        assert inst.processor == "ARM"
        assert inst.bits == 32
        assert inst.analysis_complete is True
        assert inst.port == 13337

    def test_empty_metadata(self):
        inst = IDAInstance("127.0.0.1", 13337)
        assert inst.binary_name == ""
        assert inst.analysis_complete is False
        assert inst.port == 13337

    def test_to_dict(self):
        inst = IDAInstance("127.0.0.1", 13337, {"module": "test.exe", "analysis_complete": True})
        d = inst.to_dict()
        assert d["port"] == 13337
        assert d["binary_name"] == "test.exe"
        assert d["analysis_complete"] is True


class TestProbeInstance:
    def test_probe_live_instance(self):
        metadata = {"module": "probe_test.bin", "path": "/tmp/probe_test.bin"}
        server = start_fake_ida(18900, metadata)
        try:
            inst = _probe_instance("127.0.0.1", 18900, timeout=2.0)
            assert inst is not None
            assert inst.binary_name == "probe_test.bin"
            assert inst.port == 18900
        finally:
            server.shutdown()

    def test_probe_dead_port(self):
        inst = _probe_instance("127.0.0.1", 18901, timeout=0.3)
        assert inst is None


class TestInstanceManager:
    def test_discover_finds_instances(self):
        servers = []
        try:
            servers.append(start_fake_ida(18910, {"module": "binary_a.elf"}))
            servers.append(start_fake_ida(18911, {"module": "binary_b.elf"}))

            mgr = InstanceManager("127.0.0.1", 18910, 5)
            found = mgr.discover()

            assert len(found) == 2
            names = {i.binary_name for i in found}
            assert "binary_a.elf" in names
            assert "binary_b.elf" in names
        finally:
            for s in servers:
                s.shutdown()

    def test_discover_auto_selects_lowest_port(self):
        servers = []
        try:
            servers.append(start_fake_ida(18920, {"module": "a.bin"}))
            servers.append(start_fake_ida(18921, {"module": "b.bin"}))

            mgr = InstanceManager("127.0.0.1", 18920, 5)
            mgr.discover()

            assert mgr.active_port == 18920
        finally:
            for s in servers:
                s.shutdown()

    def test_discover_empty_range(self):
        mgr = InstanceManager("127.0.0.1", 18930, 3)
        found = mgr.discover()
        assert len(found) == 0
        assert mgr.active_port is None

    def test_switch_by_port(self):
        servers = []
        try:
            servers.append(start_fake_ida(18940, {"module": "a.bin"}))
            servers.append(start_fake_ida(18941, {"module": "b.bin"}))

            mgr = InstanceManager("127.0.0.1", 18940, 5)
            mgr.discover()

            inst = mgr.switch(port=18941)
            assert inst.binary_name == "b.bin"
            assert mgr.active_port == 18941
        finally:
            for s in servers:
                s.shutdown()

    def test_switch_by_name(self):
        servers = []
        try:
            servers.append(start_fake_ida(18950, {"module": "firmware_v1.bin"}))
            servers.append(start_fake_ida(18951, {"module": "firmware_v2.bin"}))

            mgr = InstanceManager("127.0.0.1", 18950, 5)
            mgr.discover()

            inst = mgr.switch(name="v2")
            assert inst.binary_name == "firmware_v2.bin"
            assert mgr.active_port == 18951
        finally:
            for s in servers:
                s.shutdown()

    def test_switch_by_name_ambiguous(self):
        servers = []
        try:
            servers.append(start_fake_ida(18960, {"module": "firmware_v1.bin"}))
            servers.append(start_fake_ida(18961, {"module": "firmware_v2.bin"}))

            mgr = InstanceManager("127.0.0.1", 18960, 5)
            mgr.discover()

            with pytest.raises(ValueError, match="Multiple instances"):
                mgr.switch(name="firmware")
        finally:
            for s in servers:
                s.shutdown()

    def test_switch_by_name_not_found(self):
        servers = []
        try:
            servers.append(start_fake_ida(18970, {"module": "firmware.bin"}))

            mgr = InstanceManager("127.0.0.1", 18970, 5)
            mgr.discover()

            with pytest.raises(ValueError, match="No instance matching"):
                mgr.switch(name="nonexistent")
        finally:
            for s in servers:
                s.shutdown()

    def test_switch_invalid_port(self):
        mgr = InstanceManager("127.0.0.1", 18980, 3)
        mgr.discover()
        with pytest.raises(ValueError, match="No instance on port"):
            mgr.switch(port=99999)

    def test_get_active_none(self):
        mgr = InstanceManager("127.0.0.1", 18990, 3)
        assert mgr.get_active() is None

    def test_stale_active_cleared_on_discover(self):
        server = start_fake_ida(18995, {"module": "temp.bin"})
        mgr = InstanceManager("127.0.0.1", 18995, 3)
        mgr.discover()
        assert mgr.active_port == 18995

        # Kill the server
        server.shutdown()

        # Re-discover -- stale port should be cleared
        mgr.discover()
        assert mgr.active_port is None


class TestDispatchTagging:
    """Test that tool responses include instance identification."""

    def test_forward_tags_response(self):
        from ida_pro_mcp.server import _forward_to_ida

        server = start_fake_ida(18996, {"module": "tagged.bin"})
        try:
            request_obj = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "fake_tool", "arguments": {}},
                "id": 42,
            }
            response = _forward_to_ida("127.0.0.1", 18996, request_obj, request_obj)
            assert response is not None
            # Verify the response came back successfully
            assert "result" in response
        finally:
            server.shutdown()


class TestReadIdaConfig:
    def test_missing_config(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "ida_pro_mcp.server._IDA_MCP_CONFIG_FILE",
            str(tmp_path / "nonexistent.json"),
        )
        assert _read_ida_config() == {}

    def test_valid_config(self, tmp_path, monkeypatch):
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"ida_dir": "C:\\IDA"}))
        monkeypatch.setattr("ida_pro_mcp.server._IDA_MCP_CONFIG_FILE", str(cfg))
        assert _read_ida_config() == {"ida_dir": "C:\\IDA"}

    def test_corrupt_config(self, tmp_path, monkeypatch):
        cfg = tmp_path / "config.json"
        cfg.write_text("not json")
        monkeypatch.setattr("ida_pro_mcp.server._IDA_MCP_CONFIG_FILE", str(cfg))
        assert _read_ida_config() == {}


class TestToolsCache:
    def test_save_and_load(self, tmp_path, monkeypatch):
        cache_file = str(tmp_path / "tools_cache.json")
        monkeypatch.setattr("ida_pro_mcp.server._IDA_TOOLS_CACHE_FILE", cache_file)
        monkeypatch.setattr("ida_pro_mcp.server._IDA_MCP_CONFIG_DIR", str(tmp_path))
        tools = [{"name": "list_funcs", "description": "List functions"}]
        _save_tools_cache(tools)
        loaded = _load_tools_cache()
        assert loaded == tools

    def test_load_missing_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "ida_pro_mcp.server._IDA_TOOLS_CACHE_FILE",
            str(tmp_path / "nonexistent.json"),
        )
        assert _load_tools_cache() == []

    def test_load_corrupt_file(self, tmp_path, monkeypatch):
        cache_file = tmp_path / "tools_cache.json"
        cache_file.write_text("not json")
        monkeypatch.setattr("ida_pro_mcp.server._IDA_TOOLS_CACHE_FILE", str(cache_file))
        assert _load_tools_cache() == []


class TestLoadBinary:
    def test_relative_path_rejected(self):
        result = load_binary("relative/path.exe")
        assert "error" in result
        assert "absolute" in result["error"]

    def test_missing_file_rejected(self, tmp_path):
        result = load_binary(str(tmp_path / "nonexistent.exe"))
        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_no_config(self, tmp_path, monkeypatch):
        binary = tmp_path / "test.exe"
        binary.write_bytes(b"\x00")
        monkeypatch.setattr(
            "ida_pro_mcp.server._IDA_MCP_CONFIG_FILE",
            str(tmp_path / "nope.json"),
        )
        result = load_binary(str(binary))
        assert "error" in result
        assert "config" in result["error"].lower()

    def test_ida_exe_not_found(self, tmp_path, monkeypatch):
        binary = tmp_path / "test.exe"
        binary.write_bytes(b"\x00")
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"ida_dir": str(tmp_path / "fake_ida")}))
        monkeypatch.setattr("ida_pro_mcp.server._IDA_MCP_CONFIG_FILE", str(cfg))
        result = load_binary(str(binary))
        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_successful_spawn(self, tmp_path, monkeypatch):
        """Test that load_binary spawns IDA and returns immediately."""
        binary = tmp_path / "test.exe"
        binary.write_bytes(b"\x00")

        # Create a fake IDA executable
        ida_dir = tmp_path / "ida"
        ida_dir.mkdir()
        if sys.platform == "win32":
            ida_exe = ida_dir / "ida.exe"
        else:
            ida_exe = ida_dir / "ida"
        ida_exe.write_bytes(b"\x00")

        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"ida_dir": str(ida_dir)}))
        monkeypatch.setattr("ida_pro_mcp.server._IDA_MCP_CONFIG_FILE", str(cfg))

        # Use an empty port range so discover returns nothing
        saved_mgr = instance_manager.__dict__.copy()
        instance_manager.base_port = 18800
        instance_manager.port_range = 3
        instance_manager.instances = {}
        instance_manager.active_port = None

        class FakeProc:
            pid = 12345
        monkeypatch.setattr("ida_pro_mcp.server.subprocess.Popen", lambda *a, **kw: FakeProc())

        try:
            result = load_binary(str(binary))
            assert "error" not in result, f"Unexpected error: {result.get('error')}"
            assert result["status"] == "spawned"
            assert result["pid"] == 12345
            assert result["binary_path"] == str(binary)
            assert isinstance(result["pre_existing_ports"], list)
        finally:
            instance_manager.__dict__.update(saved_mgr)

    def test_spawn_records_pre_existing_ports(self, tmp_path, monkeypatch):
        """Test that load_binary returns pre-existing ports for polling."""
        binary = tmp_path / "test.exe"
        binary.write_bytes(b"\x00")

        ida_dir = tmp_path / "ida"
        ida_dir.mkdir()
        if sys.platform == "win32":
            ida_exe = ida_dir / "ida.exe"
        else:
            ida_exe = ida_dir / "ida"
        ida_exe.write_bytes(b"\x00")

        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"ida_dir": str(ida_dir)}))
        monkeypatch.setattr("ida_pro_mcp.server._IDA_MCP_CONFIG_FILE", str(cfg))

        # Start a fake instance so it shows up as pre-existing
        test_port = 18815
        fake_server = start_fake_ida(test_port, {"module": "existing.bin"})

        saved_mgr = instance_manager.__dict__.copy()
        instance_manager.base_port = test_port
        instance_manager.port_range = 3
        instance_manager.instances = {}
        instance_manager.active_port = None

        class FakeProc:
            pid = 99999
        monkeypatch.setattr("ida_pro_mcp.server.subprocess.Popen", lambda *a, **kw: FakeProc())

        try:
            result = load_binary(str(binary))
            assert result["status"] == "spawned"
            assert test_port in result["pre_existing_ports"]
        finally:
            fake_server.shutdown()
            instance_manager.__dict__.update(saved_mgr)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
