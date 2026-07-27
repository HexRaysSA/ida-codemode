from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import ida_auto
import ida_diskio
import ida_kernwin
import ida_loader
import ida_nalt
import idaapi

from ida_codemode.registry import InstanceIdentity, get_registry_dir
from ida_codemode.runtime import IDARuntime, AnalysisState, create_autoanalysis_hook
from ida_codemode.server import CodeModeHTTPServer


class ReadyToRunHook(ida_kernwin.UI_Hooks):
    def __init__(self, plugin: "CodeModePlugin") -> None:
        super().__init__()
        self.plugin = plugin

    def ready_to_run(self) -> None:
        try:
            self.plugin.start_server()
        except Exception as exc:
            ida_kernwin.msg(f"[ida-codemode] failed to start: {exc}\n")
        finally:
            self.unhook()


class CodeModePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Authenticated IDA Code Mode HTTP API"
    help = ""
    wanted_name = "IDA Code Mode"
    wanted_hotkey = ""

    def init(self) -> int:
        self.analysis_state = AnalysisState()
        self._analysis_hook: Any = create_autoanalysis_hook(self.analysis_state)
        self._analysis_hook.hook()
        # IDA's SWIG stubs model hook constructors with spurious arguments.
        hook_type: Any = ReadyToRunHook
        ui_hook = hook_type(self)
        ui_hook.hook()
        self._ui_hook: ReadyToRunHook | None = ui_hook
        self._runtime: IDARuntime | None = None
        self._server: CodeModeHTTPServer | None = None
        return idaapi.PLUGIN_KEEP

    @staticmethod
    def _current_paths() -> tuple[str, str]:
        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or ""
        exe_path = ida_nalt.get_input_file_path() or ""
        return (
            str(Path(idb_path).resolve()) if idb_path else "",
            str(Path(exe_path).resolve()) if exe_path else "",
        )

    def start_server(self) -> None:
        if self._server is not None:
            return
        if ida_auto.auto_is_ok():
            self.analysis_state.mark_complete()

        from ida_domain import Database

        database = Database.open()
        idb_path, exe_path = self._current_paths()
        identity = InstanceIdentity(idb_path=idb_path, exe_path=exe_path, backend="gui")
        runtime = IDARuntime(
            backend="gui",
            database=database,
            analysis_state=self.analysis_state,
            database_path=idb_path,
            database_options={"backend": "gui"},
        )
        server = CodeModeHTTPServer(
            runtime,
            identity,
            self.analysis_state,
            get_registry_dir(ida_diskio.get_user_idadir()),
        )
        try:
            server.start()
        except Exception:
            database.unhook()
            raise
        self._runtime = runtime
        self._server = server
        ida_kernwin.msg(f"[ida-codemode] {server.url}\n")

    def run(self, arg: int) -> None:
        if self._server is not None:
            ida_kernwin.msg(f"[ida-codemode] {self._server.url}\n")

    def term(self) -> None:
        if self._ui_hook is not None:
            self._ui_hook.unhook()
            self._ui_hook = None
        if self._server is not None:
            self._server.stop()
            self._server = None
        if self._runtime is not None and self._runtime.database is not None:
            try:
                self._runtime.database.unhook()
            except Exception:
                pass
            self._runtime = None
        if self._analysis_hook is not None:
            self._analysis_hook.unhook()
            self._analysis_hook = None


def is_interactive_gui() -> bool:
    """True only for the Qt GUI, never idat or idalib."""

    return bool(ida_kernwin.is_idaq() and os.environ.get("IDA_IS_INTERACTIVE") == "1")


def PLUGIN_ENTRY() -> CodeModePlugin | None:
    # IDA's idalib UI compatibility shim reports is_idaq(), hence both checks.
    if not is_interactive_gui():
        return None
    version = tuple(int(part) for part in idaapi.get_kernel_version().split(".")[:2])
    if version < (9, 4):
        ida_kernwin.msg("[ida-codemode] IDA 9.4 or newer is required\n")
        return None
    # IDA's SWIG stubs model plugin_t.__new__ with spurious arguments.
    plugin_type: Any = CodeModePlugin
    return plugin_type()
