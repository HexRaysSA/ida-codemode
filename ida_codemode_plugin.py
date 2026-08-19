import os
import sys
from pathlib import Path
from typing import Any

import ida_auto
import ida_kernwin
import ida_loader
import ida_nalt
import idaapi

from ida_codemode._registry import REGISTRY_DIR, InstanceIdentity, find_gui_owner
from ida_codemode._runtime import (
    AnalysisState,
    IDARuntime,
    IdbChangeState,
    create_autoanalysis_hook,
)
from ida_codemode._server import CodeModeHTTPServer


class ReadyToRunHook(ida_kernwin.UI_Hooks):
    def __init__(self, plugin: "CodeModePlugin") -> None:
        super().__init__()
        self.plugin = plugin

    def ready_to_run(self) -> None:
        try:
            self.plugin.start_server()
        except Exception as exc:  # noqa: BLE001 -- IDA startup may raise SWIG errors
            ida_kernwin.msg(f"[ida-codemode] failed to start: {exc}\n")
        finally:
            self.unhook()


class CodeModePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Authenticated IDA Code Mode HTTP API"
    help = ""
    wanted_name = "IDA Code Mode"
    wanted_hotkey = ""

    # term() runs even when init() declined with PLUGIN_SKIP, so every attribute
    # it touches needs a default that predates init().
    _analysis_hook: Any = None
    _ui_hook: ReadyToRunHook | None = None
    _runtime: IDARuntime | None = None
    _server: CodeModeHTTPServer | None = None

    def init(self) -> int:
        # IDA's idalib UI compatibility shim reports is_idaq(), hence both checks.
        if not is_interactive_gui():
            return idaapi.PLUGIN_SKIP
        if sys.version_info < (3, 11):  # noqa: UP036 -- plugin bypasses package metadata
            running = ".".join(str(part) for part in sys.version_info[:3])
            ida_kernwin.msg(
                f"[ida-codemode] Python 3.11 or newer is required (running {running})\n"
            )
            return idaapi.PLUGIN_SKIP
        version = tuple(
            int(part) for part in idaapi.get_kernel_version().split(".")[:2]
        )
        if version < (9, 4):
            ida_kernwin.msg("[ida-codemode] IDA 9.4 or newer is required\n")
            return idaapi.PLUGIN_SKIP

        self.analysis_state = AnalysisState()
        self._analysis_hook = create_autoanalysis_hook(self.analysis_state)
        self._analysis_hook.hook()
        # The change hook is installed only while /idb_events has subscribers
        # and only after initial autoanalysis has finished.
        self.idb_change_state = IdbChangeState()
        # IDA's SWIG stubs model hook constructors with spurious arguments.
        hook_type: Any = ReadyToRunHook
        ui_hook = hook_type(self)
        ui_hook.hook()
        self._ui_hook = ui_hook
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

        idb_path, exe_path = self._current_paths()

        # Back off if another plugin already registered this GUI database. IDA
        # runs ready_to_run callbacks sequentially on its UI thread, and
        # server.start() publishes synchronously, so the next plugin sees it.
        # A second owner would make the resolver raise AmbiguousDatabaseError.
        if idb_path and find_gui_owner(idb_path) is not None:
            ida_kernwin.msg("[ida-codemode] Database already registered, skipping...\n")
            return

        from ida_domain import Database

        database = Database.open()
        identity = InstanceIdentity(idb_path=idb_path, exe_path=exe_path, backend="gui")
        runtime = IDARuntime(
            backend="gui",
            database=database,
            analysis_state=self.analysis_state,
            idb_change_state=self.idb_change_state,
            unattributed_operation_label="IDA GUI",
        )
        server = CodeModeHTTPServer(
            runtime,
            identity,
            self.analysis_state,
            REGISTRY_DIR,
        )
        try:
            server.start()
        except Exception:
            try:
                database.unhook()
            finally:
                # start() may have acquired the lifetime lock before HTTP
                # startup or publication failed. Release it only after the
                # ida-domain database has detached from the GUI IDB.
                server.release_registration()
            raise
        self._runtime = runtime
        self._server = server
        ida_kernwin.msg("[ida-codemode] Database registered successfully!\n")

    def run(self, arg: int) -> None:
        if self._server is not None:
            ida_kernwin.msg(f"[ida-codemode] Server running at {self._server.url}\n")
        else:
            ida_kernwin.msg("[ida-codemode] Server not running...\n")

    def term(self) -> None:
        if self._ui_hook is not None:
            self._ui_hook.unhook()
            self._ui_hook = None
        server = self._server
        if server is not None:
            server.stop()
            self._server = None
        if self._runtime is not None:
            try:
                # Ensure the lazily-installed hook is gone before teardown.
                self._runtime.disable_idb_change_hook()
            except Exception as exc:  # noqa: BLE001 -- best-effort SWIG cleanup
                ida_kernwin.msg(
                    f"[ida-codemode] failed to remove idb-change hook: {exc}\n"
                )
            if self._runtime.database is not None:
                try:
                    self._runtime.database.unhook()
                except Exception as exc:  # noqa: BLE001 -- best-effort SWIG cleanup
                    ida_kernwin.msg(
                        f"[ida-codemode] failed to detach database: {exc}\n"
                    )
            self._runtime = None
        if server is not None:
            # Release the lifetime lock only after detaching from the GUI IDB.
            server.release_registration()
        if self._analysis_hook is not None:
            self._analysis_hook.unhook()
            self._analysis_hook = None


def is_interactive_gui() -> bool:
    """True only for the Qt GUI, never idat or idalib."""

    return bool(ida_kernwin.is_idaq() and os.environ.get("IDA_IS_INTERACTIVE") == "1")


def PLUGIN_ENTRY() -> CodeModePlugin:
    # Always hand IDA an object: returning None makes the kernel complain that
    # "PLUGIN_ENTRY() must return an object!" on every non-GUI run. Declining is
    # init()'s job, via PLUGIN_SKIP, which IDA accepts silently.
    # IDA's SWIG stubs model plugin_t.__new__ with spurious arguments.
    plugin_type: Any = CodeModePlugin
    return plugin_type()
