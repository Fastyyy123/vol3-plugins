# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
import logging
from typing import List, Optional, Tuple, Iterable

from volatility3.framework import constants, exceptions, renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)

STARTF_FLAGS = {
    0x00000001: "STARTF_USESHOWWINDOW",
    0x00000002: "STARTF_USESIZE",
    0x00000004: "STARTF_USEPOSITION",
    0x00000008: "STARTF_USECOUNTCHARS",
    0x00000010: "STARTF_USEFILLATTRIBUTE",
    0x00000020: "STARTF_RUNFULLSCREEN",
    0x00000040: "STARTF_FORCEONFEEDBACK",
    0x00000080: "STARTF_FORCEOFFFEEDBACK",
    0x00000100: "STARTF_USESTDHANDLES",
    0x00000200: "STARTF_USEHOTKEY",
    0x00000800: "STARTF_TITLEISLINKNAME",
    0x00001000: "STARTF_TITLEISAPPID",
    0x00002000: "STARTF_PREVENTPINNING",
    0x00008000: "STARTF_UNTRUSTEDSOURCE"
}

SW_FLAGS = {
    0: "SW_HIDE",
    1: "SW_SHOWNORMAL",
    2: "SW_SHOWMINIMIZED",
    3: "SW_SHOWMAXIMIZED",
    4: "SW_SHOWNOACTIVATE",
    5: "SW_SHOW",
    6: "SW_MINIMIZE",
    7: "SW_SHOWMINNOACTIVE",
    8: "SW_SHOWNA",
    9: "SW_RESTORE",
    10: "SW_SHOWDEFAULT",
    11: "SW_FORCEMINIMIZE"
}

HIDE_COMBO_FLAGS = STARTF_USESHOWWINDOW = 0x00000001
HIDE_COMBO_SW_VALUES = {0, 7, 8}


class WindowFlags(interfaces.plugins.PluginInterface):
    """Dumps WindowFlags and ShowWindowFlags from ProcessParameters in PEB."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 1, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to include",
                optional=True,
            ),
            requirements.ListRequirement(
                name="exclude-pid",
                element_type=int,
                description="Process IDs to exclude",
                optional=True,
            ),
        ]

    @staticmethod
    def create_exclude_pid_filter(excluded_pids: Optional[List[int]] = None):
        """A filter factory for filtering out excluded PIDs."""

        def filter_func(_):
            if excluded_pids is None:
                return False
            return _.UniqueProcessId in excluded_pids

        return filter_func

    @classmethod
    def _decode_window_flags(cls, wflags_val: int) -> str:
        wflags_strs = [
            name for mask, name in STARTF_FLAGS.items() if wflags_val & mask
        ]
        return f"{hex(wflags_val)} ({' | '.join(wflags_strs) or 'None'})"

    @classmethod
    def _decode_showwindow_flags(cls, swflags_val: int) -> str:
        return f"{hex(swflags_val)} ({SW_FLAGS.get(swflags_val, 'UNKNOWN')})"

    @classmethod
    def _is_hidden_suspicious(cls, wflags_val: int, swflags_val: int) -> bool:
        """STARTF_USESHOWWINDOW combined with a hide/no-activate ShowWindow value."""
        return (
            bool(wflags_val & HIDE_COMBO_FLAGS)
            and swflags_val in HIDE_COMBO_SW_VALUES
        )

    def _generator(self, procs) -> Iterable[Tuple[int, Tuple]]:
        kernel = self.context.modules[self.config["kernel"]]

        for proc in procs:
            process_name = utility.array_to_string(proc.ImageFileName)
            try:
                proc_id = proc.UniqueProcessId
            except exceptions.InvalidAddressException:
                proc_id = None

            wflags = renderers.UnreadableValue()
            swflags = renderers.UnreadableValue()
            hidden = "-"

            try:
                proc_layer_name = proc.add_process_layer()
                peb = self.context.object(
                    kernel.symbol_table_name + constants.BANG + "_PEB",
                    layer_name=proc_layer_name,
                    offset=proc.Peb,
                )
                wflags_val = peb.ProcessParameters.WindowFlags
                swflags_val = peb.ProcessParameters.ShowWindowFlags
            except exceptions.InvalidAddressException as exc:
                vollog.debug(
                    f"Unable to read PEB for process {process_name} "
                    f"(PID {proc_id}): {exc}"
                )
            else:
                wflags = self._decode_window_flags(wflags_val)
                swflags = self._decode_showwindow_flags(swflags_val)
                hidden = (
                    "SUSPICIOUS"
                    if self._is_hidden_suspicious(wflags_val, swflags_val)
                    else "-"
                )

            yield (0, (proc_id, process_name, wflags, swflags, hidden))

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        exclude_func = self.create_exclude_pid_filter(
            self.config.get("exclude-pid", None)
        )

        def combined_filter(proc):
            return filter_func(proc) or exclude_func(proc)

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("WindowFlags", str),
                ("ShowWindowFlags", str),
                ("HiddenSuspicious", str),
            ],
            self._generator(
                pslist.PsList.list_processes(
                    context=self.context,
                    kernel_module_name=self.config["kernel"],
                    filter_func=combined_filter,
                )
            ),
        )
