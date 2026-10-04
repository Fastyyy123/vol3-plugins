# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""MockingProbe plugin for detecting Process Mockingjay and in-memory code modification."""

import collections
import logging
import math
from typing import Generator, List, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, vadinfo

vollog = logging.getLogger(__name__)


def calculate_entropy(data: bytes) -> float:
    """Calculates the Shannon entropy of a byte buffer, ignoring zero-padded bytes.

    Args:
        data: Raw byte array to calculate entropy on.

    Returns:
        Shannon entropy value as a float.
    """
    if not data:
        return 0.0
    non_zero = [b for b in data if b != 0]
    if not non_zero:
        return 0.0
    data_len = len(non_zero)
    counts = collections.Counter(non_zero)
    return -sum((count / data_len) * math.log2(count / data_len) for count in counts.values())


class MockingProbe(interfaces.plugins.PluginInterface):
    """Detects Process Mockingjay and in-memory code patching using PTE Dirty bits and entropy."""

    _required_framework_version = (2, 22, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to include (all other processes are excluded)",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="only_suspicious",
                description="Display only suspicious modules (Dirty > 0 or anomalous RWX path)",
                default=False,
                optional=True,
            ),
            requirements.IntRequirement(
                name="max_pages",
                description="Maximum number of pages to scan per VAD",
                default=200000,
                optional=True,
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="vadinfo", component=vadinfo.VadInfo, version=(2, 0, 0)
            ),
        ]

    @staticmethod
    def _pte_flags(layer: interfaces.layers.TranslationLayerInterface, page: int) -> Tuple[bool, bool, bool]:
        """Translates a virtual address and retrieves PTE state.

        Args:
            layer: Process translation layer.
            page: Virtual page address.

        Returns:
            Tuple of (is_resident, is_executable, is_dirty).
        """
        try:
            entry, _ = layer._translate_entry(page & layer.page_mask)
        except Exception:  # noqa: BLE001
            return (False, False, False)

        # Bit 0: Valid / Present
        if not (entry & 1):
            return (False, False, False)

        # Bit 63: XD / No-Execute (0 indicates executable)
        is_exec = ((entry >> 63) & 1) == 0
        # Bit 6: Dirty (1 indicates modified / written to)
        is_dirty = ((entry >> 6) & 1) == 1

        return (True, is_exec, is_dirty)

    def _generator(self) -> Generator[Tuple[int, Tuple], None, None]:
        kernel = self.context.modules[self.config["kernel"]]
        max_pages = self.config.get("max_pages", 200000)
        only_suspicious = self.config.get("only_suspicious", False)

        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        for proc in pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=self.config["kernel"],
            filter_func=filter_func,
        ):
            try:
                pid = proc.UniqueProcessId
                pname = utility.array_to_string(proc.ImageFileName)
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException:
                continue

            if not proc_layer_name:
                continue

            layer = self.context.layers[proc_layer_name]

            for vad in proc.get_vad_root().traverse():
                path = vad.get_file_name()
                if not isinstance(path, str) or not path:
                    continue  # Only file-backed VAD nodes are analyzed

                prot = vad.get_protection(
                    vadinfo.VadInfo.protect_values(
                        self.context, kernel.layer_name, kernel.symbol_table_name
                    ),
                    vadinfo.winnt_protections,
                )

                if "EXECUTE" not in prot:
                    continue

                start, end = vad.get_start(), vad.get_end()
                resident = exec_ = dirty_exec = 0
                dirty_pages: List[int] = []
                npages = min((end - start) // layer.page_size + 1, max_pages)

                # Scan PTE flags for all pages in the VAD
                for i in range(npages):
                    p = start + i * layer.page_size
                    res, ex, dirty = self._pte_flags(layer, p)
                    if res:
                        resident += 1
                        if ex:
                            exec_ += 1
                            if dirty:
                                dirty_exec += 1
                                if len(dirty_pages) < 8:
                                    dirty_pages.append(p)

                path_lower = path.lower()
                is_anomalous_path = any(
                    x in path_lower for x in ["users\\", "temp\\", "programdata\\", "desktop\\", "downloads\\"]
                )
                is_rwx_or_writecopy = ("WRITE" in prot) or ("WRITECOPY" in prot)
                has_dirty_exec = dirty_exec > 0

                # Targeted entropy calculation:
                # If modified pages exist, calculate entropy strictly on the dirty pages.
                # If no dirty pages, sample pages only if the region has anomalous RWX permissions.
                payload_data = bytearray()
                if dirty_pages:
                    for dp in dirty_pages:
                        try:
                            pdata = layer.read(dp, layer.page_size, pad=True)
                            if pdata:
                                payload_data.extend(pdata)
                        except Exception:
                            pass
                elif is_anomalous_path and is_rwx_or_writecopy:
                    sample_pages = min(npages, 16)
                    for i in range(sample_pages):
                        p = start + i * layer.page_size
                        try:
                            pdata = layer.read(p, layer.page_size, pad=True)
                            if pdata:
                                payload_data.extend(pdata)
                        except Exception:
                            pass

                entropy = calculate_entropy(payload_data) if payload_data else 0.0

                is_suspicious = has_dirty_exec or (is_rwx_or_writecopy and is_anomalous_path)
                if only_suspicious and not is_suspicious:
                    continue

                module_name = path.split("\\")[-1]

                yield (0, (
                    pid,
                    pname,
                    format_hints.Hex(start),
                    format_hints.Hex(end),
                    prot,
                    resident,
                    exec_,
                    dirty_exec,
                    " ".join(f"0x{x:x}" for x in dirty_pages) if dirty_pages else "N/A",
                    round(entropy, 2),
                    module_name,
                    path,
                ))

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid([
            ("PID", int),
            ("Process", str),
            ("Start", format_hints.Hex),
            ("End", format_hints.Hex),
            ("Prot", str),
            ("Resident", int),
            ("ExecPages", int),
            ("Dirty", int),
            ("DirtyAddrs", str),
            ("Entropy", float),
            ("Module", str),
            ("Path", str),
        ], self._generator())
