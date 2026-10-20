# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""MockingProbe plugin for detecting Process Mockingjay and in-memory code modification.

The plugin walks every executable file-backed VAD of a process page by page,
translates each page through the page tables and looks for pages that are both
executable (NX = 0) and modified (Dirty = 1). The content of the modified pages
is read back and scored with the Shannon entropy: a payload that was written
into an executable mapping scores above ENTROPY_THRESHOLD.
"""

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

# Shannon entropy above which the bytes read back from the modified executable
# pages are treated as an injected payload rather than as patched code.
ENTROPY_THRESHOLD = 5.0

# Upper bound on the number of dirty pages read back per VAD. Modified pages in
# an image section are a handful in practice, the bound only keeps the payload
# buffer small if a whole section was rewritten.
MAX_DIRTY_PAGES = 1024

# Number of pages sampled for the fallback score (see _generator): used when the
# mapping has no modified page at all, so there is nothing to read back.
FALLBACK_SAMPLE_PAGES = 16


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
    return -sum(
        (count / data_len) * math.log2(count / data_len) for count in counts.values()
    )


class MockingProbe(interfaces.plugins.PluginInterface):
    """Detects Process Mockingjay and in-memory code patching using PTE Dirty bits and entropy."""

    _required_framework_version = (2, 22, 0)
    _version = (1, 1, 0)

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
                description="Display only suspicious modules (Dirty > 0 or anomalous RWX path, entropy > 5)",
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
    def _pte_flags(
        layer: interfaces.layers.TranslationLayerInterface, page: int
    ) -> Tuple[bool, bool, bool]:
        """Translates a virtual address and retrieves PTE state.

        Args:
            layer: Process translation layer.
            page: Virtual page address.

        Returns:
            Tuple of (is_resident, is_executable, is_dirty).
        """
        try:
            entry, _ = layer._translate_entry(page & layer.page_mask)
        except exceptions.InvalidAddressException:
            return (False, False, False)

        # A page is resident if it is valid. Windows also marks pages as usable
        # through the transition (bit 11) / prototype (bit 10) bits, so the check
        # is delegated to the translation layer instead of testing bit 0 alone.
        page_is_valid = getattr(layer, "_page_is_valid", None)
        if page_is_valid is not None:
            if not page_is_valid(entry):
                return (False, False, False)
        elif not (entry & 1):
            return (False, False, False)

        # Bit 63: XD / No-Execute (0 indicates executable)
        is_exec = ((entry >> 63) & 1) == 0
        # Bit 6: Dirty (1 indicates modified / written to)
        is_dirty = ((entry >> 6) & 1) == 1

        return (True, is_exec, is_dirty)

    @staticmethod
    def _read_pages(
        layer: interfaces.layers.TranslationLayerInterface, pages: List[int]
    ) -> bytes:
        """Reads the given pages back from the process address space."""
        payload = bytearray()
        for page in pages:
            try:
                payload.extend(layer.read(page, layer.page_size, pad=True))
            except exceptions.InvalidAddressException:
                # A page can be released between the PTE walk and the read.
                continue
        return bytes(payload)

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

            try:
                vads = list(proc.get_vad_root().traverse())
            except exceptions.InvalidAddressException:
                # Terminated or smeared process: the VAD tree is not walkable.
                continue

            for vad in vads:
                # Step 1: only executable file-backed sections are of interest.
                path = vad.get_file_name()
                if not isinstance(path, str) or not path:
                    continue

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

                # Step 2: walk the page tables and look for Dirty = 1 at NX = 0.
                for i in range(npages):
                    p = start + i * layer.page_size
                    res, ex, dirty = self._pte_flags(layer, p)
                    if res:
                        resident += 1
                        if ex:
                            exec_ += 1
                            if dirty:
                                dirty_exec += 1
                                if len(dirty_pages) < MAX_DIRTY_PAGES:
                                    dirty_pages.append(p)

                path_lower = path.lower()
                is_anomalous_path = any(
                    x in path_lower
                    for x in [
                        "users\\",
                        "temp\\",
                        "programdata\\",
                        "desktop\\",
                        "downloads\\",
                    ]
                )
                is_rwx_or_writecopy = ("WRITE" in prot) or ("WRITECOPY" in prot)
                has_dirty_exec = dirty_exec > 0

                # Step 3: read back the modified pages and score their content.
                if dirty_pages:
                    entropy = calculate_entropy(self._read_pages(layer, dirty_pages))
                else:
                    # Nothing was ever written through this mapping, so there is
                    # no modified page to read back. Modules outside the system
                    # directories that are still mapped writable and executable
                    # are scored on the image itself, so that a payload placed
                    # without touching the Dirty bit (copy-on-write break from
                    # another process) is reported as well.
                    entropy = 0.0
                    if is_anomalous_path and is_rwx_or_writecopy:
                        sample = [
                            start + i * layer.page_size
                            for i in range(min(npages, FALLBACK_SAMPLE_PAGES))
                        ]
                        entropy = calculate_entropy(self._read_pages(layer, sample))

                # Step 4: verdict - high entropy payload on a modified executable
                # page, or on a writable executable mapping from a user path.
                looks_like_payload = entropy > ENTROPY_THRESHOLD
                is_suspicious = looks_like_payload and (
                    has_dirty_exec or (is_rwx_or_writecopy and is_anomalous_path)
                )
                if only_suspicious and not is_suspicious:
                    continue

                module_name = path.split("\\")[-1]
                dirty_addrs = " ".join(f"0x{x:x}" for x in dirty_pages[:8])
                if len(dirty_pages) > 8:
                    dirty_addrs += " ..."

                yield (
                    0,
                    (
                        pid,
                        pname,
                        format_hints.Hex(start),
                        format_hints.Hex(end),
                        prot,
                        resident,
                        exec_,
                        dirty_exec,
                        dirty_addrs if dirty_pages else "N/A",
                        round(entropy, 2),
                        module_name,
                        path,
                    ),
                )

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
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
            ],
            self._generator(),
        )
