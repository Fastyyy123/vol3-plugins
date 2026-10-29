# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Detects in-memory patching of a process entry point.

AddressOfEntryPoint code injection overwrites the code at the entry point of an
already mapped, legitimate image (usually a signed system binary that is started
suspended and resumed after the write). The technique leaves no new VAD, no
changed VAD protection, no modified PE header and no hollowed section behind, so
VAD and protection based plugins cannot see it, and the in-memory PE header still
reports the same AddressOfEntryPoint as the file on disk.

The write always breaks the copy-on-write mapping of the page that holds the
entry point (the page is copied into a private page), so the plugin checks the
page state and compares the in-memory entry point bytes with the image section's
own page, which is the original file content. Disassembly and opcode heuristics
are only used to describe the payload, not to make the decision.
"""

import logging
from typing import Dict, List, Optional, Tuple

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, ptenum

try:
    import capstone

    has_capstone = True
except ImportError:
    has_capstone = False

vollog = logging.getLogger(__name__)

PAGE_SIZE = 0x1000
# Bytes at the entry point compared with the image section page
DIFF_WINDOW = 32
# Bytes at the entry point rendered as a hexdump and disassembly
EP_DUMP_SIZE = 64
# _IMAGE_SECTION_HEADER.Characteristics
IMAGE_SCN_MEM_EXECUTE = 0x20000000
# _IMAGE_OPTIONAL_HEADER.DataDirectory index
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14

# Prologues of the most common position independent stagers
STAGER_SIGNATURES = (
    b"\xfc\x48\x83\xe4\xf0",
    b"\xfc\x48\x89\xe5",
    b"\xfc\xe8",
    b"\xfc\x31\xd2",
)


class EntryPointHijack(interfaces.plugins.PluginInterface, ptenum.PteEnumerator):
    """Detects entry point patching by comparing the entry point page with its image."""

    _required_framework_version = (2, 22, 0)
    _version = (2, 0, 0)

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
                name="show_all",
                description="Also show processes with an intact or unverifiable entry point",
                default=False,
                optional=True,
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
        ]

    @staticmethod
    def _parse_pe(
        layer: interfaces.layers.TranslationLayerInterface, image_base: int
    ) -> Optional[Dict]:
        """Parses the NT headers of the image mapped at image_base.

        Only the headers are read, so images whose headers span more than one
        page are handled as well.

        Args:
            layer: Layer to read the image from
            image_base: Virtual address the image is mapped at

        Returns:
            A dictionary with the machine type, entry point RVA, image size,
            section table and the .NET flag, or None if the headers are invalid
        """
        dos_header = layer.read(image_base, 0x40)
        if dos_header[:2] != b"MZ":
            return None

        e_lfanew = int.from_bytes(dos_header[0x3C:0x40], "little")
        if e_lfanew <= 0 or e_lfanew > 0x10000:
            return None

        nt_header = layer.read(image_base + e_lfanew, 0x18)
        if nt_header[:4] != b"PE\x00\x00":
            return None

        number_of_sections = int.from_bytes(nt_header[6:8], "little")
        size_of_optional_header = int.from_bytes(nt_header[0x14:0x16], "little")
        if number_of_sections > 96 or size_of_optional_header > 0x400:
            return None

        optional_header = layer.read(
            image_base + e_lfanew + 0x18, size_of_optional_header
        )
        if len(optional_header) < 0x40:
            return None

        magic = int.from_bytes(optional_header[0:2], "little")
        if magic not in (0x10B, 0x20B):
            return None

        # NumberOfRvaAndSizes and DataDirectory follow the fixed optional
        # header fields and move between PE32 and PE32+
        data_directory_offset = 0x60 if magic == 0x10B else 0x70
        number_of_rva_offset = 0x5C if magic == 0x10B else 0x6C
        is_dotnet = False
        try:
            number_of_rva = int.from_bytes(
                optional_header[number_of_rva_offset : number_of_rva_offset + 4],
                "little",
            )
            if number_of_rva > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
                entry_offset = (
                    data_directory_offset + IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR * 8
                )
                is_dotnet = (
                    int.from_bytes(
                        optional_header[entry_offset : entry_offset + 4], "little"
                    )
                    != 0
                )
        except IndexError:
            is_dotnet = False

        sections = []
        if number_of_sections:
            table_address = image_base + e_lfanew + 0x18 + size_of_optional_header
            section_table = layer.read(table_address, 40 * number_of_sections)
            for index in range(number_of_sections):
                entry = section_table[index * 40 : (index + 1) * 40]
                if len(entry) < 40:
                    break
                sections.append(
                    (
                        entry[:8].rstrip(b"\x00").decode("ascii", "replace"),
                        int.from_bytes(entry[0x0C:0x10], "little"),  # VirtualAddress
                        max(
                            int.from_bytes(entry[0x08:0x0C], "little"),  # VirtualSize
                            int.from_bytes(entry[0x10:0x14], "little"),  # RawSize
                        ),
                        int.from_bytes(entry[0x24:0x28], "little"),  # Characteristics
                    )
                )

        return {
            "is_64bit": magic == 0x20B,
            "is_dotnet": is_dotnet,
            "ep_rva": int.from_bytes(optional_header[0x10:0x14], "little"),
            "size_of_image": int.from_bytes(optional_header[0x38:0x3C], "little"),
            "sections": sections,
        }

    @staticmethod
    def _section_for_rva(
        sections: List[Tuple[str, int, int, int]], rva: int
    ) -> Optional[Tuple[str, int, int, int]]:
        """Returns the section that contains the given RVA, if any."""
        for section in sections:
            _name, virtual_address, virtual_size, _characteristics = section
            if virtual_address <= rva < virtual_address + virtual_size:
                return section
        return None

    def _get_image_base(
        self, proc: interfaces.objects.ObjectInterface
    ) -> Optional[int]:
        """Returns the image base from the PEB, which is authoritative for the mapping."""
        try:
            peb = self.context.object(
                self.kernel.symbol_table_name + constants.BANG + "_PEB",
                layer_name=self.proc_layer.name,
                offset=proc.Peb,
            )
            image_base = int(peb.ImageBaseAddress)
        except exceptions.InvalidAddressException:
            return None
        return image_base or None

    def _get_page_state(self, page_address: int) -> str:
        """Returns the state of the page holding the entry point.

        The value is one of clean, dirty (the page was written), trimmed (the
        page is not resident, the PTE points into the image section) or
        unmapped.
        """
        try:
            entry, _ = self.proc_layer._translate_entry(page_address)
        except exceptions.InvalidAddressException:
            return "unmapped"

        resident = bool(entry & 1)
        # Bit 10 marks a prototype PTE, i.e. a page that still belongs to the section
        prototype = bool(entry & (1 << 10))
        # Bit 6 is the dirty flag, set when the page is written to
        dirty = bool(entry & (1 << 6))

        if prototype and not resident:
            return "trimmed"
        if resident:
            return "dirty" if dirty else "clean"
        return "unmapped"

    def _diff_with_image(
        self, entry_point: int
    ) -> Tuple[Optional[str], Optional[bytes], Optional[bytes]]:
        """Compares the in-memory entry point with the image section page.

        The image section page is read through the prototype PTE of the mapping,
        so the comparison uses the original file content and does not need the
        disk the image came from.

        Args:
            entry_point: Virtual address of the entry point

        Returns:
            A tuple of the diff summary (None when the image page is
            unavailable), the bytes mapped in the process and the original
            image bytes
        """
        window = min(EP_DUMP_SIZE, PAGE_SIZE - (entry_point & (PAGE_SIZE - 1)))
        try:
            current = self.proc_layer.read(entry_point, window)
        except exceptions.InvalidAddressException:
            return None, None, None

        try:
            pte_address, pte_value = self._get_protopte_addr_and_val_via_vad(
                entry_point
            )
            pte_physical = self.proc_layer.translate(pte_address)[0]
            image_page = self.resolve_pte(
                entry_point,
                pte_value,
                pte_physical,
                pte_vaddr=pte_address,
                is_proto=True,
                zero_ret=False,
            )
            if image_page is None or not image_page.is_data_available:
                return None, current, None
            original = image_page.read(
                rel_off=entry_point - image_page.vaddr, length=window
            )
        except Exception:
            return None, current, None

        if not original or len(original) != len(current):
            return None, current, original

        compare_length = min(DIFF_WINDOW, len(current))
        differing = [
            index
            for index in range(compare_length)
            if current[index] != original[index]
        ]
        if not differing:
            return "same as image", current, original
        return (
            f"{len(differing)} byte(s) differ, first at +0x{differing[0]:x}",
            current,
            original,
        )

    @classmethod
    def _payload_hints(
        cls, code: bytes, entry_point: int, is_64bit: bool, is_dotnet: bool
    ) -> List[str]:
        """Returns hints that describe a payload found at the entry point.

        The hints do not decide the verdict, they only help to describe what was
        written to the entry point and act as a fallback when the image page is
        not available for the comparison.
        """
        hints: List[str] = []
        if not code:
            return hints

        if code.startswith(b"\x00" * 8):
            hints.append("zeroed EP")
            return hints

        if not has_capstone:
            return hints

        mode = capstone.CS_MODE_64 if is_64bit else capstone.CS_MODE_32
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, mode)
        disassembler.detail = True
        try:
            instructions = list(disassembler.disasm(code, entry_point))
        except capstone.CsError:
            return hints

        if not instructions:
            hints.append("undecodable")
            return hints

        # NOP padding in front of a staged payload follows the same rules as a NOP sled
        nop_count = 0
        nop_end = 0
        for instruction in instructions:
            if instruction.mnemonic != "nop":
                break
            nop_count += 1
            nop_end = instruction.address + instruction.size - entry_point
        if nop_count >= 4:
            hints.append("NOP sled")

        stager = any(
            code[nop_end:].startswith(signature) for signature in STAGER_SIGNATURES
        )
        if stager:
            hints.append("PIC stager")

        executable = [insn for insn in instructions if insn.mnemonic != "nop"]
        if executable:
            first = executable[0]
            if first.mnemonic == "cld" and not stager:
                hints.append("cld")
            if first.mnemonic == "int3":
                hints.append("int3")
            if first.mnemonic == "jmp" and "[" in first.op_str and not is_dotnet:
                # jmp qword ptr [...] is also how the .NET stub reaches _CorExeMain
                hints.append("jmp [mem]")

        for index, instruction in enumerate(executable[:8]):
            operands = instruction.op_str.lower()
            if (is_64bit and ("gs:[0x60]" in operands or "gs:[60h]" in operands)) or (
                not is_64bit and ("fs:[0x30]" in operands or "fs:[30h]" in operands)
            ):
                if "PEB walk" not in hints:
                    hints.append("PEB walk")
            if (
                instruction.mnemonic == "call"
                and index + 1 < len(executable)
                and executable[index + 1].mnemonic == "pop"
                and instruction.address + instruction.size
                == executable[index + 1].address
            ):
                hints.append("GetPC")

        return hints

    @classmethod
    def _first_branch_target(
        cls, code: bytes, entry_point: int, is_64bit: bool
    ) -> Optional[int]:
        """Returns the target of a direct jmp/call at the entry point, if any."""
        if not has_capstone or len(code) < 2:
            return None

        mode = capstone.CS_MODE_64 if is_64bit else capstone.CS_MODE_32
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, mode)
        disassembler.detail = True
        try:
            for instruction in disassembler.disasm(code[:16], entry_point):
                if (
                    instruction.mnemonic in ("jmp", "call")
                    and instruction.operands
                    and instruction.operands[0].type == capstone.x86.X86_OP_IMM
                ):
                    return instruction.operands[0].imm
                return None
        except (capstone.CsError, IndexError):
            return None
        return None

    def _check_process(
        self, proc: interfaces.objects.ObjectInterface
    ) -> Optional[Tuple[str, Tuple]]:
        """Checks a single process and returns its verdict and output row."""
        try:
            self.init_for_proc(proc)
        except Exception:
            # Terminated, smeared or otherwise unreadable process
            return None
        if self.proc_layer is None:
            return None

        try:
            section_base = int(proc.SectionBaseAddress)
        except exceptions.InvalidAddressException:
            section_base = 0

        image_base = self._get_image_base(proc) or section_base
        if not image_base:
            return None

        try:
            pe = self._parse_pe(self.proc_layer, image_base)
        except exceptions.InvalidAddressException:
            return None
        if not pe or not pe["ep_rva"]:
            return None

        entry_point = image_base + pe["ep_rva"]
        page_address = entry_point & ~(PAGE_SIZE - 1)

        # Findings that prove the entry point was modified
        findings: List[str] = []
        # Supporting hints that describe the payload but can be a false positive
        hints: List[str] = []

        if section_base and section_base != image_base:
            findings.append("base mismatch")

        if pe["size_of_image"] and pe["ep_rva"] >= pe["size_of_image"]:
            findings.append("EP outside image")

        section = self._section_for_rva(pe["sections"], entry_point - image_base)
        section_name = "-"
        if section is None:
            findings.append("EP outside sections")
        else:
            section_name = section[0] or "-"
            if not section[3] & IMAGE_SCN_MEM_EXECUTE:
                findings.append("non-exec section")

        page_state = self._get_page_state(page_address)
        if page_state == "dirty":
            findings.append("page written")

        diff, current, _original = self._diff_with_image(entry_point)
        if diff is not None and diff != "same as image":
            findings.append("patched")

        hints.extend(
            self._payload_hints(
                current or b"", entry_point, pe["is_64bit"], pe["is_dotnet"]
            )
        )

        branch_target = self._first_branch_target(
            current or b"", entry_point, pe["is_64bit"]
        )
        if branch_target is not None and pe["size_of_image"]:
            image_end = image_base + pe["size_of_image"]
            if not image_base <= branch_target < image_end:
                findings.append("branch outside image")

        if findings:
            verdict = "SUSPICIOUS"
            confidence = "HIGH"
        elif hints:
            verdict = "SUSPICIOUS"
            confidence = "MEDIUM"
        elif page_state in ("trimmed", "unmapped") or diff is None:
            verdict = "unknown"
            confidence = None
        else:
            verdict = "clean"
            confidence = None

        notes = findings + hints
        if current:
            hexdump = renderers.LayerData(
                context=self.context,
                layer_name=self.proc_layer.name,
                offset=entry_point,
                length=len(current),
                no_surrounding=True,
            )
            disassembly = renderers.Disassembly(
                current, entry_point, "intel64" if pe["is_64bit"] else "intel"
            )
        else:
            hexdump = renderers.NotAvailableValue()
            disassembly = renderers.NotAvailableValue()

        row = (
            int(proc.UniqueProcessId),
            utility.array_to_string(proc.ImageFileName),
            format_hints.Hex(image_base),
            format_hints.Hex(entry_point),
            section_name,
            page_state,
            diff or "n/a",
            verdict,
            confidence or renderers.NotApplicableValue(),
            ", ".join(notes) if notes else "-",
            hexdump,
            disassembly,
        )
        return verdict, row

    def _generator(self, procs):
        show_all = self.config.get("show_all", False)

        for proc in procs:
            result = self._check_process(proc)
            if result is None:
                continue
            verdict, row = result
            if verdict != "SUSPICIOUS" and not show_all:
                continue
            yield (0, row)

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("ImageBase", format_hints.Hex),
                ("EntryPoint", format_hints.Hex),
                ("Section", str),
                ("PageState", str),
                ("ImageDiff", str),
                ("Verdict", str),
                ("Confidence", str),
                ("Notes", str),
                ("Hexdump", renderers.LayerData),
                ("Disasm", renderers.Disassembly),
            ],
            self._generator(
                pslist.PsList.list_processes(
                    context=self.context,
                    kernel_module_name=self.config["kernel"],
                    filter_func=filter_func,
                )
            ),
        )
