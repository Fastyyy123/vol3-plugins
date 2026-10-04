import logging
from typing import List, Tuple, Optional, Generator

from volatility3.framework import interfaces, renderers, exceptions, constants, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, pe_symbols

vollog = logging.getLogger(__name__)

try:
    import capstone

    has_capstone = True
except ImportError:
    has_capstone = False

try:
    import pefile

    has_pefile = True
except ImportError:
    has_pefile = False


class EntryPointHijack(interfaces.plugins.PluginInterface):
    """Detects AddressOfEntryPoint Code Injection and Entry Point Hooking/Hijacking."""

    _required_framework_version = (2, 4, 0)
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
                description="Process IDs to include (all other processes are excluded)",
                optional=True,
            ),
        ]

    def _get_entrypoint_info(
        self, proc: interfaces.objects.ObjectInterface
    ) -> Optional[Tuple[int, int, bytes]]:
        """
        Parses the main process PE headers and extracts ImageBase, AddressOfEntryPoint,
        and code bytes at the entry point.
        """
        base_address = proc.SectionBaseAddress
        if not base_address:
            return None

        try:
            proc_layer_name = proc.add_process_layer()
            proc_layer = self.context.layers[proc_layer_name]
        except exceptions.InvalidAddressException:
            return None

        try:
            # Read first page of PE headers
            header_bytes = proc_layer.read(base_address, 0x1000)
            pe_obj = pefile.PE(data=header_bytes, fast_load=True)
            ep_rva = pe_obj.OPTIONAL_HEADER.AddressOfEntryPoint
            if not ep_rva:
                return None

            ep_va = base_address + ep_rva
            code_bytes = b""
            for size in (256, 128, 64):
                try:
                    code_bytes = proc_layer.read(ep_va, size)
                    break
                except exceptions.InvalidAddressException:
                    continue

            if not code_bytes:
                return None

            return (base_address, ep_rva, code_bytes)

        except (exceptions.InvalidAddressException, Exception):
            return None

    def _analyze_code(
        self, code_bytes: bytes, ep_va: int, is_64bit: bool
    ) -> Tuple[bool, str, str, str]:
        """
        Analyzes the entry point machine code using Capstone and signature heuristics.
        Returns: (is_suspicious, confidence, reason, disassembly_str)
        """
        mode = capstone.CS_MODE_64 if is_64bit else capstone.CS_MODE_32
        md = capstone.Cs(capstone.CS_ARCH_X86, mode)
        md.detail = True

        instructions = list(md.disasm(code_bytes, ep_va))
        if not instructions:
            if code_bytes.startswith(b"\x00" * 8):
                return (True, "HIGH", "Zeroed entry point (Corrupted or wiped entry code)", "add [rax], al ... (zeroed)")
            return (True, "MEDIUM", "Entry point contains undecodable instructions", "")

        disasm_summary = " ; ".join(
            f"{insn.mnemonic} {insn.op_str}".strip() for insn in instructions[:5]
        )

        reasons = []
        confidence = "LOW"

        # 1. Zeroed entry point check (e.g., wiped entrypoint or null padding)
        if code_bytes.startswith(b"\x00" * 8):
            reasons.append("Zeroed entry point (Corrupted or wiped entry code)")
            confidence = "HIGH"

        # 2. Consecutive NOP sled detection
        nop_count = 0
        for insn in instructions:
            if insn.mnemonic == "nop":
                nop_count += 1
            else:
                break

        if nop_count >= 4:
            reasons.append(f"Suspicious NOP sled at entry point ({nop_count}+ consecutive NOPs)")
            confidence = "HIGH"

        # 3. Known Stager Signatures (Metasploit, Cobalt Strike, etc.)
        # Check at beginning or immediately following any NOP sled
        sliced_code = code_bytes[nop_count:] if nop_count < len(code_bytes) else b""
        if sliced_code.startswith(b"\xfc\x48\x83\xe4\xf0") or sliced_code.startswith(b"\xfc\x48\x89\xe5"):
            reasons.append("Known x64 PIC Stager Signature (cld; and rsp, -0x10 / mov rbp, rsp)")
            confidence = "HIGH"
        elif sliced_code.startswith(b"\xfc\xe8") or sliced_code.startswith(b"\xfc\x31\xd2"):
            reasons.append("Known x86/x64 Stager Signature (cld; call/xor)")
            confidence = "HIGH"

        # 4. Structural Shellcode Instruction Checks (filtering out NOP padding)
        executable_insns = [insn for insn in instructions if insn.mnemonic != "nop"]
        if executable_insns:
            first_exec = executable_insns[0]
            if first_exec.mnemonic == "cld":
                reasons.append("First executable instruction is 'cld' (Common shellcode flag reset)")
                confidence = "HIGH"

            # Check for TEB/PEB scraping at entry point (gs:[0x60] on x64, fs:[0x30] on x86)
            for i, insn in enumerate(executable_insns[:8]):
                op_str = insn.op_str.lower()
                if is_64bit and ("gs:[0x60]" in op_str or "gs:[60h]" in op_str or "gs:[0x30]" in op_str):
                    reasons.append(f"Direct TEB/PEB traversal in entry prolog: '{insn.mnemonic} {insn.op_str}'")
                    confidence = "HIGH"
                elif not is_64bit and ("fs:[0x30]" in op_str or "fs:[30h]" in op_str or "fs:[0x18]" in op_str):
                    reasons.append(f"Direct TEB/PEB traversal in entry prolog: '{insn.mnemonic} {insn.op_str}'")
                    confidence = "HIGH"

                # Check for stack alignment commonly used in Win64 ABI shellcodes
                if is_64bit and insn.mnemonic == "and" and ("rsp, -0x10" in op_str or "rsp, 0xfffffffffffffff0" in op_str or "rsp, -16" in op_str):
                    reasons.append(f"Stack ABI realignment in entry prolog: '{insn.mnemonic} {insn.op_str}'")
                    if confidence != "HIGH":
                        confidence = "MEDIUM"

                # Check for GetPC code: call next instruction followed by pop
                if insn.mnemonic == "call" and i < len(executable_insns) - 1:
                    next_insn = executable_insns[i + 1]
                    if next_insn.mnemonic == "pop" and insn.address + insn.size == next_insn.address:
                        reasons.append("GetPC delta resolution pattern (call $+5; pop reg)")
                        confidence = "HIGH"

            # Check for inline detour/hook placed at entry point (e.g. jmp [rip + ...] or absolute jump)
            if first_exec.mnemonic == "jmp" and ("[" in first_exec.op_str):
                # Check if this is a .NET stub (jmp mscoree!_CorExeMain is legitimate)
                if not ("mscoree" in disasm_summary.lower()):
                    reasons.append(f"Immediate indirect entry point redirection: '{first_exec.mnemonic} {first_exec.op_str}'")
                    if confidence != "HIGH":
                        confidence = "MEDIUM"

        if reasons:
            return (True, confidence, " | ".join(reasons), disasm_summary)

        return (False, "NONE", "Clean CRT startup", disasm_summary)

    def _generator(
        self, procs: Generator[interfaces.objects.ObjectInterface, None, None]
    ):
        if not has_capstone or not has_pefile:
            vollog.error("Capstone and pefile are required for EntryPointHijack plugin")
            return

        kernel = self.context.modules[self.config["kernel"]]
        is_64bit = symbols.symbol_table_is_64bit(
            context=self.context, symbol_table_name=kernel.symbol_table_name
        )

        for proc in procs:
            ep_info = self._get_entrypoint_info(proc)
            if not ep_info:
                continue

            base_address, ep_rva, code_bytes = ep_info
            ep_va = base_address + ep_rva

            is_suspicious, confidence, reason, disasm_str = self._analyze_code(
                code_bytes, ep_va, is_64bit
            )

            if is_suspicious:
                proc_name = utility.array_to_string(proc.ImageFileName)
                yield (
                    0,
                    (
                        proc.UniqueProcessId,
                        proc_name,
                        format_hints.Hex(base_address),
                        format_hints.Hex(ep_rva),
                        format_hints.Hex(ep_va),
                        confidence,
                        reason,
                        disasm_str,
                        format_hints.HexBytes(code_bytes[:16]),
                    ),
                )

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("BaseAddress", format_hints.Hex),
                ("EntryPointRVA", format_hints.Hex),
                ("EntryPointVA", format_hints.Hex),
                ("Confidence", str),
                ("Reason", str),
                ("Disassembly", str),
                ("Hexdump", format_hints.HexBytes),
            ],
            self._generator(
                pslist.PsList.list_processes(
                    context=self.context,
                    kernel_module_name=self.config["kernel"],
                    filter_func=filter_func,
                )
            ),
        )
