## Plugin Overview

### 1. `windowflags.py`
* **Module:** `windows.windowflags.WindowFlags`
* **Description:** Analyzes `ProcessParameters` within each process's PEB. Extracts and decodes `WindowFlags` and `ShowWindowFlags` [attributes](https://ntdoc.m417z.com/rtl_user_process_parameters), allowing forensic analysts to identify stealth background processes and hidden consoles


### 2. `entrypoint_hijack.py`
* **Module:** `windows.malware.entrypoint_hijack.EntryPointHijack`
* **Description:** Detects `AddressOfEntryPoint` [code injection](https://www.ired.team/offensive-security/code-injection-process-injection/addressofentrypoint-code-injection-without-virtualallocex-rwx) by **entry point integrity**, not by opcode signatures.

* The technique leaves no new VAD, no changed protection and no modified PE header, but it always breaks the copy-on-write mapping of the page holding the entry point. The plugin resolves the image section's own page through its prototype PTE (the original file content, no disk image needed) and diffs the in-memory entry point against it, so the verdict comes from a byte comparison with the untouched image.
* output like in `malfind` :)
* Pages that are trimmed cannot be compared and are reported as `unknown` instead of clean; `--show_all` also prints clean and unverifiable processes, `--pid` filters on process IDs.

### 3. `ghostscan.py`
* **Module:** `windows.malware.ghostscan.GhostScan`
* **Description:** Detects **Process Ghosting** technique. Identifies processes and VAD structures where the underlying on-disk binary has been marked for deletion (`DeletePending = 1`), where the `FILE_OBJECT` pointer is zeroed, or where image sections were mapped with `DeleteOnClose` flags.
* The official plugin of volatility3 ([windows.malware.processghosting.ProcessGhosting](https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/malware/processghosting.py)) has the [architectural limitation](https://github.com/volatilityfoundation/volatility3/blob/3fcb731e0ba5b6c4e90f19445a10f9da2bba02a4/volatility3/framework/plugins/windows/malware/processghosting.py#L207): it does not scan terminated processes. Ghostscan does this if `--include-terminated` flag specified
* added a `--pid` flag for filtering on specific process IDs

### 4. `mockingprobe.py`
* **Module:** `windows.malware.mockingprobe.MockingProbe`
* **Description:** detector for **[Process Mockingjay](https://heimdalsecurity.com/blog/new-mockingjay-process-injection-method-enables-malware-evade-edr-tools/)** and in-memory code modification in file-backed modules. Walks every executable file-backed VAD page by page, inspects hardware **PTE Dirty flags (bit 6)** at `NX = 0` to verify in-memory page writes, reads the modified pages back and applies a **Shannon entropy threshold (`> 5`)** to separate shellcode from patched code, and correlates the verdict with suspicious execution paths. `--only-suspicious` prints only modules that pass the entropy threshold together with a dirty page or an anomalous `EXECUTE_WRITECOPY` / `RWX` mapping

---

### Install

#### Linux / WSL / macOS (Bash):
```bash
VOL3_DIR="/path/to/volatility3" && cp windowflags.py "$VOL3_DIR/volatility3/plugins/windows/" && cp entrypoint_hijack.py ghostscan.py mockingprobe.py "$VOL3_DIR/volatility3/framework/plugins/windows/malware/"
```

#### Windows (PowerShell):
```powershell
$VOL3 = "C:\path\to\volatility3"; Copy-Item windowflags.py "$VOL3\volatility3\plugins\windows\"; Copy-Item entrypoint_hijack.py, ghostscan.py, mockingprobe.py "$VOL3\volatility3\framework\plugins\windows\malware\"
```
