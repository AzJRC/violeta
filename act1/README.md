# Shellcode Loader via MSBuild-Compatible C# Application

## Overview

This C# program is a minimalist shellcode loader designed to be executed using `MSBuild.exe` as part of a **Living Off the Land Binary (LOLBin)** execution technique. The application allocates executable memory, decrypts shellcode from an external file, and executes the malicious payload within the same process via a new thread. This is particularly useful in scenarios that involve bypassing Microsoft Windows Defender through memory-only execution and native API calls.

This tool was developed for **red teaming** and **defensive testing** purposes, and MUST only be used in controlled environments with explicit authorization.

## Key Features

- Shellcode is loaded from an external binary file (`config.bin`) to avoid hardcoded payloads.
- The payload is **XOR-obfuscated** to evade basic static detection mechanisms.
- Direct use of **Windows API calls** through P/Invoke and unmanaged function pointers.
- Compatible with **MSBuild LOLBin** execution, making it suitable for evasion and offensive simulation.

---

## Execution Workflow

1. **Shellcode Loading**
   - Reads the shellcode from an external file (`config.bin`) using `File.ReadAllBytes`.
   - This binary MUST be previously XOR-obfuscated using the same key defined in the program (`0xAA`).

2. **Decryption**
   - The shellcode is decrypted via a simple XOR routine using a hardcoded key (`0xAA`).
   - The decrypted payload is assumed to be position-independent shellcode.

3. **Memory Allocation**
   - The program dynamically loads `ntdll.dll` and resolves the address of `NtAllocateVirtualMemory`.
   - Allocates memory in the current process using `NtAllocateVirtualMemory` with `MEM_COMMIT | MEM_RESERVE` and `PAGE_EXECUTE_READWRITE` flags.

4. **Shellcode Injection**
   - The decrypted shellcode is copied into the allocated memory using `Marshal.Copy`.

5. **Thread Creation**
   - `CreateThread` from `kernel32.dll` is dynamically resolved and used to create a thread that starts execution at the base address of the shellcode.
   - Execution is synchronized using `WaitForSingleObject`.

---

## Requirements

- **.NET Framework or .NET Core** compatible environment
- Compiled binary named according to MSBuild project expectations (if using LOLBin evasion)
- A valid, XOR-obfuscated shellcode payload in `config.bin`
- Administrative privileges MAY be required depending on the shellcode behavior

---

## Program Structure

| Function | Purpose |
|---------|---------|
| `Main()` | Orchestrates the entire loading and execution flow |
| `LoadShellcode(string filePath)` | Loads encrypted shellcode from a local file |
| `DeXOR(byte[] data, byte key)` | Decrypts the loaded shellcode using XOR |
| `NtAllocateVirtualMemoryDelegate` | Delegate to call the native `NtAllocateVirtualMemory` function |
| `CreateThreadDelegate` | Delegate to call the native `CreateThread` function |

---

## Security and Ethical Notice

> This tool MUST only be used in ethical, legal, and authorized scenarios such as red team simulations, penetration testing with permission, or defensive research. Unauthorized use of this software to execute shellcode or evade endpoint protection mechanisms on systems you do not own or have explicit permission to test is strictly prohibited.

---

## MITRE ATT&CK Mappings

| Technique | Description |
|----------|-------------|
| **T1127.001 - Signed Binary Proxy Execution: MSBuild** | Execution of arbitrary code via MSBuild projects |
| **T1055.012 - Process Injection: Shellcode Injection** | Writing and executing shellcode in the address space of a process |
| **T1027 - Obfuscated Files or Information** | Use of XOR-obfuscated shellcode |
| **T1562.001 - Impair Defenses: Disable or Modify Tools** | Bypassing Defender through native API calls and memory-only payloads |
| **TA0002 - Execution** | Achieving code execution via LOLBin |
| **TA0005 - Defense Evasion** | Avoiding detection via obfuscation and in-memory execution |
| **TA0011 - Command and Control** | Reverse shell interaction post-execution via payload (not handled by this script) |

---

## Disclaimer

This program is provided **as-is** for educational and authorized security research purposes only. The authors and contributors are not responsible for any misuse or damage caused by this tool.

---
