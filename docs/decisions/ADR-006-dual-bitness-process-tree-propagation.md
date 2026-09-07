# ADR-006: Dual-Bitness Process Tree Propagation via Detours PE Header Inspection

## Status
Accepted

## Date
2026-09-07

## Context
Windows environments frequently execute mixed-bitness process trees. For example:
- A 64-bit shell (`cmd.exe` or `powershell.exe`) may invoke a 32-bit build tool, legacy compiler, or 32-bit Git / Python binary.
- A 32-bit application may launch a 64-bit helper utility.

In Windows, a 64-bit DLL (`proxychains64.dll`) cannot be injected into a 32-bit process, and a 32-bit DLL (`proxychains32.dll`) cannot be injected into a 64-bit process. If an injected process spawns a child of differing bitness without detecting the architecture, injection fails, causing:
1. Process launch failure (`ERROR_BAD_EXE_FORMAT` / `0xC000007B`), or
2. The child process launches in the clear without any proxying or DNS hooking, leaking all network traffic.

## Decision
1. **Dual Hook Libraries**: Build both 64-bit (`proxychains64.dll`) and 32-bit (`proxychains32.dll`) hook libraries in the same distribution directory.
2. **Hook `CreateProcessW` and `CreateProcessA`**: Intercept all child process creations within hooked processes.
3. **PE Header Inspection (`pxc_detect_pe_arch`)**:
   - Parse the target binary's `IMAGE_DOS_HEADER` (`e_magic == 'MZ'`).
   - Follow `e_lfanew` to `IMAGE_NT_HEADERS` (`Signature == 'PE\0\0'`).
   - Read `IMAGE_FILE_HEADER.Machine`:
     - `IMAGE_FILE_MACHINE_AMD64` (0x8664) -> 64-bit binary. Select `proxychains64.dll`.
     - `IMAGE_FILE_MACHINE_I386` (0x014c) -> 32-bit binary. Select `proxychains32.dll`.
     - Fallback / Unknown -> Default to host process architecture.
4. **Detours Process Creation**:
   - Inject the selected architecture-matching DLL using `DetourCreateProcessWithDllsW` / `DetourCreateProcessWithDllsA`.
5. **Cross-Bitness Helper Export**:
   - Export `DetourFinishHelperProcess` at ordinal 1 (`@1`) in both DLLs to support Microsoft Detours' native `rundll32` helper mechanism for cross-bitness process updates.
   - Handle 32-bit x86 `__stdcall` name decoration (`_DetourFinishHelperProcess@16`) via conditional linker pragma:
     ```c
     #if defined(_WIN64)
     #pragma comment(linker, "/export:DetourFinishHelperProcess,@1")
     #else
     #pragma comment(linker, "/export:DetourFinishHelperProcess=_DetourFinishHelperProcess@16,@1")
     #endif
     ```

## Alternatives Considered

### Global Windows AppInit_DLLs
- Pros: System-wide injection into all processes.
- Cons: Deprecated since Windows 8 with Secure Boot; requires registry modification; taints unrelated system processes; high risk of system instability.
- Rejected: Violates the self-contained, unprivileged CLI requirement.

### Windows API Shim Engine / SDB
- Pros: Supported by Microsoft Application Compatibility framework.
- Cons: Complex installation; requires administrator privileges; not portable.
- Rejected: Heavyweight and non-portable.

### Background Daemon with Process Monitors
- Pros: Daemon can detect new processes and inject DLLs via `CreateRemoteThread`.
- Cons: Subject to race conditions (process connects before injection completes); requires inter-process communication; vulnerable to coordinator hijacking.
- Rejected: In-process interception via hooked `CreateProcessW` guarantees atomic injection before the child process executes a single instruction.

## Consequences
- Seamless, recursive propagation through arbitrarily nested process hierarchies (e.g. `cmd.exe` -> `git.exe` -> `ssh.exe` -> `curl.exe`).
- Zero configuration required from the user regardless of whether child processes are 32-bit or 64-bit.
- If injection fails or a non-PE script is executed, the hook falls back gracefully to `true_CreateProcessW` to prevent crashing the caller.
