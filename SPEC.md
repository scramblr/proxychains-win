# SPEC.md: Hardened Native Windows Implementation of proxychains-win

## 1. Objective & Target Users
Build a standalone, security-hardened, zero-driver native Windows realization (`proxychains-win`), inspired by the design and behavior of `proxychains-ng`. It allows unprivileged users to force TCP traffic from any command-line application through SOCKS4, SOCKS5, or HTTP CONNECT proxy chains using Windows-native API hooking (Microsoft Detours) instead of Linux `LD_PRELOAD`.

## 2. CLI Interface & Commands
```powershell
proxychains-win.exe [-q] [-f <config_file>] <target_executable> [arguments...]
```
Exit Codes:
- `0`: Success (or returns the exit code of the target application).
- `1`: Configuration parsing error or file not found.
- `2`: Target process creation / injection failure.

## 3. Project Structure
```
C:\Users\user\github\gemini\
├── CMakeLists.txt                # Dual-bitness root CMake with MSVC security flags
├── cmake\
│   └── Dependencies.cmake        # Pinned Microsoft Detours FetchContent
├── include\
│   └── proxychains\
│       ├── common.h              # Common definitions, versioning, architecture macros
│       ├── config.h              # Bounded config schema & environment serializer
│       ├── fake_ip.h             # 198.18.0.0/15 synthetic IP table definitions
│       ├── hooks.h               # Winsock & Process creation hook signatures
│       └── protocol.h            # SOCKS4/5 & HTTP CONNECT tunneling state machine
├── src\
│   ├── cli\                      # proxychains.exe (CLI Launcher)
│   ├── common\                   # Shared config parsing and serialization
│   ├── core\                     # Protocol tunneling engine (adapted from core.c)
│   ├── dns\                      # Synthetic IP table guarded by SRWLOCK
│   └── hook\                     # proxychains64.dll & proxychains32.dll
└── tests\
    ├── CMakeLists.txt
    ├── test_config.cpp           # Bounded parser & fuzz test cases
    ├── test_fake_ip.cpp          # High-concurrency SRWLOCK unit tests
    └── test_protocol.cpp         # SOCKS4/5 and HTTP CONNECT mock handshakes
```

## 4. Code Style & Compiler Security Controls
- C11 for core modules, C++17 for tests and Detours wrappers.
- MSVC Hardening: `/W4 /WX`, `/GS` (stack canaries), `/guard:cf` (Control Flow Guard), `/DYNAMICBASE /HIGHENTROPYVA` (ASLR), `/NXCOMPAT` (DEP).

## 5. Testing Strategy & Quality Gates
1. Unit Tests: Parser bounds, multithreaded SRWLOCK fake IP table, protocol handshake framing.
2. Integration: End-to-end `curl.exe` through local mock SOCKS5 proxy.
3. Verification: Zero DNS leaks (no UDP 53 packets) and zero local IPC handles (no named pipes or loopback coordination ports).

## 6. Engineering Boundaries
- Always connect in-place on caller's original SOCKET handle (100% IOCP compatible).
- Always use `198.18.0.0/15` for fake DNS IPs.
- Intercept wide/async DNS (`GetAddrInfoW`, `GetAddrInfoExW`).
- Intercept `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER)` for `WSAID_CONNECTEX`.
- Directly inject child processes in `CreateProcessW` using existing `pi.hProcess`.
- Never create a background coordinator daemon, named pipe, or loopback TCP socket.
- Never use a socket handle-indirection table.
- Never call `exit()` or `ExitProcess()` from inside `proxychains_hook.dll`.
- Never load DLLs or config files from Current Working Directory (`.`).
