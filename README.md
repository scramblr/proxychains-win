# proxychains-win v0.5.1alpha

A security-hardened, zero-driver native Windows implementation built from the ground up and inspired by the design of proxychains-ng and security hardened using the most recent advancements from Tor Project guidance & Industry Standards. Forces TCP traffic from any command-line application through SOCKS4, SOCKS5, or HTTP CONNECT proxy chains using Windows-native API hooking (Microsoft Detours).

---

## Key Security & Architectural Features

- **Zero Coordinator Daemon:** No named pipes, loopback coordination ports, or unauthenticated IPC (eliminates vulnerabilities present in legacy tools like `proxinject` and `shunf4`).
- **In-Place Socket Tunneling:** Operates directly on the caller's original `SOCKET` handle, guaranteeing 100% compatibility with Windows I/O Completion Ports (IOCP) and async I/O.
- **Total DNS Leak Prevention:** Hooks modern Unicode and asynchronous DNS APIs (`GetAddrInfoW`, `GetAddrInfoExW`, `getaddrinfo`, `gethostbyname`) using synthetic IPs from the RFC 6890 benchmark subnet (`198.18.0.0/15`).
- **ConnectEx Interception:** Intercepts runtime Winsock extension functions via `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER)` to prevent traffic leaks in modern runtimes (curl with WinSSL/Schannel, Go, Rust Tokio).
- **Dual-Bitness & Child Process Tree Propagation:** Includes both 64-bit (`proxychains64.dll`) and 32-bit (`proxychains32.dll`) hook libraries with PE header inspection on `CreateProcessW` / `CreateProcessA` to seamlessly tunnel mixed-architecture process trees.
- **Zero External DNS Leaks & Tor Remote Resolution:** Emits zero DNS packets over local network adapters by default. Synthetic IPs (`198.18.0.0/15`) preserve target hostnames (both clearnet and `.onion`), which are tunneled via SOCKS5 domain name addressing (`0x03`) for remote resolution by the proxy (e.g. Tor exit nodes). An optional direct UDP nameserver can be configured with an explicit security warning.

---

## Quick Start & Build

### Prerequisites
- Visual Studio 2022 / 2026 with C/C++ Build Tools
- CMake 3.20+
- Git

### Build 64-bit Targets
```powershell
cmake -B build -A x64
cmake --build build --config Release
```

### Build 32-bit Targets (Win32 / WoW64)
```powershell
cmake -B build32 -A Win32
cmake --build build32 --config Release
```

### Run Full Test Matrix
```powershell
# 64-bit test suite (7/7 unit tests)
ctest --test-dir build -C Release --output-on-failure

# 32-bit test suite (7/7 unit tests)
ctest --test-dir build32 -C Release --output-on-failure
```

### Distribution Binaries
For unified deployment, place both hook DLLs alongside the launcher:
- `proxychains.exe` (CLI launcher)
- `proxychains64.dll` (64-bit hook engine)
- `proxychains32.dll` (32-bit hook engine)

### Automated Release Packaging
To build both 64-bit and 32-bit architectures, execute all test suites, and generate a release zip archive with SHA256 checksums:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\package.ps1 -Version "0.5.1alpha"
```

---

## Usage

```powershell
# Display help and usage information
.\build\bin\Release\proxychains.exe --help

# Display version and target architecture
.\build\bin\Release\proxychains.exe --version

# Basic execution (remote Tor DNS resolution + SOCKS5 tunneling)
.\build\bin\Release\proxychains.exe curl.exe -s -L https://check.torproject.org

# Tunneling to an official Tor hidden service (.onion)
.\build\bin\Release\proxychains.exe curl.exe -s http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/

# Quiet mode (suppresses proxychains-win banner and logging)
.\build\bin\Release\proxychains.exe -q curl.exe -s -L https://ip.urls.is/startpage
```

### CLI Command Options
| Option | Description |
| :--- | :--- |
| `-q`, `--quiet` | Quiet mode; suppresses banner and runtime logging |
| `-f <config>` | Path to a specific configuration file |
| `-h`, `--help` | Display command-line usage and options |
| `-v`, `--version` | Display version and architecture information |

---

## Configuration (`proxychains.conf`)

proxychains-win searches for configuration files in the following order:
1. File explicitly passed via `-f <config>`
2. Environment variable `PROXYCHAINS_CONF_FILE`
3. Current working directory: `.\proxychains.conf`
4. Directory of `proxychains.exe`: `<exe_dir>\proxychains.conf`
5. `%APPDATA%\proxychains\proxychains.conf`
6. `%USERPROFILE%\.proxychains\proxychains.conf`

### Configuration Format Example

```ini
# Chaining Mode: strict_chain, dynamic_chain, random_chain, or round_robin_chain
strict_chain

# Suppress banner and progress messages
# quiet_mode

# Timeouts in milliseconds
tcp_connect_time_out 8000
tcp_read_time_out 8000

# Subnet prefix for synthetic fake IP allocation (default: 198 for 198.18.0.0/15)
remote_dns_subnet 198

# Localnet bypass: IP ranges that bypass proxying entirely
# Format: localnet <network_ip> <netmask> [port]
localnet 127.0.0.0 255.0.0.0
localnet 10.0.0.0 255.0.0.0
localnet 192.168.0.0 255.255.0.0

# Proxy List
# Format: <type> <host> <port> [username] [password]
# Supported protocols: socks5, socks4, http
[ProxyList]
# Local Tor proxy
socks5  127.0.0.1  9050

# Upstream SOCKS5 proxy with authentication
# socks5  192.168.1.100  1080  alice  SecretPass123!

# Upstream HTTP CONNECT proxy
# http    proxy.corp.internal  8080
```

---

## Architecture Decision Records (ADRs)

Detailed architectural specifications, trade-offs, and security rationales are maintained in [`docs/decisions/`](docs/decisions/):

- [**ADR-001: Zero Coordinator Daemon and Direct Child Process Injection**](docs/decisions/ADR-001-zero-coordinator-daemon-direct-child-injection.md)
- [**ADR-002: In-Place Socket Tunneling on Caller's Socket Handle**](docs/decisions/ADR-002-in-place-socket-tunneling.md)
- [**ADR-003: Synthetic IP DNS Leak Prevention via 198.18.0.0/15**](docs/decisions/ADR-003-synthetic-ip-dns-leak-prevention.md)
- [**ADR-004: Winsock Extension Function Interception for ConnectEx**](docs/decisions/ADR-004-connectex-and-winsock-extension-interception.md)
- [**ADR-005: Real-Server DNS Exemption (Superseded by ADR-007)**](docs/decisions/ADR-005-real-server-dns-exemption-wire-verification.md)
- [**ADR-006: Dual-Bitness Process Tree Propagation via Detours PE Header Inspection**](docs/decisions/ADR-006-dual-bitness-process-tree-propagation.md)
- [**ADR-007: Zero External DNS by Default and Tor SOCKS5 Remote Resolution**](docs/decisions/ADR-007-zero-external-dns-default-tor-remote-resolution.md)
- [**ADR-008: User-Agent Privacy and Anti-Fingerprinting Policy (Hybrid Strategy)**](docs/decisions/ADR-008-user-agent-privacy-and-anti-fingerprinting-policy.md)
