# Changelog

All notable changes to `proxychains-win` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.2alpha] - 2026-09-07

### Added
- **Loopback Isolation & Localnet IPC Bypass (ADR-009):**
  - Inherent loopback bypass for `127.0.0.0/8`, IPv6 `::1`, `0.0.0.0`, and `localhost` hostnames, allowing tools like Kleopatra / Gpg4win to seamlessly interface with local daemons (`gpg-agent`, `dirmngr`, `scdaemon`) without proxy interception.
  - Complete `localnet` configuration parser supporting both netmask and CIDR formats (`localnet <ip> <netmask> [port]` and `localnet <ip>/<cidr> [port]`).
  - SEH-protected `addrinfo` free handler preventing memory faults during heterogeneous address deallocations.
  - Lazy provider initialization for `ConnectEx` on localnet connections.

## [0.5.1alpha] - 2026-09-07

### Original Build Features & Hardening based on proxychains-ng & proxychains-ng for Windows
- **Zero-Driver, Zero-Daemon Architecture:** Native Windows implementation using Microsoft Detours API hooking for direct in-process injection without kernel drivers, background services, named pipes, or unauthenticated IPC mechanisms.
- **In-Place Socket Tunneling:** Direct socket negotiation on the caller's original `SOCKET` handle, maintaining 100% compatibility with Windows I/O Completion Ports (IOCP) and asynchronous network runtimes.
- **Protocol Support:** Full support for SOCKS4, SOCKS5 (with username/password authentication), and HTTP CONNECT proxy protocols.
- **Chaining Modes:**
  - `strict_chain`: Chains traffic sequentially through all specified proxies in order.
  - `dynamic_chain`: Chains traffic skipping unresponsive proxies while preserving order.
  - `random_chain`: Connects through randomly selected proxies.
  - `round_robin_chain`: Rotates evenly across proxy nodes on each connection.
- **Zero External DNS Leaks by Default:**
  - Complete DNS leak prevention using synthetic IPv4 addresses from the RFC 6890 benchmark subnet (`198.18.0.0/15`).
  - Thread-safe domain mapping guarded by Windows Slim Reader/Writer (SRW) locks.
  - Domain names (including `.onion` hidden services) are securely passed to remote proxies via SOCKS5 domain name addressing (`0x03`) for resolution at the proxy/Tor exit node.
  - Direct nameserver lookups are disabled by default with prominent security warnings against local DNS leakage.
- **Win32 & Asynchronous DNS Interception:** Hooks `GetAddrInfoW`, `GetAddrInfoExW`, `getaddrinfo`, and `gethostbyname` across modern Windows network stacks.
- **Winsock Extension Hooking:** Runtime interception of `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER)` to hook `ConnectEx`, preventing socket leaks in modern runtimes such as `curl` (with Schannel), Go, and Rust (Tokio).
- **Dual-Bitness & Process Tree Propagation:**
  - 64-bit (`proxychains64.dll`) and 32-bit (`proxychains32.dll`) hook libraries.
  - Automatic PE architecture detection (`IMAGE_FILE_MACHINE_AMD64` vs `IMAGE_FILE_MACHINE_I386`) on `CreateProcessW` and `CreateProcessA` to tunnel mixed-architecture child process trees.
- **Hybrid User-Agent Privacy Strategy (ADR-008):**
  - Canonical Tor Browser User-Agent (`Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0`) enforced strictly for all Tor connections (`127.0.0.1:9050` / `9150`) to prevent mask-mismatch fingerprinting.
  - Curated, non-randomized modern browser pool for non-Tor HTTP proxy chains.
  - Complete removal of identifiable legacy client signatures.
- **Ergonomic CLI Launcher:**
  - Dual launcher binaries: `proxychains-win.exe` and `proxychains.exe`.
  - Supports `-q` / `--quiet` mode, `-f <config>` custom configuration, `-v` / `--version`, and `-h` / `--help`.
  - Multi-tier configuration search (`-f`, `PROXYCHAINS_CONF_FILE`, local directory, executable directory, `%APPDATA%`, `%USERPROFILE%`).
- **Automated Packaging Pipeline:** PowerShell script (`scripts/package.ps1`) automating dual-architecture compilation, full test execution, artifact staging, and SHA256 release checksum generation.
