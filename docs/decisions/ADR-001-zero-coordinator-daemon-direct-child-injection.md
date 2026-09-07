# ADR-001: Zero Coordinator Daemon and Direct Child Process Injection

## Status
Accepted

## Date
2026-09-07

## Context
Prior Windows proxychains implementations ("proxinject" and "shunf4/proxychains-windows") suffered from systemic local privilege escalation and remote code execution vulnerabilities:
1. `proxinject` introduced an unauthenticated local loopback TCP socket where any unprivileged process could claim to be the coordinator for an arbitrary PID and trigger DLL injection.
2. `shunf4/proxychains-windows` used a local Named Pipe with a DACL granting full access to "Everyone", self-declared PIDs, and an unauthenticated stack buffer overflow in the privileged coordinator daemon.

Both tools introduced this cross-process IPC channel solely because they lacked a mechanism to propagate DLL injection to child processes (e.g. when `git.exe` spawns `ssh.exe`) without asking a central background daemon to inject the child.

On Linux, `proxychains-ng` has NO background coordinator daemon; dynamic linker interposition (`LD_PRELOAD`) is automatically preserved across `execve()` calls.

## Decision
Completely eliminate the background coordinator daemon, all named pipes, and all loopback TCP coordination sockets.
1. The CLI launcher (`proxychains.exe`) performs initial configuration validation and launches the root target process suspended with Microsoft Detours Import Address Table (IAT) injection (`DetourCreateProcessWithDllEx`).
2. Inside `proxychains_hook.dll`, hook `CreateProcessW` and `CreateProcessA`.
3. When the host process creates a child, the parent process already possesses full rights to the child (`PROCESS_INFORMATION::hProcess`). The hook directly injects the child with `DetourCreateProcessWithDllsW` before resuming execution.

## Alternatives Considered

### Authenticated Named Pipe Daemon with Strict DACLs
- Pros: Centralized logging of all proxied processes across the system.
- Cons: Introduces local attack surface (IPC deserialization, squatting, privilege boundaries). Unnecessary complexity for a per-process CLI tool.
- Rejected: Eliminating the channel entirely is strictly superior to hardening an unnecessary channel.

### Loopback TCP Socket with Pre-Shared Cryptographic Tokens
- Pros: Simple cross-platform socket code.
- Cons: Windows firewall popups, port collision issues, and local socket exhaustion.
- Rejected: Unacceptable user experience and security posture.

## Consequences
- **Zero Local Attack Surface:** No open ports, no named pipes, no kernel object squatting, and no IPC deserialization parser bugs.
- **Fail-Closed Security:** Child process injection occurs synchronously before the child's main thread executes; no race condition where traffic can escape before hooks attach.
