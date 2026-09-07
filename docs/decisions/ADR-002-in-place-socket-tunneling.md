# ADR-002: In-Place Socket Tunneling on Caller's Socket Handle

## Status
Accepted

## Date
2026-09-07

## Context
In `proxychains-ng` on Linux, `connect_proxy_chain()` creates a new temporary socket (`ns = socket(...)`), connects and negotiates the proxy chain across `ns`, and then executes `dup2(ns, sock)` to replace the caller's socket descriptor with the tunneled socket.

Windows Winsock has **no equivalent of `dup2()` for `SOCKET` handles**. A `SOCKET` is a kernel handle backed by `\Device\Afd`.

An alternative considered was maintaining an in-memory "Handle Indirection Table" mapping the fake socket handle to the real tunneled socket handle.

## Decision
Reject the Handle Indirection Table. Connect and tunnel **directly in-place on the caller's original `SOCKET` handle**.

1. In the `connect()` / `WSAConnect()` hook, call `true_connect(sock, first_proxy_addr)`.
2. Execute the SOCKS4, SOCKS5, or HTTP CONNECT handshake directly over `sock`.
3. Leave the data plane completely unhooked.

## Alternatives Considered

### Handle Indirection Table
- Pros: Allows retrying subsequent proxies on a dead socket in dynamic chaining mode.
- Cons:
  1. **Fatal IOCP Incompatibility:** Modern Windows runtimes (Chromium, Node.js, Go, Rust Tokio, .NET, Python asyncio) bind `sock` to an I/O Completion Port (`CreateIoCompletionPort`). If `sock` is replaced behind the scenes, async overlapped I/O fails or hangs forever because the new socket is not bound to the completion port.
  2. **Massive Hook Footprint:** Requires hooking `send`, `recv`, `WSASend`, `WSARecv`, `select`, `WSAPoll`, `WSAEventSelect`, `closesocket`, and `ioctlsocket`, rewriting `fd_set` arrays on every single I/O call.
  3. **Handle Recycling Races:** Windows aggressively recycles handle values, causing severe ABA race conditions in multithreaded applications.
- Rejected: Broken on modern Windows runtimes and adds unacceptable latency to data transfer.

## Consequences
- **100% IOCP Compatibility:** Asynchronous overlapped I/O works natively without interference.
- **Zero Data-Plane Overhead:** Data transfer runs at full native kernel speed; no hooked `send` or `recv`.
- **Pre-Configured Options Preserved:** Socket options set by the caller before `connect()` (`TCP_NODELAY`, buffers) remain intact.
- **Trade-off:** In `dynamic_chain` mode, if the first proxy in the list fails to connect, Winsock does not allow reusing a failed stream socket for another connection attempt. It returns a connection error immediately.
