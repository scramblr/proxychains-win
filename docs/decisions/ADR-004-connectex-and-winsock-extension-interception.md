# ADR-004: Winsock Extension Function Interception for ConnectEx

## Status
Accepted

## Date
2026-09-07

## Context
High-performance Windows software (e.g. `curl.exe` compiled with Schannel/WinSSL, Go binaries, Rust Mio/Tokio runtimes) frequently does not call `connect()` or `WSAConnect()`. Instead, they query the Microsoft Winsock extension provider table at runtime for `ConnectEx`:
```c
WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER, &WSAID_CONNECTEX, ...);
```
Standard Winsock hooking engines that only intercept `ws2_32!connect` fail to catch `ConnectEx` calls, allowing traffic to bypass the proxy chain entirely and connect directly to the destination in cleartext.

## Decision
Hook `ws2_32!WSAIoctl`. When control code `SIO_GET_EXTENSION_FUNCTION_POINTER` is requested with GUID `WSAID_CONNECTEX`:
1. Save the underlying true `ConnectEx` pointer.
2. Return a pointer to our hooked `HookedConnectEx` wrapper.
3. The wrapper connects the socket through the proxy chain in-place, sends any initial buffer data (`lpSendBuffer`), and signals the `LPOVERLAPPED` event / completion port.

## Consequences
- Eliminates traffic leakage from modern async Windows runtimes.
- Transparent support for `curl`, Go, and Rust CLI utilities on Windows.
