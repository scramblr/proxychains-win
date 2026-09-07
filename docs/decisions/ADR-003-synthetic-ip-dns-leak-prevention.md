# ADR-003: Synthetic IP DNS Leak Prevention via 198.18.0.0/15 & Wide DNS Hooking

## Status
Accepted

## Date
2026-09-07

## Context
`proxychains-ng` intercepts DNS lookups and returns synthetic IP addresses from the `224.0.0.0/4` subnet, saving the domain mapping in an internal table. When the app connects to the synthetic IP, proxychains retrieves the domain and instructs the SOCKS5 proxy to resolve DNS remotely.

On Windows, this design has two fatal issues:
1. `224.0.0.0/4` is Class D Multicast. Winsock and Windows TCP stack explicitly reject calling `connect()` on multicast IPs with `WSAEADDRNOTAVAIL` or `WSAEINVAL`.
2. Modern Windows applications call wide-character and asynchronous DNS APIs (`GetAddrInfoW`, `GetAddrInfoExW`), completely bypassing ANSI `getaddrinfo` hooks and leaking DNS queries to the local network.

## Decision
1. Allocate synthetic IPs exclusively from **`198.18.0.0/15`** (RFC 6890 benchmark testing subnet), which is treated as standard unicast routable space by the Windows network stack.
2. Intercept **`GetAddrInfoW`**, **`GetAddrInfoExW`**, **`getaddrinfo`**, and **`gethostbyname`**.
3. Implement the internal domain-to-IP lookup table as a thread-safe in-memory hash table guarded by a Windows **`SRWLOCK`** (`AcquireSRWLockShared` for reads, `AcquireSRWLockExclusive` for writes).

## Alternatives Considered

### Linux Anonymous Pipe Allocator (`allocator_thread.c`)
- Pros: Direct adaptation of `proxychains-ng` design.
- Cons: Designed solely to prevent `fork()` heap lock deadlocks on Linux. On Windows, Windows has no `fork()`; anonymous pipes waste handles and add unnecessary IPC overhead.
- Rejected: Replaced with native `SRWLOCK`.

### Loopback Subnet (`127.0.0.0/8`)
- Pros: Unicast routable.
- Cons: High risk of colliding with local development servers, databases, and Docker bindings on `127.0.0.1:port`.
- Rejected: `198.18.0.0/15` is dedicated test/benchmark space with zero risk of local collision.

## Consequences
- Complete elimination of local DNS leaks across modern Windows applications.
- High-concurrency multithreaded DNS resolution with near-zero lock contention.
