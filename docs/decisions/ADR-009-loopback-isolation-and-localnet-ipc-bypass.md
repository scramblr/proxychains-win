# ADR-009: Loopback Isolation and Localnet IPC Bypass

## Status
Accepted

## Date
2026-09-07

## Context
Desktop applications and security suites on Windows (such as Kleopatra / Gpg4win, local developer toolchains, and database management utilities) rely heavily on inter-process communication (IPC) over the loopback network interface. Specifically, Kleopatra coordinates with backend daemons (`gpg-agent.exe`, `dirmngr.exe`, `scdaemon.exe`) by binding to dynamic ports on `127.0.0.1` and establishing local TCP connections.

In proxychains architectures:
1. Routing loopback traffic (`127.0.0.0/8`, `::1`, `localhost`) through an upstream proxy chain or Tor is structurally invalid: external proxies and Tor exit nodes cannot and will not route to the client's internal loopback services (Tor exit policies reject `127.0.0.0/8` by default).
2. Intercepting loopback calls and forwarding them to the proxy causes local IPC handshakes to fail immediately with `WSAECONNREFUSED`.
3. Desktop applications may query `localhost`, `127.0.0.1`, or emulated socket endpoints, requiring seamless local passthrough without synthetic IP allocation or remote tunneling.

## Decision
1. **Inherent Loopback Bypass:**
   - The tunneling engine (`pxc_is_localnet`) inherently treats the entire IPv4 loopback block (`127.0.0.0/8` per RFC 1122 and RFC 5735), IPv6 loopback (`::1`), `0.0.0.0` (`INADDR_ANY`), and hostnames `localhost`, `localhost.`, and `localhost.localdomain` as localnet.
   - Any connection attempt directed to loopback addresses immediately bypasses proxy chaining and invokes native Winsock `connect()`, `WSAConnect()`, or `ConnectEx()` directly.
2. **Robust `localnet` Directive Parser:**
   - The configuration parser supports both netmask notation (`localnet <ip> <netmask> [port]`) and CIDR notation (`localnet <ip>/<cidr> [port]`) across up to `PXC_MAX_LOCALNET` entries.
   - Localnet table entries are serialized across process boundaries to ensure child processes spawned by injected parents inherit all bypass rules.
3. **Loopback DNS Passthrough:**
   - `GetAddrInfoW`, `GetAddrInfoExW`, `getaddrinfo`, and `gethostbyname` bypass synthetic IP allocation for `localhost` variants and direct IP literals, returning system `addrinfo` directly.
   - Free handlers implement structured exception handling (`__try ... __except`) to safeguard memory deallocation across heterogeneous system and synthetic descriptors.
4. **ConnectEx Lazy Provider Initialization:**
   - Injected `ConnectEx` extension interception lazily loads the underlying Microsoft provider pointer if invoked for localnet connections prior to explicit `WSAIoctl` queries.

## Consequences
- **Kleopatra & GnuPG Compatibility:** Seamless operation of Gpg4win, Kleopatra, and associated backend daemons over local loopback sockets.
- **Zero Configuration Burden:** Operators do not need to manually configure `localnet 127.0.0.0 255.0.0.0` to preserve local IPC, while custom subnets (e.g. `10.0.0.0/8`, `192.168.0.0/16`) remain fully configurable.
- **Anonymity Preserved:** Outbound non-loopback TCP connections and clearnet/.onion hostnames continue to be strictly tunneled through the proxy chain without external DNS leaks.
