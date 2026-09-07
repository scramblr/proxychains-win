# ADR-007: Zero External DNS by Default and Tor SOCKS5 Remote Resolution

## Status
Accepted (Supersedes ADR-005)

## Date
2026-09-07

## Context
In ADR-005, an exemption was temporarily evaluated to bypass fake-IP generation and query resolvers directly over the network to allow wire-level packet inspection.

However, operational testing revealed a critical vulnerability inherent to Windows DNS architecture:
1. When Winsock DNS functions (`GetAddrInfoW`, `getaddrinfo`) are invoked without synthetic interception, Windows delegates DNS resolution to the Windows DNS Client service (`dnscache`).
2. The `dnscache` service issues UDP/TCP port 53 queries to the network adapter's default resolvers, regardless of application-level intent.
3. This creates a severe DNS leak, exposing target hostnames in plaintext to external network observers and violating the core security premise of `proxychains`.

In upstream `proxychains-ng`, DNS resolution is leak-free by design: every hostname (both clearnet and `.onion`) is mapped locally to a synthetic fake IPv4 address (RFC 6890 benchmark subnet `198.18.0.0/15`). When the target application subsequently connects to that synthetic IP, `proxychains` intercepts the connection, extracts the original hostname, and delegates DNS resolution to the remote proxy using SOCKS5 domain name addressing (`0x03`). When using Tor (`socks5 127.0.0.1 9050`), DNS resolution is executed exclusively by the Tor exit node across the encrypted circuit.

## Decision
1. **Zero External DNS by Default:** proxychains-win shall NEVER query an external nameserver by default. All domain names (including clearnet domains and `.onion` hidden services) are intercepted at the Winsock API layer (`GetAddrInfoW`, `GetAddrInfoExW`, `getaddrinfo`, `gethostbyname`) and allocated a synthetic IPv4 address from `198.18.0.0/15`.
2. **Tor Remote Resolution via SOCKS5:** When the application calls `connect()` on a synthetic IP, the tunneling engine extracts the domain name and passes it via SOCKS5 address type `0x03` to the Tor daemon (`127.0.0.1:9050`). Resolution happens remotely at the Tor exit node. Zero DNS packets are emitted onto the local network adapter.
3. **Strict Prohibition of Hardcoded/Default Nameservers:** No public or well-known nameservers (such as 4.2.2.2, 1.1.1.1, 8.8.8.8, 9.9.9.9, etc.) shall ever be hardcoded into the application or populated in default configuration files.
4. **Explicit Opt-In Nameserver with Critical Security Warning:** Direct DNS resolution via an external nameserver is only permitted if the operator explicitly configures a `nameserver <ip>` directive in `proxychains.conf`. The configuration template must include the prominent warning:
   `WARNING: USING AN EXTERNAL NAMESERVER DEFEATS THE ENTIRE PURPOSE OF USING A SECURE SYSTEM LIKE TOR OR PROXIES DUE TO INTERCEPTION RISKS.`

## Consequences
- **Zero DNS Leaks:** 100% of DNS lookups for tunneled applications are encrypted and resolved remotely via Tor or the proxy chain.
- **Full Tor Compatibility:** Both clearnet domains and `.onion` domains are seamlessly handled by Tor exit/rendezvous points.
- **Safety by Default:** No default resolver or system adapter DNS servers are ever queried by proxychains-win.
