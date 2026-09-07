# ADR-005: Real-Server DNS Exemption and Wire-Visible Resolver Verification

## Status
Superseded by ADR-007

## Date
2026-09-07

## Context
*(Note: This architectural approach has been SUPERSEDED by ADR-007 due to DNS leak risks inherent in delegating lookups to the Windows resolver).*

In this earlier iteration, an exemption was evaluated to bypass fake-IP generation for designated external test domains and query network resolvers directly to allow wire-level packet inspection.

However, operational testing revealed that delegating lookups to Windows DNS Client (`dnscache`) forces queries over the host's default adapter resolvers, creating a critical DNS leak and breaking anonymity.

## Decision
*(Superseded by ADR-007: All domains now resolve via synthetic fake IPs and Tor SOCKS5 remote resolution).*

## Alternatives Considered

### Global DNS Hook Toggle Flag
- Pros: Simple boolean switch to turn off all DNS hooking.
- Cons: Completely disables DNS leak protection for every domain, risking unintentional leakage of private endpoints during verification.
- Rejected: Targeted domain exemption allows precise verification of specific endpoints without compromising the security boundary of other domains.

### Proxy-Level DNS Tunneling (Tor DNSPort)
- Pros: Sends DNS requests through Tor's local DNSPort (UDP 5300).
- Cons: Requires configuring custom DNS redirection in Windows, which requires administrative rights and driver-level packet filtering.
- Rejected: Violates the zero-driver, zero-admin constraint.
## Consequences
- This approach has been replaced by ADR-007, which enforces 100% remote SOCKS5 DNS resolution via synthetic IPs without emitting external DNS queries.
