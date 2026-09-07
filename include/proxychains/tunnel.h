#ifndef PROXYCHAINS_TUNNEL_H
#define PROXYCHAINS_TUNNEL_H

#include "proxychains/common.h"
#include "proxychains/config.h"
#include "proxychains/protocol.h"

typedef enum {
    PXC_TUNNEL_SUCCESS = 0,
    PXC_TUNNEL_BYPASS,
    PXC_TUNNEL_CONFIG_EMPTY,
    PXC_TUNNEL_ALL_PROXIES_DOWN,
    PXC_TUNNEL_HANDSHAKE_FAILED,
    PXC_TUNNEL_SOCKET_ERROR
} pxc_tunnel_status_t;

typedef bool (*pxc_fake_ip_resolver_fn)(struct in_addr ip, char *out_domain, size_t max_len);

void pxc_tunnel_set_fake_ip_resolver(pxc_fake_ip_resolver_fn fn);

// Check if an endpoint matches localnet rules and should bypass proxying
bool pxc_is_localnet(const pxc_config_t *config, const pxc_endpoint_t *target);

// Resolve proxy host string (IP or hostname) to sockaddr
bool pxc_resolve_proxy(const char *host, uint16_t port, struct sockaddr_storage *out_addr, int *out_addrlen);

// Establish proxy chain in-place on caller's original socket
pxc_tunnel_status_t pxc_establish_chain(SOCKET sock, const pxc_config_t *config, const pxc_endpoint_t *target);

// Status string helper
const char *pxc_tunnel_status_to_string(pxc_tunnel_status_t status);

#endif // PROXYCHAINS_TUNNEL_H
