#include "proxychains/tunnel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pxc_fake_ip_resolver_fn g_fake_ip_resolver = NULL;
static volatile LONG g_round_robin_counter = 0;

void pxc_tunnel_set_fake_ip_resolver(pxc_fake_ip_resolver_fn fn) {
    g_fake_ip_resolver = fn;
}

const char *pxc_tunnel_status_to_string(pxc_tunnel_status_t status) {
    switch (status) {
        case PXC_TUNNEL_SUCCESS:           return "Tunnel Established";
        case PXC_TUNNEL_BYPASS:            return "Localnet Bypass";
        case PXC_TUNNEL_CONFIG_EMPTY:      return "No Proxies Configured";
        case PXC_TUNNEL_ALL_PROXIES_DOWN:  return "All Proxies Down";
        case PXC_TUNNEL_HANDSHAKE_FAILED:  return "Proxy Handshake Failed";
        case PXC_TUNNEL_SOCKET_ERROR:      return "Socket Error";
        default:                           return "Unknown Tunnel Status";
    }
}

bool pxc_is_localnet(const pxc_config_t *config, const pxc_endpoint_t *target) {
    if (!config || !target) return false;

    struct in_addr target_ip = { 0 };
    bool has_v4 = false;

    if (target->type == PXC_ADDR_IPV4) {
        target_ip = target->addr.ipv4;
        has_v4 = true;
    } else if (target->type == PXC_ADDR_DOMAIN && strcmp(target->addr.domain, "localhost") == 0) {
        target_ip.s_addr = htonl(INADDR_LOOPBACK);
        has_v4 = true;
    }

    if (has_v4) {
        for (uint32_t i = 0; i < config->localnet_count; i++) {
            const pxc_localnet_entry_t *ln = &config->localnets[i];
            if ((target_ip.s_addr & ln->netmask.s_addr) == (ln->network.s_addr & ln->netmask.s_addr)) {
                if (ln->port == 0 || ln->port == target->port) {
                    return true;
                }
            }
        }
    }

    return false;
}

bool pxc_resolve_proxy(const char *host, uint16_t port, struct sockaddr_storage *out_addr, int *out_addrlen) {
    if (!host || !out_addr || !out_addrlen) return false;

    memset(out_addr, 0, sizeof(*out_addr));

    struct sockaddr_in *sin = (struct sockaddr_in *)out_addr;
    if (inet_pton(AF_INET, host, &sin->sin_addr) == 1) {
        sin->sin_family = AF_INET;
        sin->sin_port = htons(port);
        *out_addrlen = sizeof(struct sockaddr_in);
        return true;
    }

    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out_addr;
    if (inet_pton(AF_INET6, host, &sin6->sin6_addr) == 1) {
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(port);
        *out_addrlen = sizeof(struct sockaddr_in6);
        return true;
    }

    struct addrinfo hints;
    struct addrinfo *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, NULL, &hints, &res) == 0 && res != NULL) {
        if (res->ai_family == AF_INET) {
            memcpy(sin, res->ai_addr, sizeof(struct sockaddr_in));
            sin->sin_port = htons(port);
            *out_addrlen = sizeof(struct sockaddr_in);
        } else if (res->ai_family == AF_INET6) {
            memcpy(sin6, res->ai_addr, sizeof(struct sockaddr_in6));
            sin6->sin6_port = htons(port);
            *out_addrlen = sizeof(struct sockaddr_in6);
        } else {
            freeaddrinfo(res);
            return false;
        }
        freeaddrinfo(res);
        return true;
    }

    return false;
}

static void endpoint_from_proxy(pxc_endpoint_t *ep, const pxc_proxy_entry_t *proxy) {
    memset(ep, 0, sizeof(*ep));
    struct in_addr v4;
    if (inet_pton(AF_INET, proxy->host, &v4) == 1) {
        pxc_endpoint_from_ipv4(ep, v4, proxy->port);
        return;
    }

    struct in6_addr v6;
    if (inet_pton(AF_INET6, proxy->host, &v6) == 1) {
        pxc_endpoint_from_ipv6(ep, &v6, proxy->port);
        return;
    }

    pxc_endpoint_from_domain(ep, proxy->host, proxy->port);
}

static pxc_tunnel_status_t establish_strict(SOCKET sock, const pxc_config_t *config, const pxc_endpoint_t *target) {
    struct sockaddr_storage first_addr;
    int first_addrlen = 0;

    if (!pxc_resolve_proxy(config->proxies[0].host, config->proxies[0].port, &first_addr, &first_addrlen)) {
        return PXC_TUNNEL_ALL_PROXIES_DOWN;
    }

    if (!config->quiet_mode) {
        fprintf(stderr, "[proxychains-win] Strict chain ... %s:%u ", config->proxies[0].host, (unsigned int)config->proxies[0].port);
        fflush(stderr);
    }

    pxc_status_t st = pxc_timed_connect(sock, (struct sockaddr *)&first_addr, first_addrlen, config->tcp_connect_timeout_ms);
    if (st != PXC_STATUS_SUCCESS) {
        if (!config->quiet_mode) {
            fprintf(stderr, "<-- timeout or connection refused\n");
            fflush(stderr);
        }
        return PXC_TUNNEL_ALL_PROXIES_DOWN;
    }

    for (uint32_t i = 0; i < config->proxy_count - 1; i++) {
        pxc_endpoint_t next_ep;
        endpoint_from_proxy(&next_ep, &config->proxies[i + 1]);

        if (!config->quiet_mode) {
            fprintf(stderr, "... %s:%u ", config->proxies[i + 1].host, (unsigned int)config->proxies[i + 1].port);
            fflush(stderr);
        }

        st = pxc_proxy_handshake(sock, config->proxies[i].protocol, &next_ep,
                                config->proxies[i].username, config->proxies[i].password,
                                pxc_config_get_effective_ua(config),
                                config->tcp_read_timeout_ms);
        if (st != PXC_STATUS_SUCCESS) {
            if (!config->quiet_mode) {
                fprintf(stderr, "<-- handshake failed (%s)\n", pxc_status_to_string(st));
                fflush(stderr);
            }
            return PXC_TUNNEL_HANDSHAKE_FAILED;
        }
    }

    char target_str[256];
    pxc_endpoint_to_string(target, target_str, sizeof(target_str));

    if (!config->quiet_mode) {
        fprintf(stderr, "... %s ", target_str);
        fflush(stderr);
    }

    const pxc_proxy_entry_t *last_proxy = &config->proxies[config->proxy_count - 1];
    st = pxc_proxy_handshake(sock, last_proxy->protocol, target,
                            last_proxy->username, last_proxy->password,
                            pxc_config_get_effective_ua(config),
                            config->tcp_read_timeout_ms);
    if (st != PXC_STATUS_SUCCESS) {
        if (!config->quiet_mode) {
            fprintf(stderr, "<-- denied (%s)\n", pxc_status_to_string(st));
            fflush(stderr);
        }
        return PXC_TUNNEL_HANDSHAKE_FAILED;
    }

    if (!config->quiet_mode) {
        fprintf(stderr, "... OK\n");
        fflush(stderr);
    }

    return PXC_TUNNEL_SUCCESS;
}

static pxc_tunnel_status_t establish_dynamic(SOCKET sock, const pxc_config_t *config, const pxc_endpoint_t *target) {
    uint32_t first_idx = PXC_MAX_PROXIES;
    struct sockaddr_storage first_addr;
    int first_addrlen = 0;

    for (uint32_t i = 0; i < config->proxy_count; i++) {
        struct sockaddr_storage candidate_addr;
        int candidate_addrlen = 0;

        if (!pxc_resolve_proxy(config->proxies[i].host, config->proxies[i].port, &candidate_addr, &candidate_addrlen)) {
            continue;
        }

        // If there is only one proxy in the list, no need to probe: connect caller socket directly
        if (config->proxy_count == 1) {
            first_idx = 0;
            first_addr = candidate_addr;
            first_addrlen = candidate_addrlen;
            break;
        }

        // Probe reachability with a temporary socket so caller's socket is not tainted
        SOCKET probe = socket(((struct sockaddr *)&candidate_addr)->sa_family, SOCK_STREAM, IPPROTO_TCP);
        if (probe != INVALID_SOCKET) {
            pxc_status_t probe_st = pxc_timed_connect(probe, (struct sockaddr *)&candidate_addr, candidate_addrlen, config->tcp_connect_timeout_ms);
            closesocket(probe);
            if (probe_st == PXC_STATUS_SUCCESS) {
                first_idx = i;
                first_addr = candidate_addr;
                first_addrlen = candidate_addrlen;
                break;
            }
        }
    }

    if (first_idx >= config->proxy_count) {
        if (!config->quiet_mode) {
            fprintf(stderr, "[proxychains-win] Dynamic chain ... all proxies unreachable\n");
            fflush(stderr);
        }
        return PXC_TUNNEL_ALL_PROXIES_DOWN;
    }

    if (!config->quiet_mode) {
        fprintf(stderr, "[proxychains-win] Dynamic chain ... %s:%u ", config->proxies[first_idx].host, (unsigned int)config->proxies[first_idx].port);
        fflush(stderr);
    }

    pxc_status_t st = pxc_timed_connect(sock, (struct sockaddr *)&first_addr, first_addrlen, config->tcp_connect_timeout_ms);
    if (st != PXC_STATUS_SUCCESS) {
        if (!config->quiet_mode) {
            fprintf(stderr, "<-- timeout or connection refused\n");
            fflush(stderr);
        }
        return PXC_TUNNEL_ALL_PROXIES_DOWN;
    }

    uint32_t current_proxy_idx = first_idx;
    for (uint32_t i = first_idx + 1; i < config->proxy_count; i++) {
        pxc_endpoint_t next_ep;
        endpoint_from_proxy(&next_ep, &config->proxies[i]);

        if (!config->quiet_mode) {
            fprintf(stderr, "... %s:%u ", config->proxies[i].host, (unsigned int)config->proxies[i].port);
            fflush(stderr);
        }

        st = pxc_proxy_handshake(sock, config->proxies[current_proxy_idx].protocol, &next_ep,
                                config->proxies[current_proxy_idx].username, config->proxies[current_proxy_idx].password,
                                pxc_config_get_effective_ua(config),
                                config->tcp_read_timeout_ms);
        if (st == PXC_STATUS_SUCCESS) {
            current_proxy_idx = i;
        } else {
            // In dynamic chain, intermediate proxy failure skips to next if possible
            if (!config->quiet_mode) {
                fprintf(stderr, "<-- skip (%s) ", pxc_status_to_string(st));
                fflush(stderr);
            }
        }
    }

    char target_str[256];
    pxc_endpoint_to_string(target, target_str, sizeof(target_str));

    if (!config->quiet_mode) {
        fprintf(stderr, "... %s ", target_str);
        fflush(stderr);
    }

    const pxc_proxy_entry_t *last_proxy = &config->proxies[current_proxy_idx];
    st = pxc_proxy_handshake(sock, last_proxy->protocol, target,
                            last_proxy->username, last_proxy->password,
                            pxc_config_get_effective_ua(config),
                            config->tcp_read_timeout_ms);
    if (st != PXC_STATUS_SUCCESS) {
        if (!config->quiet_mode) {
            fprintf(stderr, "<-- denied (%s)\n", pxc_status_to_string(st));
            fflush(stderr);
        }
        return PXC_TUNNEL_HANDSHAKE_FAILED;
    }

    if (!config->quiet_mode) {
        fprintf(stderr, "... OK\n");
        fflush(stderr);
    }

    return PXC_TUNNEL_SUCCESS;
}

static pxc_tunnel_status_t establish_single_proxy(SOCKET sock, const pxc_config_t *config,
                                                  uint32_t proxy_idx, const pxc_endpoint_t *target,
                                                  const char *chain_label) {
    const pxc_proxy_entry_t *proxy = &config->proxies[proxy_idx];
    struct sockaddr_storage addr;
    int addrlen = 0;

    if (!pxc_resolve_proxy(proxy->host, proxy->port, &addr, &addrlen)) {
        return PXC_TUNNEL_ALL_PROXIES_DOWN;
    }

    char target_str[256];
    pxc_endpoint_to_string(target, target_str, sizeof(target_str));

    if (!config->quiet_mode) {
        fprintf(stderr, "[proxychains-win] %s chain ... %s:%u ... %s ",
                chain_label, proxy->host, (unsigned int)proxy->port, target_str);
        fflush(stderr);
    }

    pxc_status_t st = pxc_timed_connect(sock, (struct sockaddr *)&addr, addrlen, config->tcp_connect_timeout_ms);
    if (st != PXC_STATUS_SUCCESS) {
        if (!config->quiet_mode) {
            fprintf(stderr, "<-- timeout or connection refused\n");
            fflush(stderr);
        }
        return PXC_TUNNEL_ALL_PROXIES_DOWN;
    }

    st = pxc_proxy_handshake(sock, proxy->protocol, target,
                            proxy->username, proxy->password,
                            pxc_config_get_effective_ua(config),
                            config->tcp_read_timeout_ms);
    if (st != PXC_STATUS_SUCCESS) {
        if (!config->quiet_mode) {
            fprintf(stderr, "<-- handshake failed (%s)\n", pxc_status_to_string(st));
            fflush(stderr);
        }
        return PXC_TUNNEL_HANDSHAKE_FAILED;
    }

    if (!config->quiet_mode) {
        fprintf(stderr, "... OK\n");
        fflush(stderr);
    }

    return PXC_TUNNEL_SUCCESS;
}

pxc_tunnel_status_t pxc_establish_chain(SOCKET sock, const pxc_config_t *config, const pxc_endpoint_t *target) {
    if (!config || config->proxy_count == 0) {
        return PXC_TUNNEL_CONFIG_EMPTY;
    }
    if (!target) {
        return PXC_TUNNEL_HANDSHAKE_FAILED;
    }

    if (pxc_is_localnet(config, target)) {
        return PXC_TUNNEL_BYPASS;
    }

    pxc_endpoint_t effective_target = *target;

    // Check if target is a synthetic IP on the configured subnet prefix (e.g. 198.18.0.0/15)
    if (effective_target.type == PXC_ADDR_IPV4 && g_fake_ip_resolver != NULL) {
        uint8_t first_octet = ((const uint8_t *)&effective_target.addr.ipv4.s_addr)[0];
        if (first_octet == config->remote_dns_subnet_prefix) {
            char domain_buf[PXC_MAX_STRING_LEN];
            if (g_fake_ip_resolver(effective_target.addr.ipv4, domain_buf, sizeof(domain_buf))) {
                pxc_endpoint_from_domain(&effective_target, domain_buf, target->port);
            }
        }
    }

    switch (config->chain_type) {
        case PXC_CHAIN_STRICT:
            return establish_strict(sock, config, &effective_target);

        case PXC_CHAIN_DYNAMIC:
            return establish_dynamic(sock, config, &effective_target);

        case PXC_CHAIN_RANDOM: {
            uint32_t idx = (uint32_t)(rand() % config->proxy_count);
            return establish_single_proxy(sock, config, idx, &effective_target, "Random");
        }

        case PXC_CHAIN_ROUND_ROBIN: {
            LONG raw_idx = InterlockedIncrement(&g_round_robin_counter) - 1;
            if (raw_idx < 0) raw_idx = 0;
            uint32_t idx = (uint32_t)(raw_idx % config->proxy_count);
            return establish_single_proxy(sock, config, idx, &effective_target, "Round Robin");
        }

        default:
            return establish_dynamic(sock, config, &effective_target);
    }
}
