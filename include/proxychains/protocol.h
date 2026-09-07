#ifndef PROXYCHAINS_PROTOCOL_H
#define PROXYCHAINS_PROTOCOL_H

#include "proxychains/common.h"
#include "proxychains/config.h"

typedef enum {
    PXC_STATUS_SUCCESS = 0,
    PXC_STATUS_CONN_REFUSED,
    PXC_STATUS_AUTH_FAILED,
    PXC_STATUS_NET_UNREACHABLE,
    PXC_STATUS_TIMEDOUT,
    PXC_STATUS_PROTOCOL_ERROR,
    PXC_STATUS_SOCKET_ERROR
} pxc_status_t;

typedef enum {
    PXC_ADDR_IPV4 = 1,
    PXC_ADDR_IPV6,
    PXC_ADDR_DOMAIN
} pxc_addr_type_t;

typedef struct {
    pxc_addr_type_t type;
    union {
        struct in_addr  ipv4;
        struct in6_addr ipv6;
        char            domain[PXC_MAX_STRING_LEN];
    } addr;
    uint16_t port; // Host byte order
} pxc_endpoint_t;

// Endpoint helpers
void pxc_endpoint_from_ipv4(pxc_endpoint_t *ep, struct in_addr ipv4, uint16_t port);
void pxc_endpoint_from_ipv6(pxc_endpoint_t *ep, const struct in6_addr *ipv6, uint16_t port);
bool pxc_endpoint_from_domain(pxc_endpoint_t *ep, const char *domain, uint16_t port);
bool pxc_endpoint_to_string(const pxc_endpoint_t *ep, char *buf, size_t buf_len);

// Base64 encoding
bool pxc_base64_encode(const unsigned char *src, size_t src_len, char *dst, size_t dst_max);

// Timed Winsock primitives
pxc_status_t pxc_timed_connect(SOCKET sock, const struct sockaddr *addr, int addrlen, uint32_t timeout_ms);
pxc_status_t pxc_socket_send_all(SOCKET sock, const void *buf, size_t len, uint32_t timeout_ms);
pxc_status_t pxc_socket_recv_all(SOCKET sock, void *buf, size_t len, uint32_t timeout_ms);
pxc_status_t pxc_socket_recv_http_response(SOCKET sock, char *buf, size_t buf_size, size_t *out_len, uint32_t timeout_ms);

// Protocol handshake engines
pxc_status_t pxc_socks4_handshake(SOCKET sock, const pxc_endpoint_t *target, const char *user, uint32_t timeout_ms);
pxc_status_t pxc_socks5_handshake(SOCKET sock, const pxc_endpoint_t *target, const char *user, const char *pass, uint32_t timeout_ms);
pxc_status_t pxc_http_handshake(SOCKET sock, const pxc_endpoint_t *target, const char *user, const char *pass,
                                const char *user_agent, uint32_t timeout_ms);

// Unified protocol handshake dispatcher
pxc_status_t pxc_proxy_handshake(SOCKET sock, pxc_protocol_t proto, const pxc_endpoint_t *target,
                                 const char *user, const char *pass, const char *user_agent, uint32_t timeout_ms);

// Status string helper
const char *pxc_status_to_string(pxc_status_t status);

#endif // PROXYCHAINS_PROTOCOL_H
