#include "proxychains/protocol.h"
#include "proxychains/config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *pxc_status_to_string(pxc_status_t status) {
    switch (status) {
        case PXC_STATUS_SUCCESS:         return "Success";
        case PXC_STATUS_CONN_REFUSED:    return "Connection Refused";
        case PXC_STATUS_AUTH_FAILED:     return "Authentication Failed";
        case PXC_STATUS_NET_UNREACHABLE: return "Network Unreachable";
        case PXC_STATUS_TIMEDOUT:        return "Connection Timed Out";
        case PXC_STATUS_PROTOCOL_ERROR:  return "Protocol Error";
        case PXC_STATUS_SOCKET_ERROR:    return "Socket Error";
        default:                         return "Unknown Status";
    }
}

void pxc_endpoint_from_ipv4(pxc_endpoint_t *ep, struct in_addr ipv4, uint16_t port) {
    if (!ep) return;
    memset(ep, 0, sizeof(*ep));
    ep->type = PXC_ADDR_IPV4;
    ep->addr.ipv4 = ipv4;
    ep->port = port;
}

void pxc_endpoint_from_ipv6(pxc_endpoint_t *ep, const struct in6_addr *ipv6, uint16_t port) {
    if (!ep || !ipv6) return;
    memset(ep, 0, sizeof(*ep));
    ep->type = PXC_ADDR_IPV6;
    ep->addr.ipv6 = *ipv6;
    ep->port = port;
}

bool pxc_endpoint_from_domain(pxc_endpoint_t *ep, const char *domain, uint16_t port) {
    if (!ep || !domain) return false;
    size_t len = strlen(domain);
    if (len == 0 || len >= PXC_MAX_STRING_LEN) return false;
    memset(ep, 0, sizeof(*ep));
    ep->type = PXC_ADDR_DOMAIN;
    memcpy(ep->addr.domain, domain, len);
    ep->addr.domain[len] = '\0';
    ep->port = port;
    return true;
}

bool pxc_endpoint_to_string(const pxc_endpoint_t *ep, char *buf, size_t buf_len) {
    if (!ep || !buf || buf_len == 0) return false;

    if (ep->type == PXC_ADDR_IPV4) {
        char ip_str[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &ep->addr.ipv4, ip_str, sizeof(ip_str))) return false;
        int n = snprintf(buf, buf_len, "%s:%u", ip_str, (unsigned int)ep->port);
        return (n > 0 && (size_t)n < buf_len);
    } else if (ep->type == PXC_ADDR_IPV6) {
        char ip_str[INET6_ADDRSTRLEN];
        if (!inet_ntop(AF_INET6, &ep->addr.ipv6, ip_str, sizeof(ip_str))) return false;
        int n = snprintf(buf, buf_len, "[%s]:%u", ip_str, (unsigned int)ep->port);
        return (n > 0 && (size_t)n < buf_len);
    } else if (ep->type == PXC_ADDR_DOMAIN) {
        int n = snprintf(buf, buf_len, "%s:%u", ep->addr.domain, (unsigned int)ep->port);
        return (n > 0 && (size_t)n < buf_len);
    }
    return false;
}

bool pxc_base64_encode(const unsigned char *src, size_t src_len, char *dst, size_t dst_max) {
    static const char b64_table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (!dst || dst_max == 0) return false;

    size_t needed = ((src_len + 2) / 3) * 4 + 1;
    if (dst_max < needed) return false;

    size_t di = 0;
    for (size_t i = 0; i < src_len; i += 3) {
        uint32_t val = (uint32_t)src[i] << 16;
        size_t rem = src_len - i;
        if (rem > 1) val |= (uint32_t)src[i + 1] << 8;
        if (rem > 2) val |= (uint32_t)src[i + 2];

        dst[di++] = b64_table[(val >> 18) & 0x3F];
        dst[di++] = b64_table[(val >> 12) & 0x3F];
        dst[di++] = (rem > 1) ? b64_table[(val >> 6) & 0x3F] : '=';
        dst[di++] = (rem > 2) ? b64_table[val & 0x3F] : '=';
    }
    dst[di] = '\0';
    return true;
}

pxc_status_t pxc_timed_connect(SOCKET sock, const struct sockaddr *addr, int addrlen, uint32_t timeout_ms) {
    if (sock == INVALID_SOCKET || !addr || addrlen <= 0) {
        return PXC_STATUS_SOCKET_ERROR;
    }

    u_long nonblocking = 1;
    if (ioctlsocket(sock, FIONBIO, &nonblocking) != 0) {
        return PXC_STATUS_SOCKET_ERROR;
    }

    int ret = connect(sock, addr, addrlen);
    if (ret == 0) {
        nonblocking = 0;
        ioctlsocket(sock, FIONBIO, &nonblocking);
        return PXC_STATUS_SUCCESS;
    }

    int err = WSAGetLastError();
    if (err != WSAEWOULDBLOCK) {
        nonblocking = 0;
        ioctlsocket(sock, FIONBIO, &nonblocking);
        if (err == WSAECONNREFUSED) return PXC_STATUS_CONN_REFUSED;
        if (err == WSAENETUNREACH || err == WSAEHOSTUNREACH) return PXC_STATUS_NET_UNREACHABLE;
        if (err == WSAETIMEDOUT) return PXC_STATUS_TIMEDOUT;
        return PXC_STATUS_CONN_REFUSED;
    }

    fd_set writefds, exceptfds;
    FD_ZERO(&writefds);
    FD_SET(sock, &writefds);
    FD_ZERO(&exceptfds);
    FD_SET(sock, &exceptfds);

    struct timeval tv;
    tv.tv_sec = (long)(timeout_ms / 1000);
    tv.tv_usec = (long)((timeout_ms % 1000) * 1000);

    ret = select(0, NULL, &writefds, &exceptfds, &tv);

    nonblocking = 0;
    ioctlsocket(sock, FIONBIO, &nonblocking);

    if (ret == 0) {
        return PXC_STATUS_TIMEDOUT;
    }
    if (ret == SOCKET_ERROR) {
        return PXC_STATUS_SOCKET_ERROR;
    }

    if (FD_ISSET(sock, &exceptfds)) {
        int so_err = 0;
        int optlen = sizeof(so_err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&so_err, &optlen);
        if (so_err == WSAECONNREFUSED) return PXC_STATUS_CONN_REFUSED;
        if (so_err == WSAENETUNREACH || so_err == WSAEHOSTUNREACH) return PXC_STATUS_NET_UNREACHABLE;
        return PXC_STATUS_CONN_REFUSED;
    }

    if (FD_ISSET(sock, &writefds)) {
        int so_err = 0;
        int optlen = sizeof(so_err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&so_err, &optlen);
        if (so_err != 0) {
            if (so_err == WSAECONNREFUSED) return PXC_STATUS_CONN_REFUSED;
            if (so_err == WSAENETUNREACH || so_err == WSAEHOSTUNREACH) return PXC_STATUS_NET_UNREACHABLE;
            return PXC_STATUS_CONN_REFUSED;
        }
        return PXC_STATUS_SUCCESS;
    }

    return PXC_STATUS_TIMEDOUT;
}

pxc_status_t pxc_socket_send_all(SOCKET sock, const void *buf, size_t len, uint32_t timeout_ms) {
    if (sock == INVALID_SOCKET || (!buf && len > 0)) {
        return PXC_STATUS_SOCKET_ERROR;
    }

    ULONGLONG start_ms = GetTickCount64();
    size_t total_sent = 0;

    while (total_sent < len) {
        ULONGLONG elapsed = GetTickCount64() - start_ms;
        if (elapsed >= timeout_ms) return PXC_STATUS_TIMEDOUT;
        uint32_t rem_ms = timeout_ms - (uint32_t)elapsed;

        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(sock, &writefds);

        struct timeval tv;
        tv.tv_sec = (long)(rem_ms / 1000);
        tv.tv_usec = (long)((rem_ms % 1000) * 1000);

        int r = select(0, NULL, &writefds, NULL, &tv);
        if (r == 0) return PXC_STATUS_TIMEDOUT;
        if (r == SOCKET_ERROR) return PXC_STATUS_SOCKET_ERROR;

        int n = send(sock, (const char *)buf + total_sent, (int)(len - total_sent), 0);
        if (n == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) continue;
            return PXC_STATUS_SOCKET_ERROR;
        }
        if (n == 0) return PXC_STATUS_CONN_REFUSED;
        total_sent += (size_t)n;
    }

    return PXC_STATUS_SUCCESS;
}

pxc_status_t pxc_socket_recv_all(SOCKET sock, void *buf, size_t len, uint32_t timeout_ms) {
    if (sock == INVALID_SOCKET || (!buf && len > 0)) {
        return PXC_STATUS_SOCKET_ERROR;
    }

    ULONGLONG start_ms = GetTickCount64();
    size_t total_recv = 0;

    while (total_recv < len) {
        ULONGLONG elapsed = GetTickCount64() - start_ms;
        if (elapsed >= timeout_ms) return PXC_STATUS_TIMEDOUT;
        uint32_t rem_ms = timeout_ms - (uint32_t)elapsed;

        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);

        struct timeval tv;
        tv.tv_sec = (long)(rem_ms / 1000);
        tv.tv_usec = (long)((rem_ms % 1000) * 1000);

        int r = select(0, &readfds, NULL, NULL, &tv);
        if (r == 0) return PXC_STATUS_TIMEDOUT;
        if (r == SOCKET_ERROR) return PXC_STATUS_SOCKET_ERROR;

        int n = recv(sock, (char *)buf + total_recv, (int)(len - total_recv), 0);
        if (n == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) continue;
            return PXC_STATUS_SOCKET_ERROR;
        }
        if (n == 0) return PXC_STATUS_CONN_REFUSED;
        total_recv += (size_t)n;
    }

    return PXC_STATUS_SUCCESS;
}

pxc_status_t pxc_socket_recv_http_response(SOCKET sock, char *buf, size_t buf_size, size_t *out_len, uint32_t timeout_ms) {
    if (sock == INVALID_SOCKET || !buf || buf_size < 16) {
        return PXC_STATUS_SOCKET_ERROR;
    }

    ULONGLONG start_ms = GetTickCount64();
    size_t found_hdr_len = 0;

    while (1) {
        ULONGLONG elapsed = GetTickCount64() - start_ms;
        if (elapsed >= timeout_ms) return PXC_STATUS_TIMEDOUT;
        uint32_t rem_ms = timeout_ms - (uint32_t)elapsed;

        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);

        struct timeval tv;
        tv.tv_sec = (long)(rem_ms / 1000);
        tv.tv_usec = (long)((rem_ms % 1000) * 1000);

        int r = select(0, &readfds, NULL, NULL, &tv);
        if (r == 0) return PXC_STATUS_TIMEDOUT;
        if (r == SOCKET_ERROR) return PXC_STATUS_SOCKET_ERROR;

        int peeked = recv(sock, buf, (int)(buf_size - 1), MSG_PEEK);
        if (peeked == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                Sleep(2);
                continue;
            }
            return PXC_STATUS_SOCKET_ERROR;
        }
        if (peeked == 0) return PXC_STATUS_CONN_REFUSED;

        for (int i = 0; i < peeked; i++) {
            if (i + 3 < peeked && buf[i] == '\r' && buf[i + 1] == '\n' &&
                buf[i + 2] == '\r' && buf[i + 3] == '\n') {
                found_hdr_len = (size_t)(i + 4);
                break;
            }
            if (i + 1 < peeked && buf[i] == '\n' && buf[i + 1] == '\n') {
                found_hdr_len = (size_t)(i + 2);
                break;
            }
        }

        if (found_hdr_len > 0) {
            pxc_status_t st = pxc_socket_recv_all(sock, buf, found_hdr_len, rem_ms);
            if (st != PXC_STATUS_SUCCESS) return st;
            buf[found_hdr_len] = '\0';
            if (out_len) *out_len = found_hdr_len;
            return PXC_STATUS_SUCCESS;
        }

        if ((size_t)peeked >= buf_size - 1) {
            return PXC_STATUS_PROTOCOL_ERROR;
        }

        Sleep(5);
    }
}

pxc_status_t pxc_socks4_handshake(SOCKET sock, const pxc_endpoint_t *target, const char *user, uint32_t timeout_ms) {
    if (!target) return PXC_STATUS_PROTOCOL_ERROR;
    if (target->type == PXC_ADDR_IPV6) {
        return PXC_STATUS_PROTOCOL_ERROR; // SOCKS4 doesn't support IPv6
    }

    uint8_t req[1024];
    req[0] = 0x04; // SOCKS version 4
    req[1] = 0x01; // CONNECT command
    uint16_t port_be = htons(target->port);
    memcpy(&req[2], &port_be, 2);

    size_t offset = 4;
    if (target->type == PXC_ADDR_IPV4) {
        memcpy(&req[offset], &target->addr.ipv4.s_addr, 4);
        offset += 4;
    } else if (target->type == PXC_ADDR_DOMAIN) {
        // SOCKS4a convention: 0.0.0.1
        req[offset++] = 0x00;
        req[offset++] = 0x00;
        req[offset++] = 0x00;
        req[offset++] = 0x01;
    } else {
        return PXC_STATUS_PROTOCOL_ERROR;
    }

    if (user && user[0] != '\0') {
        size_t ulen = strlen(user);
        if (ulen > 255) return PXC_STATUS_PROTOCOL_ERROR;
        memcpy(&req[offset], user, ulen);
        offset += ulen;
    }
    req[offset++] = 0x00; // Null terminator for user ID

    if (target->type == PXC_ADDR_DOMAIN) {
        size_t dlen = strlen(target->addr.domain);
        if (dlen == 0 || dlen > 255) return PXC_STATUS_PROTOCOL_ERROR;
        memcpy(&req[offset], target->addr.domain, dlen);
        offset += dlen;
        req[offset++] = 0x00; // Null terminator for domain
    }

    pxc_status_t st = pxc_socket_send_all(sock, req, offset, timeout_ms);
    if (st != PXC_STATUS_SUCCESS) return st;

    uint8_t resp[8];
    st = pxc_socket_recv_all(sock, resp, 8, timeout_ms);
    if (st != PXC_STATUS_SUCCESS) return st;

    if (resp[0] != 0x00) return PXC_STATUS_PROTOCOL_ERROR;

    uint8_t cd = resp[1];
    if (cd == 90) return PXC_STATUS_SUCCESS;
    if (cd == 91) return PXC_STATUS_CONN_REFUSED;
    if (cd == 92 || cd == 93) return PXC_STATUS_AUTH_FAILED;
    return PXC_STATUS_PROTOCOL_ERROR;
}

pxc_status_t pxc_socks5_handshake(SOCKET sock, const pxc_endpoint_t *target, const char *user, const char *pass, uint32_t timeout_ms) {
    if (!target) return PXC_STATUS_PROTOCOL_ERROR;

    bool has_auth = (user != NULL && user[0] != '\0');
    uint8_t greet[4];
    greet[0] = 0x05;
    if (has_auth) {
        greet[1] = 2;    // 2 methods
        greet[2] = 0x00; // No auth
        greet[3] = 0x02; // Username/Password
    } else {
        greet[1] = 1;    // 1 method
        greet[2] = 0x00; // No auth
    }
    size_t greet_len = has_auth ? 4 : 3;

    pxc_status_t st = pxc_socket_send_all(sock, greet, greet_len, timeout_ms);
    if (st != PXC_STATUS_SUCCESS) return st;

    uint8_t greet_resp[2];
    st = pxc_socket_recv_all(sock, greet_resp, 2, timeout_ms);
    if (st != PXC_STATUS_SUCCESS) return st;

    if (greet_resp[0] != 0x05) return PXC_STATUS_PROTOCOL_ERROR;
    if (greet_resp[1] == 0xFF) return PXC_STATUS_AUTH_FAILED;

    if (greet_resp[1] == 0x02) {
        // RFC 1929 Username/Password Subnegotiation
        uint8_t auth_req[515];
        auth_req[0] = 0x01; // Subnegotiation version 1
        size_t ulen = strlen(user);
        size_t plen = pass ? strlen(pass) : 0;
        if (ulen > 255 || plen > 255) return PXC_STATUS_PROTOCOL_ERROR;

        auth_req[1] = (uint8_t)ulen;
        memcpy(&auth_req[2], user, ulen);
        auth_req[2 + ulen] = (uint8_t)plen;
        if (plen > 0) memcpy(&auth_req[3 + ulen], pass, plen);
        size_t auth_req_len = 3 + ulen + plen;

        st = pxc_socket_send_all(sock, auth_req, auth_req_len, timeout_ms);
        if (st != PXC_STATUS_SUCCESS) return st;

        uint8_t auth_resp[2];
        st = pxc_socket_recv_all(sock, auth_resp, 2, timeout_ms);
        if (st != PXC_STATUS_SUCCESS) return st;

        if (auth_resp[0] != 0x01 && auth_resp[0] != 0x05) return PXC_STATUS_PROTOCOL_ERROR;
        if (auth_resp[1] != 0x00) return PXC_STATUS_AUTH_FAILED;
    } else if (greet_resp[1] != 0x00) {
        return PXC_STATUS_AUTH_FAILED;
    }

    // CONNECT request
    uint8_t req[1024];
    req[0] = 0x05;
    req[1] = 0x01; // CONNECT
    req[2] = 0x00; // RSV
    size_t off = 4;

    if (target->type == PXC_ADDR_IPV4) {
        req[3] = 0x01; // ATYP IPv4
        memcpy(&req[off], &target->addr.ipv4.s_addr, 4);
        off += 4;
    } else if (target->type == PXC_ADDR_DOMAIN) {
        req[3] = 0x03; // ATYP Domain
        size_t dlen = strlen(target->addr.domain);
        if (dlen == 0 || dlen > 255) return PXC_STATUS_PROTOCOL_ERROR;
        req[off++] = (uint8_t)dlen;
        memcpy(&req[off], target->addr.domain, dlen);
        off += dlen;
    } else if (target->type == PXC_ADDR_IPV6) {
        req[3] = 0x04; // ATYP IPv6
        memcpy(&req[off], &target->addr.ipv6.s6_addr, 16);
        off += 16;
    } else {
        return PXC_STATUS_PROTOCOL_ERROR;
    }

    uint16_t port_be = htons(target->port);
    memcpy(&req[off], &port_be, 2);
    off += 2;

    st = pxc_socket_send_all(sock, req, off, timeout_ms);
    if (st != PXC_STATUS_SUCCESS) return st;

    uint8_t resp_hdr[4];
    st = pxc_socket_recv_all(sock, resp_hdr, 4, timeout_ms);
    if (st != PXC_STATUS_SUCCESS) return st;

    if (resp_hdr[0] != 0x05) return PXC_STATUS_PROTOCOL_ERROR;
    uint8_t rep = resp_hdr[1];
    uint8_t atyp = resp_hdr[3];

    size_t bnd_len = 0;
    if (atyp == 0x01) {
        bnd_len = 4 + 2;
    } else if (atyp == 0x04) {
        bnd_len = 16 + 2;
    } else if (atyp == 0x03) {
        uint8_t dlen = 0;
        st = pxc_socket_recv_all(sock, &dlen, 1, timeout_ms);
        if (st != PXC_STATUS_SUCCESS) return st;
        bnd_len = dlen + 2;
    } else {
        return PXC_STATUS_PROTOCOL_ERROR;
    }

    uint8_t dummy[512];
    if (bnd_len > sizeof(dummy)) return PXC_STATUS_PROTOCOL_ERROR;
    st = pxc_socket_recv_all(sock, dummy, bnd_len, timeout_ms);
    if (st != PXC_STATUS_SUCCESS) return st;

    if (rep == 0x00) return PXC_STATUS_SUCCESS;
    if (rep == 0x05 || rep == 0x02) return PXC_STATUS_CONN_REFUSED;
    if (rep == 0x03 || rep == 0x04) return PXC_STATUS_NET_UNREACHABLE;
    if (rep == 0x06) return PXC_STATUS_TIMEDOUT;
    return PXC_STATUS_PROTOCOL_ERROR;
}

pxc_status_t pxc_http_handshake(SOCKET sock, const pxc_endpoint_t *target, const char *user, const char *pass,
                                const char *user_agent, uint32_t timeout_ms) {
    if (!target) return PXC_STATUS_PROTOCOL_ERROR;

    const char *ua = (user_agent && user_agent[0] != '\0') ? user_agent : PXC_TOR_USER_AGENT;

    char host_str[PXC_MAX_STRING_LEN + 16];
    if (target->type == PXC_ADDR_IPV4) {
        if (!inet_ntop(AF_INET, &target->addr.ipv4, host_str, sizeof(host_str))) {
            return PXC_STATUS_PROTOCOL_ERROR;
        }
    } else if (target->type == PXC_ADDR_IPV6) {
        char v6_raw[INET6_ADDRSTRLEN];
        if (!inet_ntop(AF_INET6, &target->addr.ipv6, v6_raw, sizeof(v6_raw))) {
            return PXC_STATUS_PROTOCOL_ERROR;
        }
        snprintf(host_str, sizeof(host_str), "[%s]", v6_raw);
    } else if (target->type == PXC_ADDR_DOMAIN) {
        strncpy_s(host_str, sizeof(host_str), target->addr.domain, _TRUNCATE);
    } else {
        return PXC_STATUS_PROTOCOL_ERROR;
    }

    char req_buf[2048];
    int req_len = 0;

    if (user && user[0] != '\0') {
        char creds[512];
        char b64_creds[1024];
        snprintf(creds, sizeof(creds), "%s:%s", user, pass ? pass : "");
        if (!pxc_base64_encode((const unsigned char *)creds, strlen(creds), b64_creds, sizeof(b64_creds))) {
            return PXC_STATUS_PROTOCOL_ERROR;
        }
        req_len = snprintf(req_buf, sizeof(req_buf),
                           "CONNECT %s:%u HTTP/1.1\r\n"
                           "Host: %s:%u\r\n"
                           "User-Agent: %s\r\n"
                           "Proxy-Connection: Keep-Alive\r\n"
                           "Proxy-Authorization: Basic %s\r\n\r\n",
                           host_str, (unsigned int)target->port,
                           host_str, (unsigned int)target->port,
                           ua,
                           b64_creds);
    } else {
        req_len = snprintf(req_buf, sizeof(req_buf),
                           "CONNECT %s:%u HTTP/1.1\r\n"
                           "Host: %s:%u\r\n"
                           "User-Agent: %s\r\n"
                           "Proxy-Connection: Keep-Alive\r\n\r\n",
                           host_str, (unsigned int)target->port,
                           host_str, (unsigned int)target->port,
                           ua);
    }

    if (req_len <= 0 || (size_t)req_len >= sizeof(req_buf)) {
        return PXC_STATUS_PROTOCOL_ERROR;
    }

    pxc_status_t st = pxc_socket_send_all(sock, req_buf, (size_t)req_len, timeout_ms);
    if (st != PXC_STATUS_SUCCESS) return st;

    char resp_buf[4096];
    size_t resp_len = 0;
    st = pxc_socket_recv_http_response(sock, resp_buf, sizeof(resp_buf), &resp_len, timeout_ms);
    if (st != PXC_STATUS_SUCCESS) return st;

    // Parse status line: HTTP/1.x <code>
    if (strncmp(resp_buf, "HTTP/", 5) != 0) {
        return PXC_STATUS_PROTOCOL_ERROR;
    }

    char *space = strchr(resp_buf, ' ');
    if (!space) return PXC_STATUS_PROTOCOL_ERROR;
    while (*space == ' ') space++;

    int status_code = atoi(space);
    if (status_code >= 200 && status_code < 300) return PXC_STATUS_SUCCESS;
    if (status_code == 407) return PXC_STATUS_AUTH_FAILED;
    if (status_code == 403) return PXC_STATUS_CONN_REFUSED;
    if (status_code == 502 || status_code == 503 || status_code == 504) return PXC_STATUS_NET_UNREACHABLE;

    return PXC_STATUS_PROTOCOL_ERROR;
}

pxc_status_t pxc_proxy_handshake(SOCKET sock, pxc_protocol_t proto, const pxc_endpoint_t *target,
                                 const char *user, const char *pass, const char *user_agent, uint32_t timeout_ms) {
    switch (proto) {
        case PXC_PROTO_SOCKS4:
            return pxc_socks4_handshake(sock, target, user, timeout_ms);
        case PXC_PROTO_SOCKS5:
            return pxc_socks5_handshake(sock, target, user, pass, timeout_ms);
        case PXC_PROTO_HTTP:
            return pxc_http_handshake(sock, target, user, pass, user_agent, timeout_ms);
        default:
            return PXC_STATUS_PROTOCOL_ERROR;
    }
}
