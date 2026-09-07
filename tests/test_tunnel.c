#include "proxychains/tunnel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "Assertion failed: %s at %s:%d\n", #cond, __FILE__, __LINE__); \
        exit(1); \
    } \
} while (0)

static void test_localnet_matching(void) {
    pxc_config_t config;
    pxc_config_init_defaults(&config);

    // Add localnet 192.168.0.0/255.255.0.0 (all ports)
    inet_pton(AF_INET, "192.168.0.0", &config.localnets[0].network);
    inet_pton(AF_INET, "255.255.0.0", &config.localnets[0].netmask);
    config.localnets[0].port = 0;
    config.localnet_count = 1;

    pxc_endpoint_t ep1, ep_loopback1, ep_loopback2, ep_localhost, ep_external;
    struct in_addr ip1, ip_loop1, ip_loop2, ip_ext;
    inet_pton(AF_INET, "192.168.1.100", &ip1);
    inet_pton(AF_INET, "127.0.0.1", &ip_loop1);
    inet_pton(AF_INET, "127.0.0.2", &ip_loop2);
    inet_pton(AF_INET, "8.8.8.8", &ip_ext);

    pxc_endpoint_from_ipv4(&ep1, ip1, 80);
    pxc_endpoint_from_ipv4(&ep_loopback1, ip_loop1, 80);
    pxc_endpoint_from_ipv4(&ep_loopback2, ip_loop2, 52134);
    pxc_endpoint_from_ipv4(&ep_external, ip_ext, 80);
    pxc_endpoint_from_domain(&ep_localhost, "localhost", 8080);

    TEST_ASSERT(pxc_is_localnet(&config, &ep1) == true);
    TEST_ASSERT(pxc_is_localnet(&config, &ep_loopback1) == true);
    TEST_ASSERT(pxc_is_localnet(&config, &ep_loopback2) == true);
    TEST_ASSERT(pxc_is_localnet(&config, &ep_localhost) == true);
    TEST_ASSERT(pxc_is_localnet(&config, &ep_external) == false);

    // Port-specific localnet 10.0.0.0/255.0.0.0 port 80 only
    inet_pton(AF_INET, "10.0.0.0", &config.localnets[1].network);
    inet_pton(AF_INET, "255.0.0.0", &config.localnets[1].netmask);
    config.localnets[1].port = 80;
    config.localnet_count = 2;

    struct in_addr ip3;
    inet_pton(AF_INET, "10.1.2.3", &ip3);
    pxc_endpoint_t ep3_port80, ep3_port443;
    pxc_endpoint_from_ipv4(&ep3_port80, ip3, 80);
    pxc_endpoint_from_ipv4(&ep3_port443, ip3, 443);

    TEST_ASSERT(pxc_is_localnet(&config, &ep3_port80) == true);
    TEST_ASSERT(pxc_is_localnet(&config, &ep3_port443) == false);
}

static void test_resolve_proxy(void) {
    struct sockaddr_storage addr;
    int addrlen = 0;

    TEST_ASSERT(pxc_resolve_proxy("127.0.0.1", 1080, &addr, &addrlen));
    TEST_ASSERT(addrlen == sizeof(struct sockaddr_in));
    struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
    TEST_ASSERT(sin->sin_family == AF_INET);
    TEST_ASSERT(ntohs(sin->sin_port) == 1080);

    TEST_ASSERT(pxc_resolve_proxy("::1", 9050, &addr, &addrlen));
    TEST_ASSERT(addrlen == sizeof(struct sockaddr_in6));
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;
    TEST_ASSERT(sin6->sin6_family == AF_INET6);
    TEST_ASSERT(ntohs(sin6->sin6_port) == 9050);

    TEST_ASSERT(pxc_resolve_proxy("localhost", 8080, &addr, &addrlen));
    TEST_ASSERT(addrlen > 0);
}

static void test_status_strings(void) {
    TEST_ASSERT(strcmp(pxc_tunnel_status_to_string(PXC_TUNNEL_SUCCESS), "Tunnel Established") == 0);
    TEST_ASSERT(strcmp(pxc_tunnel_status_to_string(PXC_TUNNEL_BYPASS), "Localnet Bypass") == 0);
    TEST_ASSERT(strcmp(pxc_tunnel_status_to_string(PXC_TUNNEL_CONFIG_EMPTY), "No Proxies Configured") == 0);
    TEST_ASSERT(strcmp(pxc_tunnel_status_to_string(PXC_TUNNEL_ALL_PROXIES_DOWN), "All Proxies Down") == 0);
    TEST_ASSERT(strcmp(pxc_tunnel_status_to_string(PXC_TUNNEL_HANDSHAKE_FAILED), "Proxy Handshake Failed") == 0);
    TEST_ASSERT(strcmp(pxc_tunnel_status_to_string(PXC_TUNNEL_SOCKET_ERROR), "Socket Error") == 0);
}

typedef struct {
    uint16_t port;
    HANDLE   ready_event;
    char     received_domain[256];
} mock_tunnel_server_t;

static DWORD WINAPI mock_tunnel_socks5_thread(LPVOID param) {
    mock_tunnel_server_t *ctx = (mock_tunnel_server_t *)param;

    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) return 1;

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind_addr.sin_port = 0;

    bind(listen_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr));

    int addr_len = sizeof(bind_addr);
    getsockname(listen_sock, (struct sockaddr *)&bind_addr, &addr_len);
    ctx->port = ntohs(bind_addr.sin_port);

    listen(listen_sock, 5);
    SetEvent(ctx->ready_event);

    SOCKET client_sock = accept(listen_sock, NULL, NULL);
    closesocket(listen_sock);
    if (client_sock == INVALID_SOCKET) return 1;

    uint8_t buf[1024];
    // 1. Read greeting
    int n = recv(client_sock, (char *)buf, sizeof(buf), 0);
    if (n >= 3 && buf[0] == 0x05) {
        uint8_t greet_resp[2] = { 0x05, 0x00 };
        send(client_sock, (char *)greet_resp, 2, 0);

        // 2. Read connect request
        n = recv(client_sock, (char *)buf, sizeof(buf), 0);
        if (n >= 7 && buf[0] == 0x05 && buf[1] == 0x01) {
            if (buf[3] == 0x03) { // Domain
                uint8_t dlen = buf[4];
                memcpy(ctx->received_domain, &buf[5], dlen);
                ctx->received_domain[dlen] = '\0';
            }
            uint8_t conn_resp[10] = { 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90 };
            send(client_sock, (char *)conn_resp, 10, 0);
        }
    }

    // Drain and close
    char drain[64];
    while (recv(client_sock, drain, sizeof(drain), 0) > 0) {}
    closesocket(client_sock);
    return 0;
}

static bool mock_fake_ip_lookup(struct in_addr ip, char *out_domain, size_t max_len) {
    uint32_t val = ntohl(ip.s_addr);
    if (val == 0xC612002A) { // 198.18.0.42
        strncpy_s(out_domain, max_len, "resolved-fake-domain.internal", _TRUNCATE);
        return true;
    }
    return false;
}

static void test_mock_tunnel_chain(void) {
    mock_tunnel_server_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ready_event = CreateEventW(NULL, TRUE, FALSE, NULL);

    HANDLE thread = CreateThread(NULL, 0, mock_tunnel_socks5_thread, &ctx, 0, NULL);
    TEST_ASSERT(thread != NULL);

    WaitForSingleObject(ctx.ready_event, 5000);
    CloseHandle(ctx.ready_event);

    pxc_config_t config;
    pxc_config_init_defaults(&config);
    config.quiet_mode = true;
    config.chain_type = PXC_CHAIN_STRICT;
    config.proxy_count = 1;
    config.proxies[0].protocol = PXC_PROTO_SOCKS5;
    strcpy_s(config.proxies[0].host, sizeof(config.proxies[0].host), "127.0.0.1");
    config.proxies[0].port = ctx.port;

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    TEST_ASSERT(sock != INVALID_SOCKET);

    pxc_endpoint_t target;
    pxc_endpoint_from_domain(&target, "test-target.com", 80);

    pxc_tunnel_status_t st = pxc_establish_chain(sock, &config, &target);
    TEST_ASSERT(st == PXC_TUNNEL_SUCCESS);
    TEST_ASSERT(strcmp(ctx.received_domain, "test-target.com") == 0);

    closesocket(sock);
    WaitForSingleObject(thread, 3000);
    CloseHandle(thread);
}

static void test_mock_tunnel_synthetic_ip(void) {
    mock_tunnel_server_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ready_event = CreateEventW(NULL, TRUE, FALSE, NULL);

    HANDLE thread = CreateThread(NULL, 0, mock_tunnel_socks5_thread, &ctx, 0, NULL);
    TEST_ASSERT(thread != NULL);

    WaitForSingleObject(ctx.ready_event, 5000);
    CloseHandle(ctx.ready_event);

    pxc_config_t config;
    pxc_config_init_defaults(&config);
    config.quiet_mode = true;
    config.remote_dns_subnet_prefix = 198;
    config.chain_type = PXC_CHAIN_DYNAMIC;
    config.proxy_count = 1;
    config.proxies[0].protocol = PXC_PROTO_SOCKS5;
    strcpy_s(config.proxies[0].host, sizeof(config.proxies[0].host), "127.0.0.1");
    config.proxies[0].port = ctx.port;

    pxc_tunnel_set_fake_ip_resolver(mock_fake_ip_lookup);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    TEST_ASSERT(sock != INVALID_SOCKET);

    pxc_endpoint_t target;
    struct in_addr fake_ip;
    inet_pton(AF_INET, "198.18.0.42", &fake_ip);
    pxc_endpoint_from_ipv4(&target, fake_ip, 443);

    pxc_tunnel_status_t st = pxc_establish_chain(sock, &config, &target);
    TEST_ASSERT(st == PXC_TUNNEL_SUCCESS);
    TEST_ASSERT(strcmp(ctx.received_domain, "resolved-fake-domain.internal") == 0);

    closesocket(sock);
    WaitForSingleObject(thread, 3000);
    CloseHandle(thread);

    pxc_tunnel_set_fake_ip_resolver(NULL);
}

static void test_mock_tunnel_round_robin(void) {
    mock_tunnel_server_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ready_event = CreateEventW(NULL, TRUE, FALSE, NULL);

    HANDLE thread = CreateThread(NULL, 0, mock_tunnel_socks5_thread, &ctx, 0, NULL);
    TEST_ASSERT(thread != NULL);

    WaitForSingleObject(ctx.ready_event, 5000);
    CloseHandle(ctx.ready_event);

    pxc_config_t config;
    pxc_config_init_defaults(&config);
    config.quiet_mode = true;
    config.chain_type = PXC_CHAIN_ROUND_ROBIN;
    config.proxy_count = 1;
    config.proxies[0].protocol = PXC_PROTO_SOCKS5;
    strcpy_s(config.proxies[0].host, sizeof(config.proxies[0].host), "127.0.0.1");
    config.proxies[0].port = ctx.port;

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    TEST_ASSERT(sock != INVALID_SOCKET);

    pxc_endpoint_t target;
    pxc_endpoint_from_domain(&target, "round-robin.internal", 80);

    pxc_tunnel_status_t st = pxc_establish_chain(sock, &config, &target);
    TEST_ASSERT(st == PXC_TUNNEL_SUCCESS);
    TEST_ASSERT(strcmp(ctx.received_domain, "round-robin.internal") == 0);

    closesocket(sock);
    WaitForSingleObject(thread, 3000);
    CloseHandle(thread);
}

int main(void) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    printf("Running In-Place Socket Tunneling Engine Tests...\n");

    printf("  [1] Localnet Matching...\n");
    test_localnet_matching();

    printf("  [2] Proxy Address Resolution...\n");
    test_resolve_proxy();

    printf("  [3] Status String Helper...\n");
    test_status_strings();

    printf("  [4] In-Place Chain Establishment (Mock SOCKS5)...\n");
    test_mock_tunnel_chain();

    printf("  [5] Synthetic IP Translation Handshake...\n");
    test_mock_tunnel_synthetic_ip();

    printf("  [6] Round-Robin Chaining Mode...\n");
    test_mock_tunnel_round_robin();

    WSACleanup();

    printf("All Tunneling Engine Tests PASSED successfully!\n");
    return 0;
}
