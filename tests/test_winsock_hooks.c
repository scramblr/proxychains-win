#include "proxychains/hooks.h"
#include <mswsock.h>
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

typedef struct {
    uint16_t port;
    HANDLE   ready_event;
    char     last_target_domain[256];
    uint16_t last_target_port;
    char     initial_data[256];
    int      initial_data_len;
} mock_socks_server_t;

static DWORD WINAPI mock_socks_server_thread(LPVOID param) {
    mock_socks_server_t *ctx = (mock_socks_server_t *)param;

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

    while (1) {
        SOCKET client_sock = accept(listen_sock, NULL, NULL);
        if (client_sock == INVALID_SOCKET) break;

        uint8_t buf[1024];
        // 1. Greeting
        int n = recv(client_sock, (char *)buf, sizeof(buf), 0);
        if (n >= 3 && buf[0] == 0x05) {
            uint8_t greet_resp[2] = { 0x05, 0x00 };
            send(client_sock, (char *)greet_resp, 2, 0);

            // 2. Connect request
            n = recv(client_sock, (char *)buf, sizeof(buf), 0);
            if (n >= 7 && buf[0] == 0x05 && buf[1] == 0x01) {
                if (buf[3] == 0x03) {
                    uint8_t dlen = buf[4];
                    memcpy(ctx->last_target_domain, &buf[5], dlen);
                    ctx->last_target_domain[dlen] = '\0';
                    uint16_t port_be = 0;
                    memcpy(&port_be, &buf[5 + dlen], 2);
                    ctx->last_target_port = ntohs(port_be);
                }
                uint8_t conn_resp[10] = { 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90 };
                send(client_sock, (char *)conn_resp, 10, 0);

                // 3. Receive any immediate data
                u_long nonblock = 1;
                ioctlsocket(client_sock, FIONBIO, &nonblock);
                Sleep(20);
                n = recv(client_sock, ctx->initial_data, sizeof(ctx->initial_data) - 1, 0);
                if (n > 0) {
                    ctx->initial_data_len = n;
                    ctx->initial_data[n] = '\0';
                    // Echo back with "ACK:" prefix
                    char echo_buf[512];
                    snprintf(echo_buf, sizeof(echo_buf), "ACK:%.*s", n, ctx->initial_data);
                    send(client_sock, echo_buf, (int)strlen(echo_buf), 0);
                }
            }
        }

        char drain[64];
        while (recv(client_sock, drain, sizeof(drain), 0) > 0) {}
        closesocket(client_sock);
    }

    closesocket(listen_sock);
    return 0;
}

int main(void) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    printf("Running Winsock Control-Plane Hook Tests...\n");

    // Start mock SOCKS5 server
    mock_socks_server_t mock;
    memset(&mock, 0, sizeof(mock));
    mock.ready_event = CreateEventW(NULL, TRUE, FALSE, NULL);

    HANDLE server_thread = CreateThread(NULL, 0, mock_socks_server_thread, &mock, 0, NULL);
    TEST_ASSERT(server_thread != NULL);
    WaitForSingleObject(mock.ready_event, 5000);
    CloseHandle(mock.ready_event);

    pxc_fake_ip_init(198);
    pxc_tunnel_set_fake_ip_resolver(pxc_fake_ip_lookup_domain);

    // Configure proxychains active config
    pxc_config_init_defaults(&g_pxc_active_config);
    g_pxc_active_config.quiet_mode = true;
    g_pxc_active_config.chain_type = PXC_CHAIN_STRICT;
    g_pxc_active_config.proxy_count = 1;
    g_pxc_active_config.proxies[0].protocol = PXC_PROTO_SOCKS5;
    strcpy_s(g_pxc_active_config.proxies[0].host, sizeof(g_pxc_active_config.proxies[0].host), "127.0.0.1");
    g_pxc_active_config.proxies[0].port = mock.port;

    printf("  [1] Installing DNS and Winsock Hooks...\n");
    TEST_ASSERT(pxc_install_dns_hooks() == true);
    TEST_ASSERT(pxc_install_winsock_hooks() == true);
    g_pxc_hooks_active = true;

    // Resolve target to synthetic IP
    PADDRINFOW res = NULL;
    INT ret = GetAddrInfoW(L"2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion", L"8080", NULL, &res);
    TEST_ASSERT(ret == 0 && res != NULL);
    struct sockaddr_in *target_sin = (struct sockaddr_in *)res->ai_addr;
    TEST_ASSERT(pxc_fake_ip_is_synthetic(target_sin->sin_addr));

    printf("  [2] Testing Hooked connect() via SOCKS5 Tunnel...\n");
    SOCKET sock1 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    TEST_ASSERT(sock1 != INVALID_SOCKET);

    int conn_ret = connect(sock1, res->ai_addr, (int)res->ai_addrlen);
    TEST_ASSERT(conn_ret == 0);
    TEST_ASSERT(_stricmp(mock.last_target_domain, "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion") == 0);
    TEST_ASSERT(mock.last_target_port == 8080);

    // Test sending data through the established in-place socket
    send(sock1, "PING", 4, 0);
    char recv_buf[64] = { 0 };
    int recvd = recv(sock1, recv_buf, sizeof(recv_buf) - 1, 0);
    TEST_ASSERT(recvd > 0);
    TEST_ASSERT(strcmp(recv_buf, "ACK:PING") == 0);
    closesocket(sock1);

    printf("  [3] Testing Hooked WSAConnect()...\n");
    memset(mock.last_target_domain, 0, sizeof(mock.last_target_domain));
    SOCKET sock2 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    TEST_ASSERT(sock2 != INVALID_SOCKET);

    int wsaconn_ret = WSAConnect(sock2, res->ai_addr, (int)res->ai_addrlen, NULL, NULL, NULL, NULL);
    TEST_ASSERT(wsaconn_ret == 0);
    TEST_ASSERT(_stricmp(mock.last_target_domain, "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion") == 0);
    closesocket(sock2);

    printf("  [4] Testing Hooked WSAIoctl + ConnectEx Extension Pointer...\n");
    SOCKET sock3 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    TEST_ASSERT(sock3 != INVALID_SOCKET);

    // ConnectEx requires the socket to be bound first
    struct sockaddr_in local_bind;
    memset(&local_bind, 0, sizeof(local_bind));
    local_bind.sin_family = AF_INET;
    local_bind.sin_addr.s_addr = htonl(INADDR_ANY);
    local_bind.sin_port = 0;
    bind(sock3, (struct sockaddr *)&local_bind, sizeof(local_bind));

    GUID guidConnectEx = WSAID_CONNECTEX;
    LPFN_CONNECTEX pfnConnectEx = NULL;
    DWORD bytes_returned = 0;

    int ioctl_ret = WSAIoctl(sock3, SIO_GET_EXTENSION_FUNCTION_POINTER,
                             &guidConnectEx, sizeof(guidConnectEx),
                             &pfnConnectEx, sizeof(pfnConnectEx),
                             &bytes_returned, NULL, NULL);
    TEST_ASSERT(ioctl_ret == 0);
    TEST_ASSERT(pfnConnectEx != NULL);

    memset(mock.last_target_domain, 0, sizeof(mock.last_target_domain));
    DWORD bytes_sent = 0;
    WSAOVERLAPPED ov;
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    BOOL cex_ret = pfnConnectEx(sock3, res->ai_addr, (int)res->ai_addrlen,
                                "HELLO_CONNECTEX", 15, &bytes_sent, &ov);
    TEST_ASSERT(cex_ret == TRUE);
    TEST_ASSERT(bytes_sent == 15);
    TEST_ASSERT(_stricmp(mock.last_target_domain, "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion") == 0);
    CloseHandle(ov.hEvent);
    closesocket(sock3);

    FreeAddrInfoW(res);

    printf("  [5] Testing Direct Loopback Bypass (127.0.0.1 IPC without proxy)...\n");
    SOCKET direct_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    TEST_ASSERT(direct_listen != INVALID_SOCKET);

    struct sockaddr_in d_bind;
    memset(&d_bind, 0, sizeof(d_bind));
    d_bind.sin_family = AF_INET;
    d_bind.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    d_bind.sin_port = 0;
    TEST_ASSERT(bind(direct_listen, (struct sockaddr *)&d_bind, sizeof(d_bind)) == 0);

    int d_len = sizeof(d_bind);
    TEST_ASSERT(getsockname(direct_listen, (struct sockaddr *)&d_bind, &d_len) == 0);
    uint16_t direct_port = ntohs(d_bind.sin_port);
    TEST_ASSERT(listen(direct_listen, 1) == 0);

    // Client connects to 127.0.0.1:direct_port while hooks are active
    SOCKET client_direct = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    TEST_ASSERT(client_direct != INVALID_SOCKET);

    struct sockaddr_in d_target;
    memset(&d_target, 0, sizeof(d_target));
    d_target.sin_family = AF_INET;
    d_target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    d_target.sin_port = htons(direct_port);

    int d_conn = connect(client_direct, (struct sockaddr *)&d_target, sizeof(d_target));
    TEST_ASSERT(d_conn == 0);

    SOCKET accepted = accept(direct_listen, NULL, NULL);
    TEST_ASSERT(accepted != INVALID_SOCKET);

    send(client_direct, "LOCAL_IPC_PING", 14, 0);
    char ipc_buf[32] = { 0 };
    int ipc_n = recv(accepted, ipc_buf, sizeof(ipc_buf) - 1, 0);
    TEST_ASSERT(ipc_n == 14);
    TEST_ASSERT(strcmp(ipc_buf, "LOCAL_IPC_PING") == 0);

    closesocket(accepted);
    closesocket(client_direct);
    closesocket(direct_listen);
    printf("      Direct loopback bypass passed!\n");

    printf("  [6] Uninstalling Hooks...\n");
    g_pxc_hooks_active = false;
    TEST_ASSERT(pxc_uninstall_winsock_hooks() == true);
    TEST_ASSERT(pxc_uninstall_dns_hooks() == true);

    pxc_fake_ip_cleanup();
    WSACleanup();

    printf("All Winsock Control-Plane Hook Tests PASSED successfully!\n");
    return 0;
}
