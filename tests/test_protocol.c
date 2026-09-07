#include "proxychains/protocol.h"
#include "proxychains/config.h"
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

static void test_base64(void) {
    char dst[128];

    // RFC 4648 test vectors
    TEST_ASSERT(pxc_base64_encode((const unsigned char *)"", 0, dst, sizeof(dst)));
    TEST_ASSERT(strcmp(dst, "") == 0);

    TEST_ASSERT(pxc_base64_encode((const unsigned char *)"f", 1, dst, sizeof(dst)));
    TEST_ASSERT(strcmp(dst, "Zg==") == 0);

    TEST_ASSERT(pxc_base64_encode((const unsigned char *)"fo", 2, dst, sizeof(dst)));
    TEST_ASSERT(strcmp(dst, "Zm8=") == 0);

    TEST_ASSERT(pxc_base64_encode((const unsigned char *)"foo", 3, dst, sizeof(dst)));
    TEST_ASSERT(strcmp(dst, "Zm9v") == 0);

    TEST_ASSERT(pxc_base64_encode((const unsigned char *)"foob", 4, dst, sizeof(dst)));
    TEST_ASSERT(strcmp(dst, "Zm9vYg==") == 0);

    TEST_ASSERT(pxc_base64_encode((const unsigned char *)"fooba", 5, dst, sizeof(dst)));
    TEST_ASSERT(strcmp(dst, "Zm9vYmE=") == 0);

    TEST_ASSERT(pxc_base64_encode((const unsigned char *)"foobar", 6, dst, sizeof(dst)));
    TEST_ASSERT(strcmp(dst, "Zm9vYmFy") == 0);

    // Auth credentials vector
    TEST_ASSERT(pxc_base64_encode((const unsigned char *)"admin:secret123", 15, dst, sizeof(dst)));
    TEST_ASSERT(strcmp(dst, "YWRtaW46c2VjcmV0MTIz") == 0);

    // Buffer too small check
    TEST_ASSERT(!pxc_base64_encode((const unsigned char *)"foobar", 6, dst, 8)); // needs 9 bytes (8 + null)
    TEST_ASSERT(pxc_base64_encode((const unsigned char *)"foobar", 6, dst, 9));
}

static void test_endpoints(void) {
    pxc_endpoint_t ep;
    char str[128];

    // IPv4
    struct in_addr v4;
    inet_pton(AF_INET, "192.168.1.50", &v4);
    pxc_endpoint_from_ipv4(&ep, v4, 8080);
    TEST_ASSERT(ep.type == PXC_ADDR_IPV4);
    TEST_ASSERT(ep.port == 8080);
    TEST_ASSERT(pxc_endpoint_to_string(&ep, str, sizeof(str)));
    TEST_ASSERT(strcmp(str, "192.168.1.50:8080") == 0);

    // IPv6
    struct in6_addr v6;
    inet_pton(AF_INET6, "2001:db8::1", &v6);
    pxc_endpoint_from_ipv6(&ep, &v6, 443);
    TEST_ASSERT(ep.type == PXC_ADDR_IPV6);
    TEST_ASSERT(ep.port == 443);
    TEST_ASSERT(pxc_endpoint_to_string(&ep, str, sizeof(str)));
    TEST_ASSERT(strcmp(str, "[2001:db8::1]:443") == 0);

    // Domain
    TEST_ASSERT(pxc_endpoint_from_domain(&ep, "example.org", 9000));
    TEST_ASSERT(ep.type == PXC_ADDR_DOMAIN);
    TEST_ASSERT(ep.port == 9000);
    TEST_ASSERT(strcmp(ep.addr.domain, "example.org") == 0);
    TEST_ASSERT(pxc_endpoint_to_string(&ep, str, sizeof(str)));
    TEST_ASSERT(strcmp(str, "example.org:9000") == 0);

    // Invalid domain
    TEST_ASSERT(!pxc_endpoint_from_domain(&ep, "", 80));
    TEST_ASSERT(!pxc_endpoint_from_domain(&ep, NULL, 80));
}

static void test_status_strings(void) {
    TEST_ASSERT(strcmp(pxc_status_to_string(PXC_STATUS_SUCCESS), "Success") == 0);
    TEST_ASSERT(strcmp(pxc_status_to_string(PXC_STATUS_CONN_REFUSED), "Connection Refused") == 0);
    TEST_ASSERT(strcmp(pxc_status_to_string(PXC_STATUS_AUTH_FAILED), "Authentication Failed") == 0);
    TEST_ASSERT(strcmp(pxc_status_to_string(PXC_STATUS_NET_UNREACHABLE), "Network Unreachable") == 0);
    TEST_ASSERT(strcmp(pxc_status_to_string(PXC_STATUS_TIMEDOUT), "Connection Timed Out") == 0);
    TEST_ASSERT(strcmp(pxc_status_to_string(PXC_STATUS_PROTOCOL_ERROR), "Protocol Error") == 0);
    TEST_ASSERT(strcmp(pxc_status_to_string(PXC_STATUS_SOCKET_ERROR), "Socket Error") == 0);
}

// Mock Server Infrastructure for In-Process Testing
typedef enum {
    MOCK_SOCKS4_OK,
    MOCK_SOCKS4_FAIL,
    MOCK_SOCKS5_NOAUTH_OK,
    MOCK_SOCKS5_AUTH_OK,
    MOCK_SOCKS5_AUTH_FAIL,
    MOCK_HTTP_OK,
    MOCK_HTTP_407,
    MOCK_HTTP_502
} mock_scenario_t;

typedef struct {
    mock_scenario_t scenario;
    uint16_t        port;
    HANDLE          ready_event;
} mock_server_ctx_t;

static DWORD WINAPI mock_server_thread(LPVOID param) {
    mock_server_ctx_t *ctx = (mock_server_ctx_t *)param;
    mock_scenario_t scenario = ctx->scenario;

    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        free(ctx);
        return 1;
    }

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind_addr.sin_port = 0; // Ephemeral port

    if (bind(listen_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) != 0) {
        closesocket(listen_sock);
        free(ctx);
        return 1;
    }

    int addr_len = sizeof(bind_addr);
    getsockname(listen_sock, (struct sockaddr *)&bind_addr, &addr_len);
    ctx->port = ntohs(bind_addr.sin_port);

    if (listen(listen_sock, 1) != 0) {
        closesocket(listen_sock);
        free(ctx);
        return 1;
    }

    SetEvent(ctx->ready_event);

    SOCKET client_sock = accept(listen_sock, NULL, NULL);
    closesocket(listen_sock);
    if (client_sock == INVALID_SOCKET) {
        free(ctx);
        return 1;
    }

    uint8_t buf[2048];

    switch (scenario) {
        case MOCK_SOCKS4_OK: {
            int n = recv(client_sock, (char *)buf, sizeof(buf), 0);
            if (n >= 8 && buf[0] == 0x04 && buf[1] == 0x01) {
                uint8_t resp[8] = { 0x00, 90, 0x00, 0x50, 0x7f, 0x00, 0x00, 0x01 };
                send(client_sock, (char *)resp, 8, 0);
            }
            break;
        }
        case MOCK_SOCKS4_FAIL: {
            recv(client_sock, (char *)buf, sizeof(buf), 0);
            uint8_t resp[8] = { 0x00, 91, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            send(client_sock, (char *)resp, 8, 0);
            break;
        }
        case MOCK_SOCKS5_NOAUTH_OK: {
            int n = recv(client_sock, (char *)buf, sizeof(buf), 0);
            if (n >= 3 && buf[0] == 0x05) {
                uint8_t greet_resp[2] = { 0x05, 0x00 }; // No auth
                send(client_sock, (char *)greet_resp, 2, 0);

                n = recv(client_sock, (char *)buf, sizeof(buf), 0);
                if (n >= 7 && buf[0] == 0x05 && buf[1] == 0x01) {
                    uint8_t conn_resp[10] = { 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90 };
                    send(client_sock, (char *)conn_resp, 10, 0);
                }
            }
            break;
        }
        case MOCK_SOCKS5_AUTH_OK: {
            int n = recv(client_sock, (char *)buf, sizeof(buf), 0);
            if (n >= 4 && buf[0] == 0x05) {
                uint8_t greet_resp[2] = { 0x05, 0x02 }; // User/pass auth
                send(client_sock, (char *)greet_resp, 2, 0);

                n = recv(client_sock, (char *)buf, sizeof(buf), 0);
                if (n >= 3 && buf[0] == 0x01) {
                    uint8_t auth_resp[2] = { 0x01, 0x00 }; // Success
                    send(client_sock, (char *)auth_resp, 2, 0);

                    n = recv(client_sock, (char *)buf, sizeof(buf), 0);
                    if (n >= 7 && buf[0] == 0x05 && buf[1] == 0x01) {
                        uint8_t conn_resp[10] = { 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90 };
                        send(client_sock, (char *)conn_resp, 10, 0);
                    }
                }
            }
            break;
        }
        case MOCK_SOCKS5_AUTH_FAIL: {
            int n = recv(client_sock, (char *)buf, sizeof(buf), 0);
            if (n >= 4 && buf[0] == 0x05) {
                uint8_t greet_resp[2] = { 0x05, 0x02 };
                send(client_sock, (char *)greet_resp, 2, 0);

                n = recv(client_sock, (char *)buf, sizeof(buf), 0);
                if (n >= 3 && buf[0] == 0x01) {
                    uint8_t auth_resp[2] = { 0x01, 0x01 }; // Auth failure
                    send(client_sock, (char *)auth_resp, 2, 0);
                }
            }
            break;
        }
        case MOCK_HTTP_OK: {
            int n = recv(client_sock, (char *)buf, sizeof(buf) - 1, 0);
            if (n > 0) {
                buf[n] = '\0';
                if (strstr((char *)buf, "CONNECT") != NULL && strstr((char *)buf, "User-Agent: ") != NULL) {
                    const char *resp = "HTTP/1.1 200 Connection Established\r\nProxy-Agent: MockProxy/1.0\r\n\r\n";
                    send(client_sock, resp, (int)strlen(resp), 0);
                }
            }
            break;
        }
        case MOCK_HTTP_407: {
            int n = recv(client_sock, (char *)buf, sizeof(buf) - 1, 0);
            if (n > 0) {
                const char *resp = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n";
                send(client_sock, resp, (int)strlen(resp), 0);
            }
            break;
        }
        case MOCK_HTTP_502: {
            int n = recv(client_sock, (char *)buf, sizeof(buf) - 1, 0);
            if (n > 0) {
                const char *resp = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
                send(client_sock, resp, (int)strlen(resp), 0);
            }
            break;
        }
    }

    char drain[64];
    while (recv(client_sock, drain, sizeof(drain), 0) > 0) {}
    closesocket(client_sock);
    free(ctx);
    return 0;
}

static SOCKET connect_to_mock(mock_scenario_t scenario, HANDLE *out_thread) {
    mock_server_ctx_t *ctx = (mock_server_ctx_t *)malloc(sizeof(mock_server_ctx_t));
    TEST_ASSERT(ctx != NULL);
    ctx->scenario = scenario;
    ctx->port = 0;
    ctx->ready_event = CreateEventW(NULL, TRUE, FALSE, NULL);

    HANDLE thread = CreateThread(NULL, 0, mock_server_thread, ctx, 0, NULL);
    TEST_ASSERT(thread != NULL);
    *out_thread = thread;

    WaitForSingleObject(ctx->ready_event, 5000);
    uint16_t port = ctx->port;
    CloseHandle(ctx->ready_event);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    TEST_ASSERT(sock != INVALID_SOCKET);

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    saddr.sin_port = htons(port);

    pxc_status_t st = pxc_timed_connect(sock, (struct sockaddr *)&saddr, sizeof(saddr), 3000);
    TEST_ASSERT(st == PXC_STATUS_SUCCESS);

    return sock;
}

static void test_mock_socks4(void) {
    HANDLE thread = NULL;
    SOCKET sock = connect_to_mock(MOCK_SOCKS4_OK, &thread);

    pxc_endpoint_t ep;
    struct in_addr v4;
    inet_pton(AF_INET, "10.0.0.1", &v4);
    pxc_endpoint_from_ipv4(&ep, v4, 80);

    pxc_status_t st = pxc_socks4_handshake(sock, &ep, "testuser", 3000);
    TEST_ASSERT(st == PXC_STATUS_SUCCESS);

    closesocket(sock);
    WaitForSingleObject(thread, 3000);
    CloseHandle(thread);

    // Test SOCKS4 fail
    sock = connect_to_mock(MOCK_SOCKS4_FAIL, &thread);
    st = pxc_socks4_handshake(sock, &ep, "testuser", 3000);
    TEST_ASSERT(st == PXC_STATUS_CONN_REFUSED);

    closesocket(sock);
    WaitForSingleObject(thread, 3000);
    CloseHandle(thread);
}

static void test_mock_socks5(void) {
    HANDLE thread = NULL;
    // SOCKS5 without auth
    SOCKET sock = connect_to_mock(MOCK_SOCKS5_NOAUTH_OK, &thread);
    pxc_endpoint_t ep;
    pxc_endpoint_from_domain(&ep, "check.torproject.org", 443);

    pxc_status_t st = pxc_socks5_handshake(sock, &ep, NULL, NULL, 3000);
    TEST_ASSERT(st == PXC_STATUS_SUCCESS);

    closesocket(sock);
    WaitForSingleObject(thread, 3000);
    CloseHandle(thread);

    // SOCKS5 with auth
    sock = connect_to_mock(MOCK_SOCKS5_AUTH_OK, &thread);
    st = pxc_socks5_handshake(sock, &ep, "alice", "supersecret", 3000);
    TEST_ASSERT(st == PXC_STATUS_SUCCESS);

    closesocket(sock);
    WaitForSingleObject(thread, 3000);
    CloseHandle(thread);

    // SOCKS5 auth fail
    sock = connect_to_mock(MOCK_SOCKS5_AUTH_FAIL, &thread);
    st = pxc_socks5_handshake(sock, &ep, "alice", "wrongpw", 3000);
    TEST_ASSERT(st == PXC_STATUS_AUTH_FAILED);

    closesocket(sock);
    WaitForSingleObject(thread, 3000);
    CloseHandle(thread);
}

static void test_mock_http(void) {
    HANDLE thread = NULL;
    // HTTP OK
    SOCKET sock = connect_to_mock(MOCK_HTTP_OK, &thread);
    pxc_endpoint_t ep;
    pxc_endpoint_from_domain(&ep, "secure.site.com", 443);

    pxc_status_t st = pxc_http_handshake(sock, &ep, "bob", "pwd123", PXC_TOR_USER_AGENT, 3000);
    TEST_ASSERT(st == PXC_STATUS_SUCCESS);

    closesocket(sock);
    WaitForSingleObject(thread, 3000);
    CloseHandle(thread);

    // HTTP 407
    sock = connect_to_mock(MOCK_HTTP_407, &thread);
    st = pxc_http_handshake(sock, &ep, NULL, NULL, NULL, 3000);
    TEST_ASSERT(st == PXC_STATUS_AUTH_FAILED);

    closesocket(sock);
    WaitForSingleObject(thread, 3000);
    CloseHandle(thread);

    // HTTP 502
    sock = connect_to_mock(MOCK_HTTP_502, &thread);
    st = pxc_http_handshake(sock, &ep, NULL, NULL, "Custom-UA/1.0", 3000);
    TEST_ASSERT(st == PXC_STATUS_NET_UNREACHABLE);

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

    printf("Running Protocol Core Tests...\n");

    printf("  [1] Base64 Encoding...\n");
    test_base64();

    printf("  [2] Endpoints and String Formatting...\n");
    test_endpoints();

    printf("  [3] Status Strings...\n");
    test_status_strings();

    printf("  [4] SOCKS4 / SOCKS4a Handshake...\n");
    test_mock_socks4();

    printf("  [5] SOCKS5 Handshake (No Auth, Auth OK, Auth Fail)...\n");
    test_mock_socks5();

    printf("  [6] HTTP CONNECT Handshake (200 OK, 407 Auth, 502 Gateway)...\n");
    test_mock_http();

    WSACleanup();

    printf("All Protocol Core Tests PASSED successfully!\n");
    return 0;
}
