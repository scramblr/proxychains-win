#include "proxychains/hooks.h"
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

pxc_config_t g_pxc_active_config;

static void test_getaddrinfow_interception(void) {
    PADDRINFOW res = NULL;
    ADDRINFOW hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    INT ret = GetAddrInfoW(L"check.torproject.org", L"443", &hints, &res);
    TEST_ASSERT(ret == 0);
    TEST_ASSERT(res != NULL);
    TEST_ASSERT(res->ai_family == AF_INET);
    TEST_ASSERT(res->ai_addr != NULL);

    struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
    TEST_ASSERT(ntohs(sin->sin_port) == 443);
    TEST_ASSERT(pxc_fake_ip_is_synthetic(sin->sin_addr));

    char domain_out[256];
    TEST_ASSERT(pxc_fake_ip_lookup_domain(sin->sin_addr, domain_out, sizeof(domain_out)));
    TEST_ASSERT(_stricmp(domain_out, "check.torproject.org") == 0);

    FreeAddrInfoW(res);
}

static void test_getaddrinfoexw_interception(void) {
    PADDRINFOEXW res = NULL;
    ADDRINFOEXW hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    INT ret = GetAddrInfoExW(L"2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion", L"80", NS_ALL, NULL, &hints, &res, NULL, NULL, NULL, NULL);
    TEST_ASSERT(ret == 0);
    TEST_ASSERT(res != NULL);
    TEST_ASSERT(res->ai_family == AF_INET);
    TEST_ASSERT(res->ai_addr != NULL);

    struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
    TEST_ASSERT(ntohs(sin->sin_port) == 80);
    TEST_ASSERT(pxc_fake_ip_is_synthetic(sin->sin_addr));

    char domain_out[256];
    TEST_ASSERT(pxc_fake_ip_lookup_domain(sin->sin_addr, domain_out, sizeof(domain_out)));
    TEST_ASSERT(_stricmp(domain_out, "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion") == 0);

    FreeAddrInfoExW(res);
}

static void test_getaddrinfo_ansi_interception(void) {
    struct addrinfo *res = NULL;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int ret = getaddrinfo("ntppool.org", "http", &hints, &res);
    TEST_ASSERT(ret == 0);
    TEST_ASSERT(res != NULL);
    TEST_ASSERT(res->ai_family == AF_INET);

    struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
    TEST_ASSERT(ntohs(sin->sin_port) == 80);
    TEST_ASSERT(pxc_fake_ip_is_synthetic(sin->sin_addr));

    char domain_out[256];
    TEST_ASSERT(pxc_fake_ip_lookup_domain(sin->sin_addr, domain_out, sizeof(domain_out)));
    TEST_ASSERT(_stricmp(domain_out, "ntppool.org") == 0);

    freeaddrinfo(res);
}

static void test_gethostbyname_interception(void) {
    struct hostent *he = gethostbyname("duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion");
    TEST_ASSERT(he != NULL);
    TEST_ASSERT(he->h_addrtype == AF_INET);
    TEST_ASSERT(he->h_addr_list != NULL);
    TEST_ASSERT(he->h_addr_list[0] != NULL);

    struct in_addr *ip = (struct in_addr *)he->h_addr_list[0];
    TEST_ASSERT(pxc_fake_ip_is_synthetic(*ip));

    char domain_out[256];
    TEST_ASSERT(pxc_fake_ip_lookup_domain(*ip, domain_out, sizeof(domain_out)));
    TEST_ASSERT(_stricmp(domain_out, "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion") == 0);
}

static void test_ip_passthrough(void) {
    PADDRINFOW res = NULL;
    INT ret = GetAddrInfoW(L"127.0.0.1", L"8080", NULL, &res);
    TEST_ASSERT(ret == 0);
    TEST_ASSERT(res != NULL);

    struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
    TEST_ASSERT(!pxc_fake_ip_is_synthetic(sin->sin_addr));
    TEST_ASSERT(sin->sin_addr.s_addr == htonl(INADDR_LOOPBACK));

    FreeAddrInfoW(res);
}

static void test_clearnet_and_onion_synthetic_resolution(void) {
    const char *test_domains[] = {
        "check.torproject.org",
        "ntppool.org",
        "ip.urls.is",
        "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion",
        "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
    };

    for (size_t i = 0; i < sizeof(test_domains) / sizeof(test_domains[0]); i++) {
        struct addrinfo *res = NULL;
        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        int ret = getaddrinfo(test_domains[i], "https", &hints, &res);
        TEST_ASSERT(ret == 0);
        TEST_ASSERT(res != NULL);
        TEST_ASSERT(res->ai_family == AF_INET);

        struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
        TEST_ASSERT(ntohs(sin->sin_port) == 443);
        TEST_ASSERT(pxc_fake_ip_is_synthetic(sin->sin_addr));

        char domain_out[256];
        TEST_ASSERT(pxc_fake_ip_lookup_domain(sin->sin_addr, domain_out, sizeof(domain_out)));
        TEST_ASSERT(_stricmp(domain_out, test_domains[i]) == 0);

        freeaddrinfo(res);
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    printf("Running Windows DNS API Interception Tests...\n");

    pxc_fake_ip_init(198);

    printf("  [1] Installing DNS Hooks via Detours...\n");
    TEST_ASSERT(pxc_install_dns_hooks() == true);

    printf("  [2] Intercepting GetAddrInfoW (Unicode DNS)...\n");
    test_getaddrinfow_interception();
    printf("      GetAddrInfoW passed!\n");

    printf("  [3] Intercepting GetAddrInfoExW (Async/Extended DNS)...\n");
    test_getaddrinfoexw_interception();
    printf("      GetAddrInfoExW passed!\n");

    printf("  [4] Intercepting getaddrinfo (ANSI DNS)...\n");
    test_getaddrinfo_ansi_interception();
    printf("      getaddrinfo passed!\n");

    printf("  [5] Intercepting gethostbyname (Legacy ANSI DNS)...\n");
    test_gethostbyname_interception();
    printf("      gethostbyname passed!\n");

    printf("  [6] Direct IP / Localhost Passthrough...\n");
    test_ip_passthrough();
    printf("      Direct IP passed!\n");

    printf("  [7] Clearnet and .onion Synthetic Resolution (Zero External Leaks)...\n");
    test_clearnet_and_onion_synthetic_resolution();
    printf("      Synthetic resolution passed!\n");

    printf("  [8] Uninstalling DNS Hooks...\n");
    TEST_ASSERT(pxc_uninstall_dns_hooks() == true);
    printf("      Uninstall passed!\n");

    pxc_fake_ip_cleanup();
    WSACleanup();

    printf("All Windows DNS Interception Tests PASSED successfully!\n");
    return 0;
}
