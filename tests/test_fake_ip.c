#include "proxychains/fake_ip.h"
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

static void test_basic_fake_ip(void) {
    pxc_fake_ip_init(198);

    struct in_addr ip1 = pxc_fake_ip_get_or_create("check.torproject.org");
    TEST_ASSERT(ip1.s_addr != INADDR_NONE);
    TEST_ASSERT(pxc_fake_ip_is_synthetic(ip1));

    uint32_t val = ntohl(ip1.s_addr);
    uint8_t b1 = (uint8_t)((val >> 24) & 0xFF);
    uint8_t b2 = (uint8_t)((val >> 16) & 0xFF);
    uint8_t b4 = (uint8_t)(val & 0xFF);
    TEST_ASSERT(b1 == 198);
    TEST_ASSERT(b2 == 18 || b2 == 19);
    TEST_ASSERT(b4 != 0 && b4 != 255);

    // Case insensitivity
    struct in_addr ip2 = pxc_fake_ip_get_or_create("CHECK.TORPROJECT.ORG");
    TEST_ASSERT(ip1.s_addr == ip2.s_addr);

    struct in_addr ip3 = pxc_fake_ip_get_or_create("Check.TorProject.Org");
    TEST_ASSERT(ip1.s_addr == ip3.s_addr);

    // Reverse lookup
    char domain_out[256];
    TEST_ASSERT(pxc_fake_ip_lookup_domain(ip1, domain_out, sizeof(domain_out)));
    TEST_ASSERT(_stricmp(domain_out, "check.torproject.org") == 0);

    TEST_ASSERT(pxc_fake_ip_count() == 1);

    // Non-synthetic IP check (loopback address)
    struct in_addr real_ip;
    inet_pton(AF_INET, "127.0.0.2", &real_ip);
    TEST_ASSERT(!pxc_fake_ip_is_synthetic(real_ip));
    TEST_ASSERT(!pxc_fake_ip_lookup_domain(real_ip, domain_out, sizeof(domain_out)));

    pxc_fake_ip_cleanup();
    TEST_ASSERT(pxc_fake_ip_count() == 0);
}

static void test_multi_domain_allocation(void) {
    pxc_fake_ip_init(198);

    #define NUM_DOMAINS 500
    struct in_addr ips[NUM_DOMAINS];
    char name[64];

    for (int i = 0; i < NUM_DOMAINS; i++) {
        snprintf(name, sizeof(name), "domain-%d.test.net", i);
        ips[i] = pxc_fake_ip_get_or_create(name);
        TEST_ASSERT(ips[i].s_addr != INADDR_NONE);
        TEST_ASSERT(pxc_fake_ip_is_synthetic(ips[i]));
    }

    TEST_ASSERT(pxc_fake_ip_count() == NUM_DOMAINS);

    // Verify all unique
    for (int i = 0; i < NUM_DOMAINS; i++) {
        for (int j = i + 1; j < NUM_DOMAINS; j++) {
            TEST_ASSERT(ips[i].s_addr != ips[j].s_addr);
        }
    }

    // Verify all reverse lookups
    char lookup[256];
    for (int i = 0; i < NUM_DOMAINS; i++) {
        snprintf(name, sizeof(name), "domain-%d.test.net", i);
        TEST_ASSERT(pxc_fake_ip_lookup_domain(ips[i], lookup, sizeof(lookup)));
        TEST_ASSERT(strcmp(lookup, name) == 0);
    }

    pxc_fake_ip_cleanup();
}

#define THREAD_COUNT 16
#define ITERATIONS_PER_THREAD 1000

static DWORD WINAPI concurrency_worker(LPVOID param) {
    int thread_id = (int)(intptr_t)param;
    char domain[64];
    char lookup[256];

    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        // Half shared domains across threads, half thread-specific domains
        if (i % 2 == 0) {
            snprintf(domain, sizeof(domain), "shared-host-%d.org", i % 20);
        } else {
            snprintf(domain, sizeof(domain), "t%d-host-%d.internal", thread_id, i);
        }

        struct in_addr ip = pxc_fake_ip_get_or_create(domain);
        TEST_ASSERT(ip.s_addr != INADDR_NONE);
        TEST_ASSERT(pxc_fake_ip_is_synthetic(ip));

        TEST_ASSERT(pxc_fake_ip_lookup_domain(ip, lookup, sizeof(lookup)));
        TEST_ASSERT(_stricmp(lookup, domain) == 0);
    }

    return 0;
}

static void test_concurrent_srwlock(void) {
    pxc_fake_ip_init(198);

    HANDLE threads[THREAD_COUNT];
    for (intptr_t i = 0; i < THREAD_COUNT; i++) {
        threads[i] = CreateThread(NULL, 0, concurrency_worker, (LPVOID)i, 0, NULL);
        TEST_ASSERT(threads[i] != NULL);
    }

    WaitForMultipleObjects(THREAD_COUNT, threads, TRUE, 10000);

    for (int i = 0; i < THREAD_COUNT; i++) {
        DWORD exit_code = 0;
        GetExitCodeThread(threads[i], &exit_code);
        TEST_ASSERT(exit_code == 0);
        CloseHandle(threads[i]);
    }

    TEST_ASSERT(pxc_fake_ip_count() > 0);
    pxc_fake_ip_cleanup();
    TEST_ASSERT(pxc_fake_ip_count() == 0);
}

int main(void) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    printf("Running In-Process Fake IP Subsystem Tests...\n");

    printf("  [1] Basic Fake IP Allocation and Reverse Lookup...\n");
    test_basic_fake_ip();

    printf("  [2] Multi-Domain Uniqueness and Reverse Verification...\n");
    test_multi_domain_allocation();

    printf("  [3] High-Concurrency Multi-Threaded SRWLOCK Stress Test...\n");
    test_concurrent_srwlock();

    WSACleanup();

    printf("All Fake IP Subsystem Tests PASSED successfully!\n");
    return 0;
}
