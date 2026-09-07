#include "proxychains/fake_ip.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define PXC_HASH_BUCKETS 2048

typedef struct pxc_fake_ip_entry {
    char                      domain[PXC_MAX_STRING_LEN];
    struct in_addr            ip;
    struct pxc_fake_ip_entry *next_domain;
    struct pxc_fake_ip_entry *next_ip;
} pxc_fake_ip_entry_t;

static SRWLOCK              g_srwlock = SRWLOCK_INIT;
static pxc_fake_ip_entry_t *g_domain_buckets[PXC_HASH_BUCKETS] = { 0 };
static pxc_fake_ip_entry_t *g_ip_buckets[PXC_HASH_BUCKETS]     = { 0 };
static size_t               g_entry_count                      = 0;
static uint32_t             g_ip_index                         = 0;
static uint8_t              g_subnet_prefix                    = 198;
static bool                 g_initialized                      = false;

static uint32_t hash_domain(const char *str) {
    uint32_t hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) + (uint32_t)tolower((unsigned char)*str);
        str++;
    }
    return hash % PXC_HASH_BUCKETS;
}

static uint32_t hash_ip(struct in_addr ip) {
    uint32_t h = ip.s_addr;
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    return h % PXC_HASH_BUCKETS;
}

void pxc_fake_ip_init(uint8_t subnet_prefix) {
    AcquireSRWLockExclusive(&g_srwlock);
    g_subnet_prefix = (subnet_prefix == 0) ? 198 : subnet_prefix;
    g_initialized = true;
    ReleaseSRWLockExclusive(&g_srwlock);
}

void pxc_fake_ip_cleanup(void) {
    AcquireSRWLockExclusive(&g_srwlock);
    for (size_t i = 0; i < PXC_HASH_BUCKETS; i++) {
        pxc_fake_ip_entry_t *entry = g_domain_buckets[i];
        while (entry) {
            pxc_fake_ip_entry_t *next = entry->next_domain;
            free(entry);
            entry = next;
        }
        g_domain_buckets[i] = NULL;
        g_ip_buckets[i] = NULL;
    }
    g_entry_count = 0;
    g_ip_index = 0;
    ReleaseSRWLockExclusive(&g_srwlock);
}

bool pxc_fake_ip_is_synthetic(struct in_addr ip) {
    uint32_t host_val = ntohl(ip.s_addr);
    uint8_t b1 = (uint8_t)((host_val >> 24) & 0xFF);
    uint8_t b2 = (uint8_t)((host_val >> 16) & 0xFF);

    // Matches subnet prefix (default 198) and RFC 6890 /15 range: 18 or 19
    if (b1 == g_subnet_prefix) {
        if (g_subnet_prefix == 198) {
            return (b2 == 18 || b2 == 19);
        }
        return true;
    }
    return false;
}

struct in_addr pxc_fake_ip_get_or_create(const char *domain) {
    struct in_addr invalid_ip;
    invalid_ip.s_addr = INADDR_NONE;

    if (!domain || domain[0] == '\0') return invalid_ip;
    size_t len = strlen(domain);
    if (len >= PXC_MAX_STRING_LEN) return invalid_ip;

    uint32_t d_bucket = hash_domain(domain);

    // 1. Shared read lock lookup
    AcquireSRWLockShared(&g_srwlock);
    pxc_fake_ip_entry_t *curr = g_domain_buckets[d_bucket];
    while (curr) {
        if (_stricmp(curr->domain, domain) == 0) {
            struct in_addr result = curr->ip;
            ReleaseSRWLockShared(&g_srwlock);
            return result;
        }
        curr = curr->next_domain;
    }
    ReleaseSRWLockShared(&g_srwlock);

    // 2. Exclusive write lock for creation
    AcquireSRWLockExclusive(&g_srwlock);

    // Double-check if another thread inserted while acquiring exclusive lock
    curr = g_domain_buckets[d_bucket];
    while (curr) {
        if (_stricmp(curr->domain, domain) == 0) {
            struct in_addr result = curr->ip;
            ReleaseSRWLockExclusive(&g_srwlock);
            return result;
        }
        curr = curr->next_domain;
    }

    // Allocate new IP from 198.18.0.0/15
    uint32_t idx = g_ip_index++;
    uint8_t octet1 = g_subnet_prefix;
    uint8_t octet2 = (uint8_t)(18 + ((idx / (256 * 254)) % 2));
    uint8_t octet3 = (uint8_t)((idx / 254) % 256);
    uint8_t octet4 = (uint8_t)(1 + (idx % 254)); // 1..254

    struct in_addr new_ip;
    new_ip.s_addr = htonl(((uint32_t)octet1 << 24) |
                          ((uint32_t)octet2 << 16) |
                          ((uint32_t)octet3 << 8)  |
                          (uint32_t)octet4);

    pxc_fake_ip_entry_t *new_entry = (pxc_fake_ip_entry_t *)malloc(sizeof(pxc_fake_ip_entry_t));
    if (!new_entry) {
        ReleaseSRWLockExclusive(&g_srwlock);
        return invalid_ip;
    }

    strncpy_s(new_entry->domain, sizeof(new_entry->domain), domain, _TRUNCATE);
    new_entry->ip = new_ip;

    // Insert into domain hash table
    new_entry->next_domain = g_domain_buckets[d_bucket];
    g_domain_buckets[d_bucket] = new_entry;

    // Insert into IP hash table
    uint32_t ip_bucket = hash_ip(new_ip);
    new_entry->next_ip = g_ip_buckets[ip_bucket];
    g_ip_buckets[ip_bucket] = new_entry;

    g_entry_count++;

    ReleaseSRWLockExclusive(&g_srwlock);
    return new_ip;
}

bool pxc_fake_ip_lookup_domain(struct in_addr ip, char *out_domain, size_t max_len) {
    if (!out_domain || max_len == 0) return false;
    if (!pxc_fake_ip_is_synthetic(ip)) return false;

    uint32_t ip_bucket = hash_ip(ip);

    AcquireSRWLockShared(&g_srwlock);
    pxc_fake_ip_entry_t *curr = g_ip_buckets[ip_bucket];
    while (curr) {
        if (curr->ip.s_addr == ip.s_addr) {
            strncpy_s(out_domain, max_len, curr->domain, _TRUNCATE);
            ReleaseSRWLockShared(&g_srwlock);
            return true;
        }
        curr = curr->next_ip;
    }
    ReleaseSRWLockShared(&g_srwlock);

    return false;
}

size_t pxc_fake_ip_count(void) {
    AcquireSRWLockShared(&g_srwlock);
    size_t count = g_entry_count;
    ReleaseSRWLockShared(&g_srwlock);
    return count;
}
