#ifndef PROXYCHAINS_FAKE_IP_H
#define PROXYCHAINS_FAKE_IP_H

#include "proxychains/common.h"
#include "proxychains/config.h"

// Initialize fake IP table subsystem
void pxc_fake_ip_init(uint8_t subnet_prefix);

// Cleanup and free all allocated entries in the fake IP table
void pxc_fake_ip_cleanup(void);

// Given a domain name, returns synthetic IPv4 address (198.18.x.x)
// Case-insensitive. Thread-safe.
struct in_addr pxc_fake_ip_get_or_create(const char *domain);

// Given an IPv4 address, checks if it is in the synthetic range and returns original domain name
// Returns true if found and copied into out_domain; false otherwise.
bool pxc_fake_ip_lookup_domain(struct in_addr ip, char *out_domain, size_t max_len);

// Check if an IP is within the synthetic IP subnet (198.18.0.0/15)
bool pxc_fake_ip_is_synthetic(struct in_addr ip);

// Get current registered domain count
size_t pxc_fake_ip_count(void);

#endif // PROXYCHAINS_FAKE_IP_H
