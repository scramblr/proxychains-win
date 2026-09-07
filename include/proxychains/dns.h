#ifndef PROXYCHAINS_DNS_H
#define PROXYCHAINS_DNS_H

#include "proxychains/common.h"

bool pxc_dns_resolve_udp(const char *domain, const char *nameserver, struct in_addr *out_ip);

#endif // PROXYCHAINS_DNS_H
