#include "proxychains/dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool pxc_dns_resolve_udp(const char *domain, const char *nameserver, struct in_addr *out_ip) {
    if (!domain || !nameserver || !out_ip) return false;

    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return false;

    DWORD timeout_ms = 3000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_ms, sizeof(timeout_ms));

    struct sockaddr_in ns_addr;
    memset(&ns_addr, 0, sizeof(ns_addr));
    ns_addr.sin_family = AF_INET;
    ns_addr.sin_port = htons(53);
    if (inet_pton(AF_INET, nameserver, &ns_addr.sin_addr) != 1) {
        closesocket(s);
        return false;
    }

    uint8_t packet[512];
    memset(packet, 0, sizeof(packet));

    uint16_t tx_id = (uint16_t)(GetCurrentProcessId() ^ (uint32_t)GetTickCount());
    packet[0] = (uint8_t)(tx_id >> 8);
    packet[1] = (uint8_t)(tx_id & 0xFF);
    packet[2] = 0x01; // Recursion Desired (RD = 1)
    packet[3] = 0x00;
    packet[4] = 0x00;
    packet[5] = 0x01; // QDCOUNT = 1

    size_t pos = 12;
    const char *p = domain;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        if (len == 0 || len > 63 || pos + len + 1 >= sizeof(packet)) {
            closesocket(s);
            return false;
        }
        packet[pos++] = (uint8_t)len;
        memcpy(&packet[pos], p, len);
        pos += len;
        if (!dot) break;
        p = dot + 1;
    }
    packet[pos++] = 0x00;

    // QTYPE = 1 (A), QCLASS = 1 (IN)
    packet[pos++] = 0x00; packet[pos++] = 0x01;
    packet[pos++] = 0x00; packet[pos++] = 0x01;

    int sent = sendto(s, (const char *)packet, (int)pos, 0, (struct sockaddr *)&ns_addr, sizeof(ns_addr));
    if (sent <= 0) {
        closesocket(s);
        return false;
    }

    uint8_t resp[1024];
    int recvd = recvfrom(s, (char *)resp, sizeof(resp), 0, NULL, NULL);
    closesocket(s);

    if (recvd < 12) return false;

    // Check ID, QR bit (bit 7 of resp[2]), and RCODE (lower 4 bits of resp[3])
    uint16_t resp_id = (uint16_t)((resp[0] << 8) | resp[1]);
    if (resp_id != tx_id) return false;
    if ((resp[2] & 0x80) == 0) return false; // Not a response
    if ((resp[3] & 0x0F) != 0) return false; // RCODE != NOERROR

    uint16_t ancount = (uint16_t)((resp[6] << 8) | resp[7]);
    if (ancount == 0) return false;

    // Skip question section
    size_t cur = 12;
    while (cur < (size_t)recvd && resp[cur] != 0) {
        if ((resp[cur] & 0xC0) == 0xC0) {
            cur += 2;
            goto question_done;
        }
        cur += 1 + resp[cur];
    }
    if (cur < (size_t)recvd && resp[cur] == 0) cur++;
question_done:
    cur += 4; // Skip QTYPE and QCLASS

    // Walk answers
    for (uint16_t a = 0; a < ancount && cur + 10 <= (size_t)recvd; a++) {
        // Skip NAME field
        if ((resp[cur] & 0xC0) == 0xC0) {
            cur += 2;
        } else {
            while (cur < (size_t)recvd && resp[cur] != 0) {
                cur += 1 + resp[cur];
            }
            if (cur < (size_t)recvd) cur++;
        }

        if (cur + 10 > (size_t)recvd) break;

        uint16_t atype = (uint16_t)((resp[cur] << 8) | resp[cur + 1]);
        uint16_t aclass = (uint16_t)((resp[cur + 2] << 8) | resp[cur + 3]);
        uint16_t rdlen = (uint16_t)((resp[cur + 8] << 8) | resp[cur + 9]);
        cur += 10;

        if (cur + rdlen > (size_t)recvd) break;

        if (atype == 1 && aclass == 1 && rdlen == 4) {
            memcpy(out_ip, &resp[cur], 4);
            return true;
        }
        cur += rdlen;
    }

    return false;
}
