#ifndef PROXYCHAINS_CONFIG_H
#define PROXYCHAINS_CONFIG_H

#include "proxychains/common.h"

#define PXC_MAX_PROXIES        64
#define PXC_MAX_LOCALNET       32
#define PXC_MAX_STRING_LEN     256

typedef enum {
    PXC_PROTO_HTTP = 1,
    PXC_PROTO_SOCKS4,
    PXC_PROTO_SOCKS5
} pxc_protocol_t;

typedef enum {
    PXC_CHAIN_DYNAMIC = 1,
    PXC_CHAIN_STRICT,
    PXC_CHAIN_RANDOM,
    PXC_CHAIN_ROUND_ROBIN
} pxc_chain_type_t;

typedef struct {
    pxc_protocol_t protocol;
    char           host[PXC_MAX_STRING_LEN];
    uint16_t       port;
    char           username[PXC_MAX_STRING_LEN];
    char           password[PXC_MAX_STRING_LEN];
    bool           has_auth;
} pxc_proxy_entry_t;

typedef struct {
    struct in_addr network;
    struct in_addr netmask;
    uint16_t       port; // 0 = all ports
} pxc_localnet_entry_t;

#define PXC_TOR_USER_AGENT "Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0"
#define PXC_MAX_USER_AGENTS 16

typedef struct {
    pxc_chain_type_t     chain_type;
    uint32_t             tcp_connect_timeout_ms;
    uint32_t             tcp_read_timeout_ms;
    uint8_t              remote_dns_subnet_prefix; // e.g. 198 for 198.18.0.0/15
    bool                 quiet_mode;
    char                 nameserver[PXC_MAX_STRING_LEN];
    char                 http_user_agent[PXC_MAX_STRING_LEN];
    char                 user_agent_pool[PXC_MAX_USER_AGENTS][PXC_MAX_STRING_LEN];
    uint32_t             user_agent_pool_count;

    uint32_t             proxy_count;
    pxc_proxy_entry_t    proxies[PXC_MAX_PROXIES];

    uint32_t             localnet_count;
    pxc_localnet_entry_t localnets[PXC_MAX_LOCALNET];
} pxc_config_t;

typedef struct {
    bool ok;
    int  error_line;
    char error_message[256];
} pxc_parse_result_t;

void pxc_config_init_defaults(pxc_config_t *config);
bool pxc_config_is_tor(const pxc_config_t *config);
const char *pxc_config_get_effective_ua(const pxc_config_t *config);
pxc_parse_result_t pxc_config_parse_string(const char *content, pxc_config_t *out_config);
pxc_parse_result_t pxc_config_parse_file(const wchar_t *path, pxc_config_t *out_config);

bool pxc_config_serialize_env(const pxc_config_t *config, wchar_t *out_buf, size_t buf_chars);
bool pxc_config_deserialize_env(const wchar_t *env_val, pxc_config_t *out_config);

#endif // PROXYCHAINS_CONFIG_H
