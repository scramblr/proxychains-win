#include "proxychains/config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static int g_test_count = 0;
static int g_pass_count = 0;

#define TEST_ASSERT(cond, msg) do { \
    g_test_count++; \
    if (cond) { \
        g_pass_count++; \
    } else { \
        printf("  FAILED: %s (line %d)\n", msg, __LINE__); \
        return 1; \
    } \
} while(0)

static int test_valid_strict_config(void) {
    const char *conf =
        "# Global comments\n"
        "strict_chain\n"
        "tcp_connect_time_out 8000\n"
        "tcp_read_time_out 3500\n"
        "remote_dns_subnet 198\n"
        "quiet_mode\n"
        "\n"
        "[ProxyList]\n"
        "socks5 127.0.0.1 1080 admin secret123\n"
        "http   192.168.1.10 8080\n"
        "socks4 10.0.0.1 9050\n";

    pxc_config_t cfg;
    pxc_parse_result_t res = pxc_config_parse_string(conf, &cfg);

    TEST_ASSERT(res.ok == true, "Expected valid parse result");
    TEST_ASSERT(cfg.chain_type == PXC_CHAIN_STRICT, "Expected strict chain");
    TEST_ASSERT(cfg.tcp_connect_timeout_ms == 8000, "Expected 8000ms connect timeout");
    TEST_ASSERT(cfg.tcp_read_timeout_ms == 3500, "Expected 3500ms read timeout");
    TEST_ASSERT(cfg.remote_dns_subnet_prefix == 198, "Expected 198 subnet prefix");
    TEST_ASSERT(cfg.quiet_mode == true, "Expected quiet mode enabled");
    TEST_ASSERT(cfg.nameserver[0] == '\0', "Expected empty nameserver by default");
    TEST_ASSERT(cfg.proxy_count == 3, "Expected 3 proxies");

    // Check Proxy 1 (SOCKS5 + auth)
    TEST_ASSERT(cfg.proxies[0].protocol == PXC_PROTO_SOCKS5, "Proxy 1 protocol SOCKS5");
    TEST_ASSERT(strcmp(cfg.proxies[0].host, "127.0.0.1") == 0, "Proxy 1 host");
    TEST_ASSERT(cfg.proxies[0].port == 1080, "Proxy 1 port");
    TEST_ASSERT(cfg.proxies[0].has_auth == true, "Proxy 1 has auth");
    TEST_ASSERT(strcmp(cfg.proxies[0].username, "admin") == 0, "Proxy 1 username");
    TEST_ASSERT(strcmp(cfg.proxies[0].password, "secret123") == 0, "Proxy 1 password");

    // Check Proxy 2 (HTTP)
    TEST_ASSERT(cfg.proxies[1].protocol == PXC_PROTO_HTTP, "Proxy 2 protocol HTTP");
    TEST_ASSERT(strcmp(cfg.proxies[1].host, "192.168.1.10") == 0, "Proxy 2 host");
    TEST_ASSERT(cfg.proxies[1].port == 8080, "Proxy 2 port");
    TEST_ASSERT(cfg.proxies[1].has_auth == false, "Proxy 2 has no auth");

    // Check Proxy 3 (SOCKS4)
    TEST_ASSERT(cfg.proxies[2].protocol == PXC_PROTO_SOCKS4, "Proxy 3 protocol SOCKS4");
    TEST_ASSERT(strcmp(cfg.proxies[2].host, "10.0.0.1") == 0, "Proxy 3 host");
    TEST_ASSERT(cfg.proxies[2].port == 9050, "Proxy 3 port");

    return 0;
}

static int test_reject_overflow_token(void) {
    char long_token[600];
    memset(long_token, 'A', 500);
    long_token[500] = '\0';

    char conf[1024];
    snprintf(conf, sizeof(conf), "[ProxyList]\nsocks5 127.0.0.1 1080 %s password\n", long_token);

    pxc_config_t cfg;
    pxc_parse_result_t res = pxc_config_parse_string(conf, &cfg);

    // Bounded parser must reject token exceeding buffer capacity gracefully
    TEST_ASSERT(res.ok == false, "Expected parser to reject token > 255 chars");
    return 0;
}

static int test_reject_invalid_port(void) {
    const char *conf = "[ProxyList]\nsocks5 127.0.0.1 99999\n";
    pxc_config_t cfg;
    pxc_parse_result_t res = pxc_config_parse_string(conf, &cfg);

    TEST_ASSERT(res.ok == false, "Expected parser to reject port 99999");
    TEST_ASSERT(res.error_line > 0, "Expected non-zero error line number");
    return 0;
}

static int test_reject_unknown_protocol(void) {
    const char *conf = "[ProxyList]\ntor 127.0.0.1 9050\n";
    pxc_config_t cfg;
    pxc_parse_result_t res = pxc_config_parse_string(conf, &cfg);

    TEST_ASSERT(res.ok == false, "Expected parser to reject unknown protocol 'tor'");
    return 0;
}

static int test_serialization_round_trip(void) {
    pxc_config_t src, dst;
    pxc_config_init_defaults(&src);
    src.chain_type = PXC_CHAIN_DYNAMIC;
    src.tcp_connect_timeout_ms = 15000;
    src.tcp_read_timeout_ms = 6000;
    src.remote_dns_subnet_prefix = 198;
    src.quiet_mode = true;
    src.proxy_count = 1;

    src.proxies[0].protocol = PXC_PROTO_SOCKS5;
    strncpy_s(src.proxies[0].host, sizeof(src.proxies[0].host), "proxy.example.internal", _TRUNCATE);
    src.proxies[0].port = 1080;
    src.proxies[0].has_auth = true;
    strncpy_s(src.proxies[0].username, sizeof(src.proxies[0].username), "proxyuser", _TRUNCATE);
    strncpy_s(src.proxies[0].password, sizeof(src.proxies[0].password), "s3cr3t!", _TRUNCATE);

    wchar_t env_buf[sizeof(pxc_config_t) * 2 + 1];
    bool ser_ok = pxc_config_serialize_env(&src, env_buf, sizeof(env_buf) / sizeof(wchar_t));
    TEST_ASSERT(ser_ok == true, "Expected serialization to succeed");

    bool deser_ok = pxc_config_deserialize_env(env_buf, &dst);
    TEST_ASSERT(deser_ok == true, "Expected deserialization to succeed");

    TEST_ASSERT(dst.chain_type == PXC_CHAIN_DYNAMIC, "Roundtrip chain_type");
    TEST_ASSERT(dst.tcp_connect_timeout_ms == 15000, "Roundtrip tcp_connect_timeout_ms");
    TEST_ASSERT(dst.tcp_read_timeout_ms == 6000, "Roundtrip tcp_read_timeout_ms");
    TEST_ASSERT(dst.quiet_mode == true, "Roundtrip quiet_mode");
    TEST_ASSERT(dst.proxy_count == 1, "Roundtrip proxy_count");
    TEST_ASSERT(dst.proxies[0].protocol == PXC_PROTO_SOCKS5, "Roundtrip proxy protocol");
    TEST_ASSERT(strcmp(dst.proxies[0].host, "proxy.example.internal") == 0, "Roundtrip host");
    TEST_ASSERT(dst.proxies[0].port == 1080, "Roundtrip port");
    TEST_ASSERT(dst.proxies[0].has_auth == true, "Roundtrip has_auth");
    TEST_ASSERT(strcmp(dst.proxies[0].username, "proxyuser") == 0, "Roundtrip username");
    TEST_ASSERT(strcmp(dst.proxies[0].password, "s3cr3t!") == 0, "Roundtrip password");

    return 0;
}

static int test_nameserver_config(void) {
    const char *conf =
        "strict_chain\n"
        "nameserver 127.0.0.53\n"
        "[ProxyList]\n"
        "socks5 127.0.0.1 9050\n";

    pxc_config_t cfg;
    pxc_parse_result_t res = pxc_config_parse_string(conf, &cfg);

    TEST_ASSERT(res.ok == true, "Expected valid parse result for nameserver");
    TEST_ASSERT(strcmp(cfg.nameserver, "127.0.0.53") == 0, "Expected nameserver parsed");
    return 0;
}

static int test_user_agent_config(void) {
    // 1. Tor chain: always canonical Tor UA
    const char *tor_conf =
        "strict_chain\n"
        "http_user_agent CustomBrowser/1.0\n"
        "[ProxyList]\n"
        "socks5 127.0.0.1 9050\n";

    pxc_config_t cfg;
    pxc_parse_result_t res = pxc_config_parse_string(tor_conf, &cfg);
    TEST_ASSERT(res.ok == true, "Tor config should parse");
    TEST_ASSERT(pxc_config_is_tor(&cfg) == true, "Should identify Tor proxy");
    // Tor strictly enforces canonical Tor UA even if http_user_agent was specified
    TEST_ASSERT(strcmp(pxc_config_get_effective_ua(&cfg), PXC_TOR_USER_AGENT) == 0,
                "Tor chain must enforce canonical Tor Browser User-Agent");

    // 2. Non-Tor chain with custom http_user_agent
    const char *nontor_conf =
        "strict_chain\n"
        "http_user_agent Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\n"
        "[ProxyList]\n"
        "http 127.0.0.1 8080\n";

    res = pxc_config_parse_string(nontor_conf, &cfg);
    TEST_ASSERT(res.ok == true, "Non-Tor config should parse");
    TEST_ASSERT(pxc_config_is_tor(&cfg) == false, "Should identify non-Tor proxy");
    TEST_ASSERT(strcmp(pxc_config_get_effective_ua(&cfg),
                       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36") == 0,
                "Non-Tor chain should use configured http_user_agent");

    // 3. Non-Tor chain with user_agent pool
    const char *pool_conf =
        "strict_chain\n"
        "user_agent Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36\n"
        "[ProxyList]\n"
        "http 127.0.0.1 8080\n";

    res = pxc_config_parse_string(pool_conf, &cfg);
    TEST_ASSERT(res.ok == true, "Pool config should parse");
    TEST_ASSERT(cfg.user_agent_pool_count == 1, "Pool count should be 1");
    TEST_ASSERT(strcmp(pxc_config_get_effective_ua(&cfg),
                       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36") == 0,
                "Non-Tor chain should use user_agent pool entry");

    // 4. Non-Tor chain with no UA directives: falls back safely to PXC_TOR_USER_AGENT
    const char *fallback_conf =
        "strict_chain\n"
        "[ProxyList]\n"
        "http 127.0.0.1 8080\n";

    res = pxc_config_parse_string(fallback_conf, &cfg);
    TEST_ASSERT(res.ok == true, "Fallback config should parse");
    TEST_ASSERT(strcmp(pxc_config_get_effective_ua(&cfg), PXC_TOR_USER_AGENT) == 0,
                "Non-Tor chain without custom UA should fall back to PXC_TOR_USER_AGENT");

    return 0;
}

static int test_round_robin_config(void) {
    const char *conf =
        "round_robin_chain\n"
        "[ProxyList]\n"
        "socks5 127.0.0.1 9050\n"
        "http 127.0.0.1 8080\n";

    pxc_config_t cfg;
    pxc_parse_result_t res = pxc_config_parse_string(conf, &cfg);
    TEST_ASSERT(res.ok == true, "Round robin config should parse");
    TEST_ASSERT(cfg.chain_type == PXC_CHAIN_ROUND_ROBIN, "Chain type should be PXC_CHAIN_ROUND_ROBIN");
    TEST_ASSERT(cfg.proxy_count == 2, "Proxy count should be 2");
    return 0;
}

static int test_localnet_config(void) {
    const char *conf =
        "strict_chain\n"
        "localnet 127.0.0.0 255.0.0.0\n"
        "localnet 10.0.0.0/8\n"
        "localnet 192.168.1.0/24 8080\n"
        "localnet 172.16.0.1 255.255.255.255 443\n"
        "[ProxyList]\n"
        "socks5 127.0.0.1 9050\n";

    pxc_config_t cfg;
    pxc_parse_result_t res = pxc_config_parse_string(conf, &cfg);
    TEST_ASSERT(res.ok == true, "Localnet config should parse successfully");
    TEST_ASSERT(cfg.localnet_count == 4, "Should have parsed 4 localnet entries");

    // Entry 0: 127.0.0.0 / 255.0.0.0
    TEST_ASSERT(cfg.localnets[0].network.s_addr == htonl(0x7F000000), "Entry 0 network 127.0.0.0");
    TEST_ASSERT(cfg.localnets[0].netmask.s_addr == htonl(0xFF000000), "Entry 0 netmask 255.0.0.0");
    TEST_ASSERT(cfg.localnets[0].port == 0, "Entry 0 port 0 (all ports)");

    // Entry 1: 10.0.0.0/8
    TEST_ASSERT(cfg.localnets[1].network.s_addr == htonl(0x0A000000), "Entry 1 network 10.0.0.0");
    TEST_ASSERT(cfg.localnets[1].netmask.s_addr == htonl(0xFF000000), "Entry 1 netmask /8");
    TEST_ASSERT(cfg.localnets[1].port == 0, "Entry 1 port 0");

    // Entry 2: 192.168.1.0/24 8080
    TEST_ASSERT(cfg.localnets[2].network.s_addr == htonl(0xC0A80100), "Entry 2 network 192.168.1.0");
    TEST_ASSERT(cfg.localnets[2].netmask.s_addr == htonl(0xFFFFFF00), "Entry 2 netmask /24");
    TEST_ASSERT(cfg.localnets[2].port == 8080, "Entry 2 port 8080");

    // Entry 3: 172.16.0.1 255.255.255.255 443
    TEST_ASSERT(cfg.localnets[3].network.s_addr == htonl(0xAC100001), "Entry 3 network 172.16.0.1");
    TEST_ASSERT(cfg.localnets[3].netmask.s_addr == htonl(0xFFFFFFFF), "Entry 3 netmask 255.255.255.255");
    TEST_ASSERT(cfg.localnets[3].port == 443, "Entry 3 port 443");

    return 0;
}

int main(void) {
    printf("Running Task 2 Configuration Parser Unit Tests...\n");

    if (test_valid_strict_config() != 0) return 1;
    if (test_round_robin_config() != 0) return 1;
    if (test_localnet_config() != 0) return 1;
    if (test_nameserver_config() != 0) return 1;
    if (test_user_agent_config() != 0) return 1;
    if (test_reject_overflow_token() != 0) return 1;
    if (test_reject_invalid_port() != 0) return 1;
    if (test_reject_unknown_protocol() != 0) return 1;
    if (test_serialization_round_trip() != 0) return 1;

    printf("ALL TESTS PASSED (%d/%d assertions successful)\n", g_pass_count, g_test_count);
    return 0;
}
