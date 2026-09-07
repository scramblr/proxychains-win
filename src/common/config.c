#include "proxychains/config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

void pxc_config_init_defaults(pxc_config_t *config) {
    if (!config) return;
    memset(config, 0, sizeof(pxc_config_t));
    config->chain_type = PXC_CHAIN_STRICT;
    config->tcp_connect_timeout_ms = 10000;
    config->tcp_read_timeout_ms = 4000;
    config->remote_dns_subnet_prefix = 198; // RFC 6890: 198.18.0.0/15
    config->quiet_mode = false;
    config->nameserver[0] = '\0';
    config->http_user_agent[0] = '\0';
    config->user_agent_pool_count = 0;
    config->proxy_count = 0;
    config->localnet_count = 0;
}

bool pxc_config_is_tor(const pxc_config_t *config) {
    if (!config || config->proxy_count == 0) return false;
    for (uint32_t i = 0; i < config->proxy_count; i++) {
        if ((strcmp(config->proxies[i].host, "127.0.0.1") == 0 ||
             _stricmp(config->proxies[i].host, "localhost") == 0) &&
            (config->proxies[i].port == 9050 || config->proxies[i].port == 9150)) {
            return true;
        }
    }
    return false;
}

const char *pxc_config_get_effective_ua(const pxc_config_t *config) {
    if (!config) return PXC_TOR_USER_AGENT;
    if (pxc_config_is_tor(config)) {
        return PXC_TOR_USER_AGENT;
    }
    if (config->http_user_agent[0] != '\0') {
        return config->http_user_agent;
    }
    if (config->user_agent_pool_count > 0) {
        return config->user_agent_pool[0];
    }
    return PXC_TOR_USER_AGENT;
}

static char *trim_whitespace(char *str) {
    while (*str && isspace((unsigned char)*str)) str++;
    if (*str == '\0') return str;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

typedef enum {
    TOKEN_OK = 0,
    TOKEN_END,
    TOKEN_OVERFLOW
} token_status_t;

static token_status_t next_token(const char **cursor, char *out_buf, size_t max_len) {
    const char *p = *cursor;
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p == '\0' || *p == '#') {
        *cursor = p;
        return TOKEN_END;
    }

    size_t i = 0;
    while (*p && !isspace((unsigned char)*p) && *p != '#') {
        if (i + 1 < max_len) {
            out_buf[i++] = *p;
        } else {
            *cursor = p;
            return TOKEN_OVERFLOW;
        }
        p++;
    }
    out_buf[i] = '\0';
    *cursor = p;
    return TOKEN_OK;
}

pxc_parse_result_t pxc_config_parse_string(const char *content, pxc_config_t *out_config) {
    pxc_parse_result_t res = { true, 0, "" };
    if (!content || !out_config) {
        res.ok = false;
        res.error_line = 0;
        snprintf(res.error_message, sizeof(res.error_message), "Invalid null parameter passed to parser");
        return res;
    }

    pxc_config_init_defaults(out_config);

    bool in_proxy_list = false;
    int line_no = 0;
    const char *line_start = content;

    char line[1024];
    char token[PXC_MAX_STRING_LEN];

    while (*line_start) {
        line_no++;
        const char *line_end = strchr(line_start, '\n');
        size_t line_len = line_end ? (size_t)(line_end - line_start) : strlen(line_start);

        if (line_len >= sizeof(line)) {
            res.ok = false;
            res.error_line = line_no;
            snprintf(res.error_message, sizeof(res.error_message), "Line %d exceeds maximum length (1024 bytes)", line_no);
            return res;
        }

        memcpy(line, line_start, line_len);
        line[line_len] = '\0';
        line_start = line_end ? (line_end + 1) : (line_start + line_len);

        char *trimmed = trim_whitespace(line);
        if (*trimmed == '\0' || *trimmed == '#') continue;

        if (_stricmp(trimmed, "[ProxyList]") == 0) {
            in_proxy_list = true;
            continue;
        }

        const char *cursor = trimmed;

        if (!in_proxy_list) {
            token_status_t t_stat = next_token(&cursor, token, sizeof(token));
            if (t_stat == TOKEN_END) continue;
            if (t_stat == TOKEN_OVERFLOW) {
                res.ok = false;
                res.error_line = line_no;
                snprintf(res.error_message, sizeof(res.error_message), "Directive exceeds maximum token length on line %d", line_no);
                return res;
            }

            if (_stricmp(token, "strict_chain") == 0) {
                out_config->chain_type = PXC_CHAIN_STRICT;
            } else if (_stricmp(token, "dynamic_chain") == 0) {
                out_config->chain_type = PXC_CHAIN_DYNAMIC;
            } else if (_stricmp(token, "random_chain") == 0) {
                out_config->chain_type = PXC_CHAIN_RANDOM;
            } else if (_stricmp(token, "round_robin_chain") == 0) {
                out_config->chain_type = PXC_CHAIN_ROUND_ROBIN;
            } else if (_stricmp(token, "quiet_mode") == 0) {
                out_config->quiet_mode = true;
            } else if (_stricmp(token, "tcp_connect_time_out") == 0) {
                if (next_token(&cursor, token, sizeof(token)) == TOKEN_OK) {
                    out_config->tcp_connect_timeout_ms = (uint32_t)strtoul(token, NULL, 10);
                }
            } else if (_stricmp(token, "tcp_read_time_out") == 0) {
                if (next_token(&cursor, token, sizeof(token)) == TOKEN_OK) {
                    out_config->tcp_read_timeout_ms = (uint32_t)strtoul(token, NULL, 10);
                }
            } else if (_stricmp(token, "remote_dns_subnet") == 0) {
                if (next_token(&cursor, token, sizeof(token)) == TOKEN_OK) {
                    unsigned long val = strtoul(token, NULL, 10);
                    if (val > 0 && val < 255) {
                        out_config->remote_dns_subnet_prefix = (uint8_t)val;
                    }
                }
            } else if (_stricmp(token, "nameserver") == 0) {
                if (next_token(&cursor, token, sizeof(token)) == TOKEN_OK) {
                    strncpy_s(out_config->nameserver, sizeof(out_config->nameserver), token, _TRUNCATE);
                }
            } else if (_stricmp(token, "http_user_agent") == 0) {
                while (*cursor && isspace((unsigned char)*cursor)) cursor++;
                char val[PXC_MAX_STRING_LEN];
                strncpy_s(val, sizeof(val), cursor, _TRUNCATE);
                char *comment = strchr(val, '#');
                if (comment) *comment = '\0';
                char *clean_ua = trim_whitespace(val);
                size_t ulen = strlen(clean_ua);
                if (ulen >= 2 && ((clean_ua[0] == '"' && clean_ua[ulen - 1] == '"') ||
                                  (clean_ua[0] == '\'' && clean_ua[ulen - 1] == '\''))) {
                    clean_ua[ulen - 1] = '\0';
                    clean_ua++;
                }
                if (*clean_ua) {
                    strncpy_s(out_config->http_user_agent, sizeof(out_config->http_user_agent), clean_ua, _TRUNCATE);
                }
            } else if (_stricmp(token, "user_agent") == 0) {
                while (*cursor && isspace((unsigned char)*cursor)) cursor++;
                char val[PXC_MAX_STRING_LEN];
                strncpy_s(val, sizeof(val), cursor, _TRUNCATE);
                char *comment = strchr(val, '#');
                if (comment) *comment = '\0';
                char *clean_ua = trim_whitespace(val);
                size_t ulen = strlen(clean_ua);
                if (ulen >= 2 && ((clean_ua[0] == '"' && clean_ua[ulen - 1] == '"') ||
                                  (clean_ua[0] == '\'' && clean_ua[ulen - 1] == '\''))) {
                    clean_ua[ulen - 1] = '\0';
                    clean_ua++;
                }
                if (*clean_ua && out_config->user_agent_pool_count < PXC_MAX_USER_AGENTS) {
                    strncpy_s(out_config->user_agent_pool[out_config->user_agent_pool_count++],
                              PXC_MAX_STRING_LEN, clean_ua, _TRUNCATE);
                }
            }
        } else {
            // Processing [ProxyList] section
            if (out_config->proxy_count >= PXC_MAX_PROXIES) {
                res.ok = false;
                res.error_line = line_no;
                snprintf(res.error_message, sizeof(res.error_message), "Proxy list limit reached (maximum %d proxies)", PXC_MAX_PROXIES);
                return res;
            }

            pxc_proxy_entry_t *entry = &out_config->proxies[out_config->proxy_count];
            memset(entry, 0, sizeof(pxc_proxy_entry_t));

            // Protocol
            token_status_t p_stat = next_token(&cursor, token, sizeof(token));
            if (p_stat == TOKEN_END) continue;
            if (p_stat == TOKEN_OVERFLOW) {
                res.ok = false;
                res.error_line = line_no;
                snprintf(res.error_message, sizeof(res.error_message), "Protocol token exceeds maximum length on line %d", line_no);
                return res;
            }

            if (_stricmp(token, "socks5") == 0) entry->protocol = PXC_PROTO_SOCKS5;
            else if (_stricmp(token, "socks4") == 0) entry->protocol = PXC_PROTO_SOCKS4;
            else if (_stricmp(token, "http") == 0) entry->protocol = PXC_PROTO_HTTP;
            else {
                res.ok = false;
                res.error_line = line_no;
                snprintf(res.error_message, sizeof(res.error_message), "Unknown protocol '%s' on line %d", token, line_no);
                return res;
            }

            // Host
            token_status_t h_stat = next_token(&cursor, entry->host, sizeof(entry->host));
            if (h_stat == TOKEN_OVERFLOW) {
                res.ok = false;
                res.error_line = line_no;
                snprintf(res.error_message, sizeof(res.error_message), "Proxy host exceeds maximum length on line %d", line_no);
                return res;
            }
            if (h_stat != TOKEN_OK) {
                res.ok = false;
                res.error_line = line_no;
                snprintf(res.error_message, sizeof(res.error_message), "Missing proxy host on line %d", line_no);
                return res;
            }

            // Port
            token_status_t port_stat = next_token(&cursor, token, sizeof(token));
            if (port_stat != TOKEN_OK) {
                res.ok = false;
                res.error_line = line_no;
                snprintf(res.error_message, sizeof(res.error_message), "Missing or invalid proxy port on line %d", line_no);
                return res;
            }

            int port = atoi(token);
            if (port <= 0 || port > 65535) {
                res.ok = false;
                res.error_line = line_no;
                snprintf(res.error_message, sizeof(res.error_message), "Port out of range (1-65535): %d on line %d", port, line_no);
                return res;
            }
            entry->port = (uint16_t)port;

            // Optional username
            token_status_t u_stat = next_token(&cursor, entry->username, sizeof(entry->username));
            if (u_stat == TOKEN_OVERFLOW) {
                res.ok = false;
                res.error_line = line_no;
                snprintf(res.error_message, sizeof(res.error_message), "Proxy username exceeds maximum length on line %d", line_no);
                return res;
            }
            if (u_stat == TOKEN_OK) {
                entry->has_auth = true;
                // Optional password
                token_status_t pwd_stat = next_token(&cursor, entry->password, sizeof(entry->password));
                if (pwd_stat == TOKEN_OVERFLOW) {
                    res.ok = false;
                    res.error_line = line_no;
                    snprintf(res.error_message, sizeof(res.error_message), "Proxy password exceeds maximum length on line %d", line_no);
                    return res;
                }
                if (pwd_stat != TOKEN_OK) {
                    entry->password[0] = '\0';
                }
            }

            out_config->proxy_count++;
        }
    }

    if (out_config->proxy_count == 0) {
        res.ok = false;
        res.error_line = line_no;
        snprintf(res.error_message, sizeof(res.error_message), "No valid proxies defined in [ProxyList] section");
        return res;
    }

    return res;
}

pxc_parse_result_t pxc_config_parse_file(const wchar_t *path, pxc_config_t *out_config) {
    pxc_parse_result_t res = { true, 0, "" };
    if (!path || !out_config) {
        res.ok = false;
        res.error_line = 0;
        snprintf(res.error_message, sizeof(res.error_message), "Invalid null parameter");
        return res;
    }

    FILE *f = NULL;
    if (_wfopen_s(&f, path, L"rb") != 0 || !f) {
        res.ok = false;
        res.error_line = 0;
        snprintf(res.error_message, sizeof(res.error_message), "Failed to open configuration file");
        return res;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0 || size > (1024 * 1024)) {
        fclose(f);
        res.ok = false;
        res.error_line = 0;
        snprintf(res.error_message, sizeof(res.error_message), "Configuration file is empty or exceeds 1MB");
        return res;
    }

    char *buf = (char *)malloc(size + 1);
    if (!buf) {
        fclose(f);
        res.ok = false;
        res.error_line = 0;
        snprintf(res.error_message, sizeof(res.error_message), "Memory allocation failed reading configuration");
        return res;
    }

    size_t read_bytes = fread(buf, 1, size, f);
    fclose(f);
    buf[read_bytes] = '\0';

    res = pxc_config_parse_string(buf, out_config);
    free(buf);
    return res;
}

bool pxc_config_serialize_env(const pxc_config_t *config, wchar_t *out_buf, size_t buf_chars) {
    if (!config || !out_buf) return false;
    const uint8_t *bytes = (const uint8_t *)config;
    size_t required = (sizeof(pxc_config_t) * 2) + 1;
    if (buf_chars < required) return false;

    static const wchar_t hex_chars[] = L"0123456789ABCDEF";
    for (size_t i = 0; i < sizeof(pxc_config_t); i++) {
        out_buf[i * 2]     = hex_chars[(bytes[i] >> 4) & 0x0F];
        out_buf[i * 2 + 1] = hex_chars[bytes[i] & 0x0F];
    }
    out_buf[sizeof(pxc_config_t) * 2] = L'\0';
    return true;
}

bool pxc_config_deserialize_env(const wchar_t *env_val, pxc_config_t *out_config) {
    if (!env_val || !out_config) return false;
    size_t len = wcslen(env_val);
    if (len != sizeof(pxc_config_t) * 2) return false;

    uint8_t *bytes = (uint8_t *)out_config;
    for (size_t i = 0; i < sizeof(pxc_config_t); i++) {
        wchar_t h = env_val[i * 2];
        wchar_t l = env_val[i * 2 + 1];

        int hi = (h >= L'0' && h <= L'9') ? (h - L'0') : ((h >= L'A' && h <= L'F') ? (h - L'A' + 10) : -1);
        int lo = (l >= L'0' && l <= L'9') ? (l - L'0') : ((l >= L'A' && l <= L'F') ? (l - L'A' + 10) : -1);

        if (hi == -1 || lo == -1) return false;
        bytes[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}
