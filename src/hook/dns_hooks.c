#include "proxychains/hooks.h"
#include "proxychains/dns.h"
#include <detours.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PXC_AI_MAGIC 0x50584344 // 'PXCD'

typedef enum {
    PXC_AI_TYPE_W = 1,
    PXC_AI_TYPE_A = 2,
    PXC_AI_TYPE_EXW = 3
} pxc_ai_type_t;

typedef struct {
    uint32_t magic;
    uint32_t type;
} pxc_ai_prefix_t;

typedef struct {
    struct sockaddr_in sin;
    wchar_t            canon[PXC_MAX_STRING_LEN];
    pxc_ai_prefix_t    prefix;
    ADDRINFOW          ai;
} pxc_synthetic_addrinfow_t;

typedef struct {
    struct sockaddr_in sin;
    char               canon[PXC_MAX_STRING_LEN];
    pxc_ai_prefix_t    prefix;
    struct addrinfo    ai;
} pxc_synthetic_addrinfoa_t;

typedef struct {
    struct sockaddr_in sin;
    wchar_t            canon[PXC_MAX_STRING_LEN];
    pxc_ai_prefix_t    prefix;
    ADDRINFOEXW        aiex;
} pxc_synthetic_addrinfoexw_t;

// Trampoline pointers
pxc_GetAddrInfoW_t     true_GetAddrInfoW    = NULL;
pxc_FreeAddrInfoW_t    true_FreeAddrInfoW   = NULL;
pxc_GetAddrInfoExW_t   true_GetAddrInfoExW  = NULL;
pxc_FreeAddrInfoExW_t  true_FreeAddrInfoExW = NULL;
pxc_getaddrinfo_t      true_getaddrinfo     = NULL;
pxc_freeaddrinfo_t     true_freeaddrinfo    = NULL;
pxc_gethostbyname_t    true_gethostbyname   = NULL;

static uint16_t parse_service_port_w(PCWSTR pServiceName) {
    if (!pServiceName) return 0;
    wchar_t *endp = NULL;
    long p = wcstol(pServiceName, &endp, 10);
    if (endp && *endp == L'\0' && p > 0 && p <= 65535) {
        return (uint16_t)p;
    }
    if (_wcsicmp(pServiceName, L"http") == 0) return 80;
    if (_wcsicmp(pServiceName, L"https") == 0) return 443;
    if (_wcsicmp(pServiceName, L"ssh") == 0) return 22;
    if (_wcsicmp(pServiceName, L"ftp") == 0) return 21;
    if (_wcsicmp(pServiceName, L"smtp") == 0) return 25;
    if (_wcsicmp(pServiceName, L"dns") == 0 || _wcsicmp(pServiceName, L"domain") == 0) return 53;
    return 0;
}

static uint16_t parse_service_port_a(const char *pServiceName) {
    if (!pServiceName) return 0;
    char *endp = NULL;
    long p = strtol(pServiceName, &endp, 10);
    if (endp && *endp == '\0' && p > 0 && p <= 65535) {
        return (uint16_t)p;
    }
    if (_stricmp(pServiceName, "http") == 0) return 80;
    if (_stricmp(pServiceName, "https") == 0) return 443;
    if (_stricmp(pServiceName, "ssh") == 0) return 22;
    if (_stricmp(pServiceName, "ftp") == 0) return 21;
    if (_stricmp(pServiceName, "smtp") == 0) return 25;
    if (_stricmp(pServiceName, "dns") == 0 || _stricmp(pServiceName, "domain") == 0) return 53;
    return 0;
}

static bool pxc_resolve_domain(const char *domain, struct in_addr *out_ip) {
    if (g_pxc_active_config.nameserver[0] != '\0') {
        if (pxc_dns_resolve_udp(domain, g_pxc_active_config.nameserver, out_ip)) {
            return true;
        }
    }
    *out_ip = pxc_fake_ip_get_or_create(domain);
    return (out_ip->s_addr != INADDR_NONE);
}

static inline bool is_localhost_w(PCWSTR str) {
    if (!str) return false;
    return (_wcsicmp(str, L"localhost") == 0 ||
            _wcsicmp(str, L"localhost.") == 0 ||
            _wcsicmp(str, L"localhost.localdomain") == 0);
}

static inline bool is_localhost_a(const char *str) {
    if (!str) return false;
    return (_stricmp(str, "localhost") == 0 ||
            _stricmp(str, "localhost.") == 0 ||
            _stricmp(str, "localhost.localdomain") == 0);
}

static INT WSAAPI Hook_GetAddrInfoW(PCWSTR pNodeName, PCWSTR pServiceName,
                                    const ADDRINFOW *pHints, PADDRINFOW *ppResult) {
    if (!ppResult) return WSAEINVAL;

    if (!pNodeName) {
        return true_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    }

    struct in_addr test_v4;
    struct in6_addr test_v6;
    if (InetPtonW(AF_INET, pNodeName, &test_v4) == 1 ||
        InetPtonW(AF_INET6, pNodeName, &test_v6) == 1 ||
        is_localhost_w(pNodeName)) {
        return true_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    }

    char domain[PXC_MAX_STRING_LEN];
    if (WideCharToMultiByte(CP_UTF8, 0, pNodeName, -1, domain, sizeof(domain), NULL, NULL) == 0) {
        return EAI_FAIL;
    }

    struct in_addr target_ip;
    if (!pxc_resolve_domain(domain, &target_ip)) {
        return EAI_FAIL;
    }

    uint16_t port = parse_service_port_w(pServiceName);

    pxc_synthetic_addrinfow_t *res = (pxc_synthetic_addrinfow_t *)malloc(sizeof(pxc_synthetic_addrinfow_t));
    if (!res) return EAI_MEMORY;
    memset(res, 0, sizeof(*res));

    res->prefix.magic = PXC_AI_MAGIC;
    res->prefix.type = PXC_AI_TYPE_W;

    res->ai.ai_flags = pHints ? pHints->ai_flags : 0;
    res->ai.ai_family = AF_INET;
    res->ai.ai_socktype = pHints ? pHints->ai_socktype : SOCK_STREAM;
    res->ai.ai_protocol = pHints ? pHints->ai_protocol : IPPROTO_TCP;
    res->ai.ai_addrlen = sizeof(struct sockaddr_in);
    wcsncpy_s(res->canon, sizeof(res->canon) / sizeof(wchar_t), pNodeName, _TRUNCATE);
    res->ai.ai_canonname = res->canon;

    res->sin.sin_family = AF_INET;
    res->sin.sin_port = htons(port);
    res->sin.sin_addr = target_ip;
    res->ai.ai_addr = (struct sockaddr *)&res->sin;
    res->ai.ai_next = NULL;

    *ppResult = &res->ai;
    return 0;
}

static VOID WSAAPI Hook_FreeAddrInfo(PADDRINFOW pAddrInfo) {
    if (!pAddrInfo) return;

    __try {
        pxc_ai_prefix_t *prefix = ((pxc_ai_prefix_t *)pAddrInfo) - 1;
        if (prefix->magic == PXC_AI_MAGIC) {
            if (prefix->type == PXC_AI_TYPE_W) {
                pxc_synthetic_addrinfow_t *wrapper = CONTAINING_RECORD(prefix, pxc_synthetic_addrinfow_t, prefix);
                free(wrapper);
                return;
            } else if (prefix->type == PXC_AI_TYPE_A) {
                pxc_synthetic_addrinfoa_t *wrapper = CONTAINING_RECORD(prefix, pxc_synthetic_addrinfoa_t, prefix);
                free(wrapper);
                return;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Fall through to true_FreeAddrInfoW
    }

    if (true_FreeAddrInfoW) {
        true_FreeAddrInfoW(pAddrInfo);
    }
}

static INT WSAAPI Hook_GetAddrInfoExW(PCWSTR pName, PCWSTR pServiceName, DWORD dwNameSpace, LPGUID lpNspId,
                                      const ADDRINFOEXW *hints, PADDRINFOEXW *ppResult, struct timeval *timeout,
                                      LPOVERLAPPED lpOverlapped, LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine,
                                      LPHANDLE lpNameHandle) {
    if (!ppResult) return WSAEINVAL;

    if (!pName) {
        return true_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId, hints, ppResult,
                                   timeout, lpOverlapped, lpCompletionRoutine, lpNameHandle);
    }

    struct in_addr test_v4;
    struct in6_addr test_v6;
    if (InetPtonW(AF_INET, pName, &test_v4) == 1 ||
        InetPtonW(AF_INET6, pName, &test_v6) == 1 ||
        is_localhost_w(pName)) {
        return true_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId, hints, ppResult,
                                   timeout, lpOverlapped, lpCompletionRoutine, lpNameHandle);
    }

    char domain[PXC_MAX_STRING_LEN];
    if (WideCharToMultiByte(CP_UTF8, 0, pName, -1, domain, sizeof(domain), NULL, NULL) == 0) {
        return EAI_FAIL;
    }

    struct in_addr target_ip;
    if (!pxc_resolve_domain(domain, &target_ip)) {
        return EAI_FAIL;
    }

    uint16_t port = parse_service_port_w(pServiceName);

    pxc_synthetic_addrinfoexw_t *res = (pxc_synthetic_addrinfoexw_t *)malloc(sizeof(pxc_synthetic_addrinfoexw_t));
    if (!res) return EAI_MEMORY;
    memset(res, 0, sizeof(*res));

    res->prefix.magic = PXC_AI_MAGIC;
    res->prefix.type = PXC_AI_TYPE_EXW;

    res->aiex.ai_flags = hints ? hints->ai_flags : 0;
    res->aiex.ai_family = AF_INET;
    res->aiex.ai_socktype = hints ? hints->ai_socktype : SOCK_STREAM;
    res->aiex.ai_protocol = hints ? hints->ai_protocol : IPPROTO_TCP;
    res->aiex.ai_addrlen = sizeof(struct sockaddr_in);
    wcsncpy_s(res->canon, sizeof(res->canon) / sizeof(wchar_t), pName, _TRUNCATE);
    res->aiex.ai_canonname = res->canon;

    res->sin.sin_family = AF_INET;
    res->sin.sin_port = htons(port);
    res->sin.sin_addr = target_ip;
    res->aiex.ai_addr = (struct sockaddr *)&res->sin;
    res->aiex.ai_next = NULL;

    *ppResult = &res->aiex;

    if (lpOverlapped) {
        lpOverlapped->Internal = 0;
        lpOverlapped->InternalHigh = 0;
        if (lpOverlapped->hEvent) {
            SetEvent(lpOverlapped->hEvent);
        }
    }
    if (lpCompletionRoutine) {
        lpCompletionRoutine(0, 0, lpOverlapped);
    }

    return 0;
}

static VOID WSAAPI Hook_FreeAddrInfoExW(PADDRINFOEXW pAddrInfo) {
    if (!pAddrInfo) return;

    __try {
        pxc_ai_prefix_t *prefix = ((pxc_ai_prefix_t *)pAddrInfo) - 1;
        if (prefix->magic == PXC_AI_MAGIC && prefix->type == PXC_AI_TYPE_EXW) {
            pxc_synthetic_addrinfoexw_t *wrapper = CONTAINING_RECORD(prefix, pxc_synthetic_addrinfoexw_t, prefix);
            free(wrapper);
            return;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Fall through
    }

    if (true_FreeAddrInfoExW) {
        true_FreeAddrInfoExW(pAddrInfo);
    }
}

static int WSAAPI Hook_getaddrinfo(const char *nodename, const char *servname,
                                   const struct addrinfo *hints, struct addrinfo **res) {
    if (!res) return WSAEINVAL;

    if (!nodename) {
        return true_getaddrinfo(nodename, servname, hints, res);
    }

    struct in_addr test_v4;
    struct in6_addr test_v6;
    if (inet_pton(AF_INET, nodename, &test_v4) == 1 ||
        inet_pton(AF_INET6, nodename, &test_v6) == 1 ||
        is_localhost_a(nodename)) {
        return true_getaddrinfo(nodename, servname, hints, res);
    }

    struct in_addr target_ip;
    if (!pxc_resolve_domain(nodename, &target_ip)) {
        return EAI_FAIL;
    }

    uint16_t port = parse_service_port_a(servname);

    pxc_synthetic_addrinfoa_t *syn = (pxc_synthetic_addrinfoa_t *)malloc(sizeof(pxc_synthetic_addrinfoa_t));
    if (!syn) return EAI_MEMORY;
    memset(syn, 0, sizeof(*syn));

    syn->prefix.magic = PXC_AI_MAGIC;
    syn->prefix.type = PXC_AI_TYPE_A;

    syn->ai.ai_flags = hints ? hints->ai_flags : 0;
    syn->ai.ai_family = AF_INET;
    syn->ai.ai_socktype = hints ? hints->ai_socktype : SOCK_STREAM;
    syn->ai.ai_protocol = hints ? hints->ai_protocol : IPPROTO_TCP;
    syn->ai.ai_addrlen = sizeof(struct sockaddr_in);
    strncpy_s(syn->canon, sizeof(syn->canon), nodename, _TRUNCATE);
    syn->ai.ai_canonname = syn->canon;

    syn->sin.sin_family = AF_INET;
    syn->sin.sin_port = htons(port);
    syn->sin.sin_addr = target_ip;
    syn->ai.ai_addr = (struct sockaddr *)&syn->sin;
    syn->ai.ai_next = NULL;

    *res = &syn->ai;
    return 0;
}

static struct hostent * WSAAPI Hook_gethostbyname(const char *name) {
    if (!name) return NULL;

    struct in_addr test_v4;
    if (inet_pton(AF_INET, name, &test_v4) == 1 || is_localhost_a(name)) {
        return true_gethostbyname(name);
    }

    struct in_addr target_ip;
    if (!pxc_resolve_domain(name, &target_ip)) {
        return NULL;
    }

    static __declspec(thread) struct {
        struct hostent host;
        char *aliases[1];
        char *addr_list[2];
        struct in_addr addr;
        char name[PXC_MAX_STRING_LEN];
    } t_hostent;

    strncpy_s(t_hostent.name, sizeof(t_hostent.name), name, _TRUNCATE);
    t_hostent.addr = target_ip;
    t_hostent.addr_list[0] = (char *)&t_hostent.addr;
    t_hostent.addr_list[1] = NULL;
    t_hostent.aliases[0] = NULL;

    t_hostent.host.h_name = t_hostent.name;
    t_hostent.host.h_aliases = t_hostent.aliases;
    t_hostent.host.h_addrtype = AF_INET;
    t_hostent.host.h_length = sizeof(struct in_addr);
    t_hostent.host.h_addr_list = t_hostent.addr_list;

    return &t_hostent.host;
}

static bool g_freeaddrinfo_separate = false;

bool pxc_install_dns_hooks(void) {
    HMODULE hWs2 = GetModuleHandleW(L"ws2_32.dll");
    if (!hWs2) hWs2 = LoadLibraryW(L"ws2_32.dll");

    true_GetAddrInfoW    = (pxc_GetAddrInfoW_t)GetProcAddress(hWs2, "GetAddrInfoW");
    true_FreeAddrInfoW   = (pxc_FreeAddrInfoW_t)GetProcAddress(hWs2, "FreeAddrInfoW");
    true_GetAddrInfoExW  = (pxc_GetAddrInfoExW_t)GetProcAddress(hWs2, "GetAddrInfoExW");
    true_FreeAddrInfoExW = (pxc_FreeAddrInfoExW_t)GetProcAddress(hWs2, "FreeAddrInfoExW");
    true_getaddrinfo     = (pxc_getaddrinfo_t)GetProcAddress(hWs2, "getaddrinfo");
    true_freeaddrinfo    = (pxc_freeaddrinfo_t)GetProcAddress(hWs2, "freeaddrinfo");
    true_gethostbyname   = (pxc_gethostbyname_t)GetProcAddress(hWs2, "gethostbyname");

    g_freeaddrinfo_separate = (true_freeaddrinfo != NULL && true_freeaddrinfo != (pxc_freeaddrinfo_t)true_FreeAddrInfoW);

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach((PVOID *)&true_GetAddrInfoW, (PVOID)(ULONG_PTR)Hook_GetAddrInfoW);
    DetourAttach((PVOID *)&true_FreeAddrInfoW, (PVOID)(ULONG_PTR)Hook_FreeAddrInfo);
    DetourAttach((PVOID *)&true_GetAddrInfoExW, (PVOID)(ULONG_PTR)Hook_GetAddrInfoExW);
    DetourAttach((PVOID *)&true_FreeAddrInfoExW, (PVOID)(ULONG_PTR)Hook_FreeAddrInfoExW);
    DetourAttach((PVOID *)&true_getaddrinfo, (PVOID)(ULONG_PTR)Hook_getaddrinfo);

    if (g_freeaddrinfo_separate) {
        DetourAttach((PVOID *)&true_freeaddrinfo, (PVOID)(ULONG_PTR)Hook_FreeAddrInfo);
    }

    DetourAttach((PVOID *)&true_gethostbyname, (PVOID)(ULONG_PTR)Hook_gethostbyname);

    LONG status = DetourTransactionCommit();
    return (status == NO_ERROR);
}

bool pxc_uninstall_dns_hooks(void) {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourDetach((PVOID *)&true_GetAddrInfoW, (PVOID)(ULONG_PTR)Hook_GetAddrInfoW);
    DetourDetach((PVOID *)&true_FreeAddrInfoW, (PVOID)(ULONG_PTR)Hook_FreeAddrInfo);
    DetourDetach((PVOID *)&true_GetAddrInfoExW, (PVOID)(ULONG_PTR)Hook_GetAddrInfoExW);
    DetourDetach((PVOID *)&true_FreeAddrInfoExW, (PVOID)(ULONG_PTR)Hook_FreeAddrInfoExW);
    DetourDetach((PVOID *)&true_getaddrinfo, (PVOID)(ULONG_PTR)Hook_getaddrinfo);

    if (g_freeaddrinfo_separate) {
        DetourDetach((PVOID *)&true_freeaddrinfo, (PVOID)(ULONG_PTR)Hook_FreeAddrInfo);
    }

    DetourDetach((PVOID *)&true_gethostbyname, (PVOID)(ULONG_PTR)Hook_gethostbyname);

    LONG status = DetourTransactionCommit();
    return (status == NO_ERROR);
}
