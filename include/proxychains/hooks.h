#ifndef PROXYCHAINS_HOOKS_H
#define PROXYCHAINS_HOOKS_H

#include "proxychains/common.h"
#include "proxychains/config.h"
#include "proxychains/fake_ip.h"
#include "proxychains/tunnel.h"

// DNS Function Pointers
typedef INT (WSAAPI *pxc_GetAddrInfoW_t)(PCWSTR, PCWSTR, const ADDRINFOW *, PADDRINFOW *);
typedef VOID (WSAAPI *pxc_FreeAddrInfoW_t)(PADDRINFOW);
typedef INT (WSAAPI *pxc_GetAddrInfoExW_t)(PCWSTR, PCWSTR, DWORD, LPGUID, const ADDRINFOEXW *,
                                          PADDRINFOEXW *, struct timeval *, LPOVERLAPPED,
                                          LPLOOKUPSERVICE_COMPLETION_ROUTINE, LPHANDLE);
typedef VOID (WSAAPI *pxc_FreeAddrInfoExW_t)(PADDRINFOEXW);
typedef int (WSAAPI *pxc_getaddrinfo_t)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
typedef void (WSAAPI *pxc_freeaddrinfo_t)(struct addrinfo *);
typedef struct hostent *(WSAAPI *pxc_gethostbyname_t)(const char *);

// Winsock Function Pointers
typedef int (WSAAPI *pxc_connect_t)(SOCKET, const struct sockaddr *, int);
typedef int (WSAAPI *pxc_WSAConnect_t)(SOCKET, const struct sockaddr *, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
typedef int (WSAAPI *pxc_WSAIoctl_t)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef BOOL (PASCAL *pxc_ConnectEx_t)(SOCKET, const struct sockaddr *, int, PVOID, DWORD, LPDWORD, LPOVERLAPPED);

// Process Creation Function Pointer
typedef BOOL (WINAPI *pxc_CreateProcessW_t)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                                           BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *pxc_CreateProcessA_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                                           BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

// Global trampoline pointers
extern pxc_GetAddrInfoW_t     true_GetAddrInfoW;
extern pxc_FreeAddrInfoW_t    true_FreeAddrInfoW;
extern pxc_GetAddrInfoExW_t   true_GetAddrInfoExW;
extern pxc_FreeAddrInfoExW_t  true_FreeAddrInfoExW;
extern pxc_getaddrinfo_t      true_getaddrinfo;
extern pxc_freeaddrinfo_t     true_freeaddrinfo;
extern pxc_gethostbyname_t    true_gethostbyname;

extern pxc_connect_t          true_connect;
extern pxc_WSAConnect_t       true_WSAConnect;
extern pxc_WSAIoctl_t         true_WSAIoctl;
extern pxc_ConnectEx_t        true_ConnectEx;

extern pxc_CreateProcessW_t   true_CreateProcessW;
extern pxc_CreateProcessA_t   true_CreateProcessA;

extern HINSTANCE              g_pxc_hinstance;

// PE Architecture & Path helpers
typedef enum {
    PXC_ARCH_UNKNOWN = 0,
    PXC_ARCH_X86,
    PXC_ARCH_X64
} pxc_arch_t;

pxc_arch_t pxc_detect_pe_arch(const wchar_t *exe_path);
void pxc_extract_exe_path(LPCWSTR app_name, LPCWSTR cmd_line, wchar_t *out_exe, size_t max_chars);

// Hook installation and removal
bool pxc_install_dns_hooks(void);
bool pxc_uninstall_dns_hooks(void);

bool pxc_install_winsock_hooks(void);
bool pxc_uninstall_winsock_hooks(void);

bool pxc_install_process_hooks(void);
bool pxc_uninstall_process_hooks(void);

// Global active configuration in injected process
extern pxc_config_t g_pxc_active_config;
extern bool         g_pxc_hooks_active;

#endif // PROXYCHAINS_HOOKS_H
