#include "proxychains/hooks.h"
#include <detours.h>
#include <mswsock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const GUID PXC_WSAID_CONNECTEX = WSAID_CONNECTEX;

pxc_connect_t    true_connect    = NULL;
pxc_WSAConnect_t true_WSAConnect = NULL;
pxc_WSAIoctl_t   true_WSAIoctl   = NULL;
pxc_ConnectEx_t  true_ConnectEx  = NULL;

pxc_config_t     g_pxc_active_config;
bool             g_pxc_hooks_active = false;

static __declspec(thread) bool t_inside_hook = false;

static BOOL PASCAL Hook_ConnectEx(SOCKET s, const struct sockaddr *name, int namelen,
                                  PVOID lpSendBuffer, DWORD dwSendDataLength,
                                  LPDWORD lpdwBytesSent, LPOVERLAPPED lpOverlapped);

static int WSAAPI Hook_connect(SOCKET s, const struct sockaddr *name, int namelen) {
    if (t_inside_hook || !g_pxc_hooks_active || g_pxc_active_config.proxy_count == 0 ||
        !name || namelen < (int)sizeof(struct sockaddr_in)) {
        return true_connect(s, name, namelen);
    }

    if (name->sa_family != AF_INET) {
        return true_connect(s, name, namelen);
    }

    const struct sockaddr_in *sin = (const struct sockaddr_in *)name;
    pxc_endpoint_t ep;
    pxc_endpoint_from_ipv4(&ep, sin->sin_addr, ntohs(sin->sin_port));

    if (pxc_is_localnet(&g_pxc_active_config, &ep)) {
        return true_connect(s, name, namelen);
    }

    t_inside_hook = true;
    pxc_tunnel_status_t st = pxc_establish_chain(s, &g_pxc_active_config, &ep);
    t_inside_hook = false;

    if (st == PXC_TUNNEL_SUCCESS) {
        return 0;
    }
    if (st == PXC_TUNNEL_BYPASS) {
        return true_connect(s, name, namelen);
    }

    WSASetLastError(WSAECONNREFUSED);
    return SOCKET_ERROR;
}

static int WSAAPI Hook_WSAConnect(SOCKET s, const struct sockaddr *name, int namelen,
                                  LPWSABUF lpCallerData, LPWSABUF lpCalleeData,
                                  LPQOS lpSQOS, LPQOS lpGQOS) {
    if (t_inside_hook || !g_pxc_hooks_active || g_pxc_active_config.proxy_count == 0 ||
        !name || namelen < (int)sizeof(struct sockaddr_in)) {
        return true_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    }

    if (name->sa_family != AF_INET) {
        return true_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    }

    const struct sockaddr_in *sin = (const struct sockaddr_in *)name;
    pxc_endpoint_t ep;
    pxc_endpoint_from_ipv4(&ep, sin->sin_addr, ntohs(sin->sin_port));

    if (pxc_is_localnet(&g_pxc_active_config, &ep)) {
        return true_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    }

    t_inside_hook = true;
    pxc_tunnel_status_t st = pxc_establish_chain(s, &g_pxc_active_config, &ep);
    t_inside_hook = false;

    if (st == PXC_TUNNEL_SUCCESS) {
        return 0;
    }
    if (st == PXC_TUNNEL_BYPASS) {
        return true_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    }

    WSASetLastError(WSAECONNREFUSED);
    return SOCKET_ERROR;
}

static void ensure_connectex_loaded(SOCKET s) {
    if (!true_ConnectEx && true_WSAIoctl) {
        DWORD ret_bytes = 0;
        GUID guid = WSAID_CONNECTEX;
        true_WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid),
                      &true_ConnectEx, sizeof(true_ConnectEx), &ret_bytes, NULL, NULL);
    }
}

static BOOL PASCAL Hook_ConnectEx(SOCKET s, const struct sockaddr *name, int namelen,
                                  PVOID lpSendBuffer, DWORD dwSendDataLength,
                                  LPDWORD lpdwBytesSent, LPOVERLAPPED lpOverlapped) {
    ensure_connectex_loaded(s);

    if (t_inside_hook || !g_pxc_hooks_active || g_pxc_active_config.proxy_count == 0 ||
        !name || namelen < (int)sizeof(struct sockaddr_in)) {
        if (true_ConnectEx) {
            return true_ConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
        }
        return FALSE;
    }

    if (name->sa_family != AF_INET) {
        if (true_ConnectEx) {
            return true_ConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
        }
        return FALSE;
    }

    const struct sockaddr_in *sin = (const struct sockaddr_in *)name;
    pxc_endpoint_t ep;
    pxc_endpoint_from_ipv4(&ep, sin->sin_addr, ntohs(sin->sin_port));

    if (pxc_is_localnet(&g_pxc_active_config, &ep)) {
        if (true_ConnectEx) {
            return true_ConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
        }
        return FALSE;
    }

    t_inside_hook = true;
    pxc_tunnel_status_t st = pxc_establish_chain(s, &g_pxc_active_config, &ep);
    t_inside_hook = false;

    if (st == PXC_TUNNEL_SUCCESS) {
        DWORD bytes_sent = 0;
        if (lpSendBuffer && dwSendDataLength > 0) {
            int sent = send(s, (const char *)lpSendBuffer, (int)dwSendDataLength, 0);
            if (sent > 0) bytes_sent = (DWORD)sent;
        }
        if (lpdwBytesSent) *lpdwBytesSent = bytes_sent;
        if (lpOverlapped) {
            lpOverlapped->Internal = 0;
            lpOverlapped->InternalHigh = bytes_sent;
            if (lpOverlapped->hEvent) SetEvent(lpOverlapped->hEvent);
        }
        return TRUE;
    }

    if (st == PXC_TUNNEL_BYPASS) {
        if (true_ConnectEx) {
            return true_ConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
        }
        return FALSE;
    }

    WSASetLastError(WSAECONNREFUSED);
    if (lpOverlapped) {
        lpOverlapped->Internal = (ULONG_PTR)0xC0000236; // STATUS_CONNECTION_REFUSED
        if (lpOverlapped->hEvent) SetEvent(lpOverlapped->hEvent);
    }
    return FALSE;
}

static int WSAAPI Hook_WSAIoctl(SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer, DWORD cbInBuffer,
                                LPVOID lpvOutBuffer, DWORD cbOutBuffer, LPDWORD lpcbBytesReturned,
                                LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    if (dwIoControlCode == SIO_GET_EXTENSION_FUNCTION_POINTER &&
        lpvInBuffer != NULL && cbInBuffer >= sizeof(GUID) &&
        lpvOutBuffer != NULL && cbOutBuffer >= sizeof(pxc_ConnectEx_t)) {

        const GUID *guid = (const GUID *)lpvInBuffer;
        if (memcmp(guid, &PXC_WSAID_CONNECTEX, sizeof(GUID)) == 0) {
            if (!true_ConnectEx && true_WSAIoctl) {
                DWORD ret_bytes = 0;
                true_WSAIoctl(s, dwIoControlCode, lpvInBuffer, cbInBuffer,
                              &true_ConnectEx, sizeof(true_ConnectEx), &ret_bytes, NULL, NULL);
            }

            *(pxc_ConnectEx_t *)lpvOutBuffer = Hook_ConnectEx;
            if (lpcbBytesReturned) *lpcbBytesReturned = sizeof(pxc_ConnectEx_t);
            return 0;
        }
    }

    if (true_WSAIoctl) {
        return true_WSAIoctl(s, dwIoControlCode, lpvInBuffer, cbInBuffer,
                             lpvOutBuffer, cbOutBuffer, lpcbBytesReturned,
                             lpOverlapped, lpCompletionRoutine);
    }

    WSASetLastError(WSAEOPNOTSUPP);
    return SOCKET_ERROR;
}

bool pxc_install_winsock_hooks(void) {
    HMODULE hWs2 = GetModuleHandleW(L"ws2_32.dll");
    if (!hWs2) hWs2 = LoadLibraryW(L"ws2_32.dll");

    true_connect    = (pxc_connect_t)GetProcAddress(hWs2, "connect");
    true_WSAConnect = (pxc_WSAConnect_t)GetProcAddress(hWs2, "WSAConnect");
    true_WSAIoctl   = (pxc_WSAIoctl_t)GetProcAddress(hWs2, "WSAIoctl");

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach((PVOID *)&true_connect, (PVOID)(ULONG_PTR)Hook_connect);
    DetourAttach((PVOID *)&true_WSAConnect, (PVOID)(ULONG_PTR)Hook_WSAConnect);
    DetourAttach((PVOID *)&true_WSAIoctl, (PVOID)(ULONG_PTR)Hook_WSAIoctl);

    LONG status = DetourTransactionCommit();
    return (status == NO_ERROR);
}

bool pxc_uninstall_winsock_hooks(void) {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourDetach((PVOID *)&true_connect, (PVOID)(ULONG_PTR)Hook_connect);
    DetourDetach((PVOID *)&true_WSAConnect, (PVOID)(ULONG_PTR)Hook_WSAConnect);
    DetourDetach((PVOID *)&true_WSAIoctl, (PVOID)(ULONG_PTR)Hook_WSAIoctl);

    LONG status = DetourTransactionCommit();
    return (status == NO_ERROR);
}
