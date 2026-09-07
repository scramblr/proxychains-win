#ifndef PROXYCHAINS_COMMON_H
#define PROXYCHAINS_COMMON_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stdbool.h>

#define PXC_VERSION_MAJOR 0
#define PXC_VERSION_MINOR 5
#define PXC_VERSION_PATCH 1
#define PXC_VERSION_SUFFIX L"alpha"
#define PXC_VERSION_STR L"0.5.1alpha"

#ifdef _WIN64
#define PXC_HOOK_DLL_NAME L"proxychains64.dll"
#else
#define PXC_HOOK_DLL_NAME L"proxychains32.dll"
#endif

#define PXC_CONFIG_ENV_VAR L"PROXYCHAINS_CONF_DATA"

#endif // PROXYCHAINS_COMMON_H
