#include "proxychains/common.h"
#include "proxychains/config.h"
#include "proxychains/hooks.h"
#include <detours.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN64)
#pragma comment(linker, "/export:DetourFinishHelperProcess,@1")
#else
#pragma comment(linker, "/export:DetourFinishHelperProcess=_DetourFinishHelperProcess@16,@1")
#endif

HINSTANCE g_pxc_hinstance = NULL;

static bool pxc_try_load_config_from_env(pxc_config_t *out_config) {
    DWORD data_len = GetEnvironmentVariableW(L"PROXYCHAINS_CONF_DATA", NULL, 0);
    if (data_len > 0) {
        wchar_t *env_data = (wchar_t *)malloc(data_len * sizeof(wchar_t));
        if (env_data) {
            GetEnvironmentVariableW(L"PROXYCHAINS_CONF_DATA", env_data, data_len);
            bool ok = pxc_config_deserialize_env(env_data, out_config);
            free(env_data);
            if (ok && out_config->proxy_count > 0) {
                return true;
            }
        }
    }

    wchar_t conf_file[MAX_PATH] = { 0 };
    DWORD file_len = GetEnvironmentVariableW(L"PROXYCHAINS_CONF_FILE", conf_file, MAX_PATH);
    if (file_len > 0 && file_len < MAX_PATH) {
        pxc_parse_result_t res = pxc_config_parse_file(conf_file, out_config);
        if (res.ok && out_config->proxy_count > 0) {
            return true;
        }
    }

    return false;
}

static bool pxc_try_load_config_from_defaults(pxc_config_t *out_config) {
    static const wchar_t *default_paths[] = {
        L".\\proxychains.conf",
        L"proxychains.conf"
    };

    for (size_t i = 0; i < sizeof(default_paths) / sizeof(default_paths[0]); i++) {
        if (GetFileAttributesW(default_paths[i]) != INVALID_FILE_ATTRIBUTES) {
            pxc_parse_result_t res = pxc_config_parse_file(default_paths[i], out_config);
            if (res.ok && out_config->proxy_count > 0) {
                return true;
            }
        }
    }

    // Check directory of the DLL
    if (g_pxc_hinstance) {
        wchar_t dll_dir_conf[MAX_PATH] = { 0 };
        GetModuleFileNameW(g_pxc_hinstance, dll_dir_conf, MAX_PATH);
        wchar_t *last_slash = wcsrchr(dll_dir_conf, L'\\');
        if (last_slash) {
            *(last_slash + 1) = L'\0';
            wcsncat_s(dll_dir_conf, MAX_PATH, L"proxychains.conf", _TRUNCATE);
            if (GetFileAttributesW(dll_dir_conf) != INVALID_FILE_ATTRIBUTES) {
                pxc_parse_result_t res = pxc_config_parse_file(dll_dir_conf, out_config);
                if (res.ok && out_config->proxy_count > 0) {
                    return true;
                }
            }
        }
    }

    // Check %APPDATA%\proxychains\proxychains.conf
    wchar_t appdata[MAX_PATH] = { 0 };
    if (GetEnvironmentVariableW(L"APPDATA", appdata, MAX_PATH) > 0) {
        wchar_t appdata_conf[MAX_PATH] = { 0 };
        swprintf_s(appdata_conf, MAX_PATH, L"%s\\proxychains\\proxychains.conf", appdata);
        if (GetFileAttributesW(appdata_conf) != INVALID_FILE_ATTRIBUTES) {
            pxc_parse_result_t res = pxc_config_parse_file(appdata_conf, out_config);
            if (res.ok && out_config->proxy_count > 0) {
                return true;
            }
        }
    }

    // Check %USERPROFILE%\.proxychains\proxychains.conf
    wchar_t userprofile[MAX_PATH] = { 0 };
    if (GetEnvironmentVariableW(L"USERPROFILE", userprofile, MAX_PATH) > 0) {
        wchar_t profile_conf[MAX_PATH] = { 0 };
        swprintf_s(profile_conf, MAX_PATH, L"%s\\.proxychains\\proxychains.conf", userprofile);
        if (GetFileAttributesW(profile_conf) != INVALID_FILE_ATTRIBUTES) {
            pxc_parse_result_t res = pxc_config_parse_file(profile_conf, out_config);
            if (res.ok && out_config->proxy_count > 0) {
                return true;
            }
        }
    }

    return false;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    switch (fdwReason) {
        case DLL_PROCESS_ATTACH: {
            g_pxc_hinstance = hinstDLL;
            DisableThreadLibraryCalls(hinstDLL);
            DetourRestoreAfterWith();

            pxc_config_init_defaults(&g_pxc_active_config);

            bool loaded = pxc_try_load_config_from_env(&g_pxc_active_config);
            if (!loaded) {
                loaded = pxc_try_load_config_from_defaults(&g_pxc_active_config);
            }

            if (loaded && g_pxc_active_config.proxy_count > 0) {
                pxc_fake_ip_init(g_pxc_active_config.remote_dns_subnet_prefix);
                pxc_tunnel_set_fake_ip_resolver(pxc_fake_ip_lookup_domain);

                pxc_install_dns_hooks();
                pxc_install_winsock_hooks();
                pxc_install_process_hooks();

                g_pxc_hooks_active = true;
            }
            break;
        }

        case DLL_PROCESS_DETACH: {
            if (lpvReserved == NULL) {
                g_pxc_hooks_active = false;
                pxc_uninstall_process_hooks();
                pxc_uninstall_winsock_hooks();
                pxc_uninstall_dns_hooks();
                pxc_fake_ip_cleanup();
            }
            break;
        }
    }

    return TRUE;
}
