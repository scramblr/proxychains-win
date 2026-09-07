#include "proxychains/common.h"
#include "proxychains/config.h"
#include "proxychains/hooks.h"
#include <detours.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Globals referenced by process_hooks.c
pxc_config_t g_pxc_active_config;
bool         g_pxc_hooks_active = false;
HINSTANCE    g_pxc_hinstance    = NULL;

static void print_usage(void) {
    wprintf(L"proxychains-win v%s\n", PXC_VERSION_STR);
    wprintf(L"Usage: proxychains-win [-q] [-f <config_file>] <program> [arguments...]\n\n");
    wprintf(L"Options:\n");
    wprintf(L"  -q, --quiet          Quiet mode (suppress banner and logs)\n");
    wprintf(L"  -f <config_file>     Specify custom configuration file path\n");
    wprintf(L"  -h, --help           Display this help message\n");
    wprintf(L"  -v, --version        Display version information\n");
}

static void print_version(void) {
    wprintf(L"proxychains-win v%s (%s-bit)\n",
            PXC_VERSION_STR,
            sizeof(void*) == 8 ? L"64" : L"32");
}

static void pxc_append_arg(wchar_t *dest, size_t dest_max, const wchar_t *arg) {
    if (dest[0] != L'\0') {
        wcsncat_s(dest, dest_max, L" ", _TRUNCATE);
    }

    bool quote_needed = (wcschr(arg, L' ') != NULL || wcschr(arg, L'\t') != NULL || arg[0] == L'\0');

    if (!quote_needed) {
        wcsncat_s(dest, dest_max, arg, _TRUNCATE);
        return;
    }

    wcsncat_s(dest, dest_max, L"\"", _TRUNCATE);
    for (const wchar_t *p = arg; *p != L'\0'; p++) {
        if (*p == L'"') {
            wcsncat_s(dest, dest_max, L"\\\"", _TRUNCATE);
        } else if (*p == L'\\') {
            size_t slash_count = 0;
            while (*p == L'\\') {
                slash_count++;
                p++;
            }
            if (*p == L'"') {
                for (size_t i = 0; i < slash_count * 2; i++) {
                    wcsncat_s(dest, dest_max, L"\\", _TRUNCATE);
                }
                wcsncat_s(dest, dest_max, L"\\\"", _TRUNCATE);
            } else if (*p == L'\0') {
                for (size_t i = 0; i < slash_count * 2; i++) {
                    wcsncat_s(dest, dest_max, L"\\", _TRUNCATE);
                }
                break;
            } else {
                for (size_t i = 0; i < slash_count; i++) {
                    wcsncat_s(dest, dest_max, L"\\", _TRUNCATE);
                }
                wchar_t ch[2] = { *p, L'\0' };
                wcsncat_s(dest, dest_max, ch, _TRUNCATE);
            }
        } else {
            wchar_t ch[2] = { *p, L'\0' };
            wcsncat_s(dest, dest_max, ch, _TRUNCATE);
        }
    }
    wcsncat_s(dest, dest_max, L"\"", _TRUNCATE);
}

static bool pxc_find_config_file(const wchar_t *specified_path, const wchar_t *exe_dir, wchar_t *out_path, size_t max_chars) {
    if (specified_path && specified_path[0] != L'\0') {
        if (GetFileAttributesW(specified_path) != INVALID_FILE_ATTRIBUTES) {
            wcsncpy_s(out_path, max_chars, specified_path, _TRUNCATE);
            return true;
        }
        return false;
    }

    if (GetFileAttributesW(L".\\proxychains.conf") != INVALID_FILE_ATTRIBUTES) {
        wcsncpy_s(out_path, max_chars, L".\\proxychains.conf", _TRUNCATE);
        return true;
    }

    if (exe_dir && exe_dir[0] != L'\0') {
        swprintf_s(out_path, max_chars, L"%s\\proxychains.conf", exe_dir);
        if (GetFileAttributesW(out_path) != INVALID_FILE_ATTRIBUTES) {
            return true;
        }
    }

    wchar_t appdata[MAX_PATH] = { 0 };
    if (GetEnvironmentVariableW(L"APPDATA", appdata, MAX_PATH) > 0) {
        swprintf_s(out_path, max_chars, L"%s\\proxychains\\proxychains.conf", appdata);
        if (GetFileAttributesW(out_path) != INVALID_FILE_ATTRIBUTES) {
            return true;
        }
    }

    wchar_t userprofile[MAX_PATH] = { 0 };
    if (GetEnvironmentVariableW(L"USERPROFILE", userprofile, MAX_PATH) > 0) {
        swprintf_s(out_path, max_chars, L"%s\\.proxychains\\proxychains.conf", userprofile);
        if (GetFileAttributesW(out_path) != INVALID_FILE_ATTRIBUTES) {
            return true;
        }
    }

    return false;
}

static bool pxc_find_hook_dll(pxc_arch_t arch, const wchar_t *exe_dir, char *out_dll_path_a, size_t max_chars) {
    const wchar_t *dll_name = NULL;
    if (arch == PXC_ARCH_X64) {
        dll_name = L"proxychains64.dll";
    } else if (arch == PXC_ARCH_X86) {
        dll_name = L"proxychains32.dll";
    } else {
#if defined(_WIN64)
        dll_name = L"proxychains64.dll";
#else
        dll_name = L"proxychains32.dll";
#endif
    }

    wchar_t full_dll_path[MAX_PATH];
    if (exe_dir && exe_dir[0] != L'\0') {
        swprintf_s(full_dll_path, MAX_PATH, L"%s\\%s", exe_dir, dll_name);
    } else {
        wcsncpy_s(full_dll_path, MAX_PATH, dll_name, _TRUNCATE);
    }

    if (GetFileAttributesW(full_dll_path) != INVALID_FILE_ATTRIBUTES) {
        WideCharToMultiByte(CP_ACP, 0, full_dll_path, -1, out_dll_path_a, (int)max_chars, NULL, NULL);
        return true;
    }

    if (GetFileAttributesW(dll_name) != INVALID_FILE_ATTRIBUTES) {
        WideCharToMultiByte(CP_ACP, 0, dll_name, -1, out_dll_path_a, (int)max_chars, NULL, NULL);
        return true;
    }

    return false;
}

int wmain(int argc, wchar_t *argv[]) {
    const wchar_t *config_file = NULL;
    bool quiet_override = false;
    int target_arg_idx = -1;

    for (int i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"-q") == 0 || wcscmp(argv[i], L"--quiet") == 0) {
            quiet_override = true;
        } else if (wcscmp(argv[i], L"-f") == 0) {
            if (i + 1 < argc) {
                config_file = argv[++i];
            } else {
                fwprintf(stderr, L"proxychains-win: Error: -f option requires a file path\n");
                return 1;
            }
        } else if (wcscmp(argv[i], L"-h") == 0 || wcscmp(argv[i], L"--help") == 0) {
            print_usage();
            return 0;
        } else if (wcscmp(argv[i], L"-v") == 0 || wcscmp(argv[i], L"--version") == 0) {
            print_version();
            return 0;
        } else if (argv[i][0] == L'-') {
            fwprintf(stderr, L"proxychains-win: Unknown option '%s'\n", argv[i]);
            print_usage();
            return 1;
        } else {
            target_arg_idx = i;
            break;
        }
    }

    if (target_arg_idx == -1) {
        print_usage();
        return 1;
    }

    // Get proxychains-win executable directory
    wchar_t exe_dir[MAX_PATH] = { 0 };
    GetModuleFileNameW(NULL, exe_dir, MAX_PATH);
    wchar_t *last_slash = wcsrchr(exe_dir, L'\\');
    if (last_slash) *last_slash = L'\0';

    // Locate and parse configuration
    wchar_t found_conf_path[MAX_PATH] = { 0 };
    if (!pxc_find_config_file(config_file, exe_dir, found_conf_path, MAX_PATH)) {
        if (config_file) {
            fwprintf(stderr, L"proxychains-win: Error: Specified configuration file '%s' not found.\n", config_file);
        } else {
            fwprintf(stderr, L"proxychains-win: Error: No configuration file found (checked .\\proxychains.conf, %%APPDATA%%, %%USERPROFILE%%).\n");
        }
        return 1;
    }

    pxc_config_t config;
    pxc_config_init_defaults(&config);
    pxc_parse_result_t parse_res = pxc_config_parse_file(found_conf_path, &config);
    if (!parse_res.ok) {
        fwprintf(stderr, L"proxychains-win: Configuration error in '%s': line %d: %hs\n",
                 found_conf_path, parse_res.error_line, parse_res.error_message);
        return 1;
    }

    if (config.proxy_count == 0) {
        fwprintf(stderr, L"proxychains-win: Error: Configuration file '%s' contains no proxies in [ProxyList].\n", found_conf_path);
        return 1;
    }

    if (quiet_override) {
        config.quiet_mode = true;
    }

    if (!config.quiet_mode) {
        wprintf(L"[proxychains-win] proxychains-win v%s\n", PXC_VERSION_STR);
        wprintf(L"[proxychains-win] Configuration: %s (%u proxies loaded)\n",
                found_conf_path, config.proxy_count);
    }

    // Serialize configuration to hex string for child environment
    size_t hex_chars = (sizeof(pxc_config_t) * 2) + 1;
    wchar_t *hex_buf = (wchar_t *)malloc(hex_chars * sizeof(wchar_t));
    if (!hex_buf) {
        fwprintf(stderr, L"proxychains-win: Memory allocation failed.\n");
        return 1;
    }
    if (!pxc_config_serialize_env(&config, hex_buf, hex_chars)) {
        fwprintf(stderr, L"proxychains-win: Failed to serialize configuration.\n");
        free(hex_buf);
        return 1;
    }

    SetEnvironmentVariableW(L"PROXYCHAINS_CONF_DATA", hex_buf);
    SetEnvironmentVariableW(L"PROXYCHAINS_CONF_FILE", found_conf_path);
    SetEnvironmentVariableW(L"PROXYCHAINS_DIR", exe_dir);
    free(hex_buf);

    // Build target command line string
    wchar_t cmdline[32768] = { 0 };
    for (int i = target_arg_idx; i < argc; i++) {
        pxc_append_arg(cmdline, sizeof(cmdline) / sizeof(wchar_t), argv[i]);
    }

    // Detect target PE architecture
    const wchar_t *target_exe = argv[target_arg_idx];
    pxc_arch_t arch = pxc_detect_pe_arch(target_exe);

    // Locate hook DLL
    char dll_path_a[MAX_PATH];
    if (!pxc_find_hook_dll(arch, exe_dir, dll_path_a, MAX_PATH)) {
        const char *wanted_dll = (arch == PXC_ARCH_X86) ? "proxychains32.dll" : "proxychains64.dll";
        fwprintf(stderr, L"proxychains-win: Error: Required hook library '%hs' not found in '%s'.\n",
                 wanted_dll, exe_dir);
        return 1;
    }

    LPCSTR dlls[1] = { dll_path_a };

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags |= STARTF_USESTDHANDLES;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError  = GetStdHandle(STD_ERROR_HANDLE);

    BOOL created = DetourCreateProcessWithDllsW(
        NULL,
        cmdline,
        NULL,
        NULL,
        TRUE,
        0,
        NULL,
        NULL,
        &si,
        &pi,
        1,
        dlls,
        NULL
    );

    if (!created) {
        DWORD err = GetLastError();
        fwprintf(stderr, L"proxychains-win: Error: Failed to start target process '%s' (Win32 error %lu).\n",
                 target_exe, err);
        return 1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return (int)exit_code;
}
