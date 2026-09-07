#include "proxychains/hooks.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "Assertion failed: %s at %s:%d\n", #cond, __FILE__, __LINE__); \
        exit(1); \
    } \
} while (0)

pxc_config_t g_pxc_active_config;
bool         g_pxc_hooks_active = false;
HINSTANCE    g_pxc_hinstance    = NULL;

static void test_path_extraction(void) {
    printf("  [1] Testing Command Line & Executable Path Extraction...\n");
    wchar_t exe[MAX_PATH];

    // Explicit app name
    pxc_extract_exe_path(L"C:\\tools\\curl.exe", L"curl -s https://check.torproject.org", exe, MAX_PATH);
    TEST_ASSERT(wcscmp(exe, L"C:\\tools\\curl.exe") == 0);

    // Quoted command line
    pxc_extract_exe_path(NULL, L"\"C:\\Program Files\\Git\\bin\\git.exe\" status", exe, MAX_PATH);
    TEST_ASSERT(wcscmp(exe, L"C:\\Program Files\\Git\\bin\\git.exe") == 0);

    // Unquoted command line with arguments
    pxc_extract_exe_path(NULL, L"ping.exe 127.0.0.1 -n 1", exe, MAX_PATH);
    TEST_ASSERT(wcscmp(exe, L"ping.exe") == 0);

    // Command line without arguments
    pxc_extract_exe_path(NULL, L"notepad.exe", exe, MAX_PATH);
    TEST_ASSERT(wcscmp(exe, L"notepad.exe") == 0);
}

static void test_pe_arch_detection(void) {
    printf("  [2] Testing PE Architecture Inspection...\n");

    // Test system binaries
    wchar_t sys_dir[MAX_PATH] = { 0 };
    GetSystemDirectoryW(sys_dir, MAX_PATH);

    wchar_t sys_cmd[MAX_PATH];
    swprintf_s(sys_cmd, MAX_PATH, L"%s\\cmd.exe", sys_dir);
    pxc_arch_t arch_sys = pxc_detect_pe_arch(sys_cmd);
#if defined(_WIN64)
    TEST_ASSERT(arch_sys == PXC_ARCH_X64);
#else
    TEST_ASSERT(arch_sys == PXC_ARCH_X86);
#endif

    // Test 32-bit SysWOW64 if available on 64-bit Windows
    wchar_t win_dir[MAX_PATH] = { 0 };
    GetWindowsDirectoryW(win_dir, MAX_PATH);
    wchar_t wow64_cmd[MAX_PATH];
    swprintf_s(wow64_cmd, MAX_PATH, L"%s\\SysWOW64\\cmd.exe", win_dir);
    if (GetFileAttributesW(wow64_cmd) != INVALID_FILE_ATTRIBUTES) {
        pxc_arch_t arch_wow64 = pxc_detect_pe_arch(wow64_cmd);
        TEST_ASSERT(arch_wow64 == PXC_ARCH_X86);
    }

    // Test non-existent file
    pxc_arch_t arch_none = pxc_detect_pe_arch(L"C:\\non_existent_binary_xyz123.exe");
    TEST_ASSERT(arch_none == PXC_ARCH_UNKNOWN);
}

static void test_process_hook_lifecycle(void) {
    printf("  [3] Testing Process Hook Installation and Execution...\n");

    // Initialize config
    pxc_config_init_defaults(&g_pxc_active_config);
    g_pxc_active_config.quiet_mode = true;
    g_pxc_active_config.proxy_count = 1;
    g_pxc_active_config.proxies[0].protocol = PXC_PROTO_SOCKS5;
    strcpy_s(g_pxc_active_config.proxies[0].host, sizeof(g_pxc_active_config.proxies[0].host), "127.0.0.1");
    g_pxc_active_config.proxies[0].port = 9050;

    TEST_ASSERT(pxc_install_process_hooks() == true);
    g_pxc_hooks_active = true;

    // Execute child process via Hook_CreateProcessW
    wchar_t cmd[MAX_PATH] = L"cmd.exe /c exit 0";
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    BOOL created = CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    TEST_ASSERT(created == TRUE);
    TEST_ASSERT(pi.hProcess != NULL);

    DWORD wait_res = WaitForSingleObject(pi.hProcess, 5000);
    TEST_ASSERT(wait_res == WAIT_OBJECT_0);

    DWORD exit_code = 1;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    TEST_ASSERT(exit_code == 0);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    printf("  [4] Testing Process Hook Uninstallation...\n");
    g_pxc_hooks_active = false;
    TEST_ASSERT(pxc_uninstall_process_hooks() == true);
}

int main(void) {
    printf("Running Process Creation & Child Propagation Tests...\n");
    test_path_extraction();
    test_pe_arch_detection();
    test_process_hook_lifecycle();
    printf("All Process Creation & Child Propagation Tests PASSED successfully!\n");
    return 0;
}
