#include "proxychains/hooks.h"
#include <detours.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

pxc_CreateProcessW_t true_CreateProcessW = NULL;
pxc_CreateProcessA_t true_CreateProcessA = NULL;

static __declspec(thread) bool t_inside_process_hook = false;

pxc_arch_t pxc_detect_pe_arch(const wchar_t *exe_path) {
    if (!exe_path || exe_path[0] == L'\0') {
        return PXC_ARCH_UNKNOWN;
    }

    HANDLE hFile = CreateFileW(exe_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wchar_t resolved_path[MAX_PATH];
        DWORD res = SearchPathW(NULL, exe_path, L".exe", MAX_PATH, resolved_path, NULL);
        if (res > 0 && res < MAX_PATH) {
            hFile = CreateFileW(resolved_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        }
    }
    if (hFile == INVALID_HANDLE_VALUE) {
        return PXC_ARCH_UNKNOWN;
    }

    IMAGE_DOS_HEADER dos_hdr;
    DWORD read_bytes = 0;
    if (!ReadFile(hFile, &dos_hdr, sizeof(dos_hdr), &read_bytes, NULL) ||
        read_bytes != sizeof(dos_hdr) || dos_hdr.e_magic != IMAGE_DOS_SIGNATURE) {
        CloseHandle(hFile);
        return PXC_ARCH_UNKNOWN;
    }

    if (SetFilePointer(hFile, dos_hdr.e_lfanew, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        CloseHandle(hFile);
        return PXC_ARCH_UNKNOWN;
    }

    DWORD nt_signature = 0;
    if (!ReadFile(hFile, &nt_signature, sizeof(nt_signature), &read_bytes, NULL) ||
        read_bytes != sizeof(nt_signature) || nt_signature != IMAGE_NT_SIGNATURE) {
        CloseHandle(hFile);
        return PXC_ARCH_UNKNOWN;
    }

    IMAGE_FILE_HEADER file_hdr;
    if (!ReadFile(hFile, &file_hdr, sizeof(file_hdr), &read_bytes, NULL) ||
        read_bytes != sizeof(file_hdr)) {
        CloseHandle(hFile);
        return PXC_ARCH_UNKNOWN;
    }

    CloseHandle(hFile);

    if (file_hdr.Machine == IMAGE_FILE_MACHINE_AMD64) {
        return PXC_ARCH_X64;
    }
    if (file_hdr.Machine == IMAGE_FILE_MACHINE_I386) {
        return PXC_ARCH_X86;
    }
    return PXC_ARCH_UNKNOWN;
}

void pxc_extract_exe_path(LPCWSTR app_name, LPCWSTR cmd_line, wchar_t *out_exe, size_t max_chars) {
    if (app_name && app_name[0] != L'\0') {
        wcsncpy_s(out_exe, max_chars, app_name, _TRUNCATE);
        return;
    }
    if (!cmd_line || cmd_line[0] == L'\0') {
        out_exe[0] = L'\0';
        return;
    }

    if (cmd_line[0] == L'"') {
        const wchar_t *end = wcschr(cmd_line + 1, L'"');
        if (end) {
            size_t len = (size_t)(end - (cmd_line + 1));
            if (len >= max_chars) len = max_chars - 1;
            wcsncpy_s(out_exe, max_chars, cmd_line + 1, len);
            out_exe[len] = L'\0';
            return;
        }
    }

    const wchar_t *space = wcschr(cmd_line, L' ');
    if (space) {
        size_t len = (size_t)(space - cmd_line);
        if (len >= max_chars) len = max_chars - 1;
        wcsncpy_s(out_exe, max_chars, cmd_line, len);
        out_exe[len] = L'\0';
        return;
    }

    wcsncpy_s(out_exe, max_chars, cmd_line, _TRUNCATE);
}

static bool pxc_get_dll_path(pxc_arch_t arch, char *out_dll_path_a, size_t max_chars) {
    wchar_t base_dir[MAX_PATH] = { 0 };
    DWORD env_len = GetEnvironmentVariableW(L"PROXYCHAINS_DIR", base_dir, MAX_PATH);
    if (env_len == 0 || env_len >= MAX_PATH) {
        if (g_pxc_hinstance) {
            GetModuleFileNameW(g_pxc_hinstance, base_dir, MAX_PATH);
            wchar_t *last_slash = wcsrchr(base_dir, L'\\');
            if (last_slash) *last_slash = L'\0';
        }
    }

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
    if (base_dir[0] != L'\0') {
        swprintf_s(full_dll_path, MAX_PATH, L"%s\\%s", base_dir, dll_name);
    } else {
        wcsncpy_s(full_dll_path, MAX_PATH, dll_name, _TRUNCATE);
    }

    if (GetFileAttributesW(full_dll_path) == INVALID_FILE_ATTRIBUTES) {
        if (GetFileAttributesW(dll_name) != INVALID_FILE_ATTRIBUTES) {
            WideCharToMultiByte(CP_ACP, 0, dll_name, -1, out_dll_path_a, (int)max_chars, NULL, NULL);
            return true;
        }
        return false;
    }

    WideCharToMultiByte(CP_ACP, 0, full_dll_path, -1, out_dll_path_a, (int)max_chars, NULL, NULL);
    return true;
}

static BOOL WINAPI Hook_CreateProcessW(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation) {

    if (t_inside_process_hook || !g_pxc_hooks_active) {
        return true_CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
                                   lpThreadAttributes, bInheritHandles, dwCreationFlags,
                                   lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }

    wchar_t exe_path[MAX_PATH];
    pxc_extract_exe_path(lpApplicationName, lpCommandLine, exe_path, MAX_PATH);

    pxc_arch_t arch = pxc_detect_pe_arch(exe_path);
    char dll_path_a[MAX_PATH];
    if (!pxc_get_dll_path(arch, dll_path_a, MAX_PATH)) {
        return true_CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
                                   lpThreadAttributes, bInheritHandles, dwCreationFlags,
                                   lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }

    LPCSTR dlls[1] = { dll_path_a };

    t_inside_process_hook = true;
    BOOL ok = DetourCreateProcessWithDllsW(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation,
        1,
        dlls,
        true_CreateProcessW
    );
    t_inside_process_hook = false;

    if (!ok) {
        return true_CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
                                   lpThreadAttributes, bInheritHandles, dwCreationFlags,
                                   lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }
    return TRUE;
}

static BOOL WINAPI Hook_CreateProcessA(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation) {

    if (t_inside_process_hook || !g_pxc_hooks_active) {
        return true_CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes,
                                   lpThreadAttributes, bInheritHandles, dwCreationFlags,
                                   lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }

    wchar_t app_w[MAX_PATH] = { 0 };
    wchar_t cmd_w[1024] = { 0 };
    if (lpApplicationName) {
        MultiByteToWideChar(CP_ACP, 0, lpApplicationName, -1, app_w, MAX_PATH);
    }
    if (lpCommandLine) {
        MultiByteToWideChar(CP_ACP, 0, lpCommandLine, -1, cmd_w, 1024);
    }

    wchar_t exe_path[MAX_PATH];
    pxc_extract_exe_path(app_w, cmd_w, exe_path, MAX_PATH);

    pxc_arch_t arch = pxc_detect_pe_arch(exe_path);
    char dll_path_a[MAX_PATH];
    if (!pxc_get_dll_path(arch, dll_path_a, MAX_PATH)) {
        return true_CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes,
                                   lpThreadAttributes, bInheritHandles, dwCreationFlags,
                                   lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }

    LPCSTR dlls[1] = { dll_path_a };

    t_inside_process_hook = true;
    BOOL ok = DetourCreateProcessWithDllsA(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation,
        1,
        dlls,
        true_CreateProcessA
    );
    t_inside_process_hook = false;

    if (!ok) {
        return true_CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes,
                                   lpThreadAttributes, bInheritHandles, dwCreationFlags,
                                   lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }
    return TRUE;
}

bool pxc_install_process_hooks(void) {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) return false;

    true_CreateProcessW = (pxc_CreateProcessW_t)GetProcAddress(hKernel32, "CreateProcessW");
    true_CreateProcessA = (pxc_CreateProcessA_t)GetProcAddress(hKernel32, "CreateProcessA");

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    if (true_CreateProcessW) {
        DetourAttach((PVOID *)&true_CreateProcessW, (PVOID)(ULONG_PTR)Hook_CreateProcessW);
    }
    if (true_CreateProcessA) {
        DetourAttach((PVOID *)&true_CreateProcessA, (PVOID)(ULONG_PTR)Hook_CreateProcessA);
    }

    LONG status = DetourTransactionCommit();
    return (status == NO_ERROR);
}

bool pxc_uninstall_process_hooks(void) {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    if (true_CreateProcessW) {
        DetourDetach((PVOID *)&true_CreateProcessW, (PVOID)(ULONG_PTR)Hook_CreateProcessW);
    }
    if (true_CreateProcessA) {
        DetourDetach((PVOID *)&true_CreateProcessA, (PVOID)(ULONG_PTR)Hook_CreateProcessA);
    }

    LONG status = DetourTransactionCommit();
    return (status == NO_ERROR);
}
