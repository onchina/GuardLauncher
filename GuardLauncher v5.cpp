#ifndef _WIN64
#error "此代码针对 x64 架构编写，请使用 x64 编译器编译。"
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifndef STARTF_TITLEISLINKNAME
#define STARTF_TITLEISLINKNAME 0x00000800
#endif

// ===================== 0. Zero-CRT 编译器内在函数支持 =====================
// 满足 MSVC /O2 优化器对结构体清零与拷贝自动生成的 memset / memcpy 外部符号引用
#pragma function(memset, memcpy)
extern "C" void* __cdecl memset(void* dst, int val, size_t count) {
    unsigned char* p = (unsigned char*)dst;
    while (count--) {
        *p++ = (unsigned char)val;
    }
    return dst;
}

extern "C" void* __cdecl memcpy(void* dst, const void* src, size_t count) {
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    while (count--) {
        *d++ = *s++;
    }
    return dst;
}

// ===================== 1. 纯 Kernel32 字符串与命令行解析 =====================

static const wchar_t* MyWcsChr(const wchar_t* s, wchar_t ch) {
    if (!s) return nullptr;
    for (; *s; ++s) {
        if (*s == ch) return s;
    }
    return nullptr;
}

static int MyWcsNCmp(const wchar_t* s1, const wchar_t* s2, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (s1[i] != s2[i]) return (s1[i] < s2[i]) ? -1 : 1;
        if (s1[i] == L'\0') return 0;
    }
    return 0;
}

// 提取命令行中的单个参数（遵循 Windows 引号与反斜杠转义规则），并输出下一个参数的起始位置
static bool NextCmdArg(const wchar_t* p, wchar_t* outBuf, size_t maxChars, const wchar_t** nextPos) {
    while (*p == L' ' || *p == L'\t') ++p;
    if (*p == L'\0') {
        if (maxChars > 0) outBuf[0] = L'\0';
        if (nextPos) *nextPos = p;
        return false;
    }

    size_t outIdx = 0;
    bool inQuotes = false;

    while (*p) {
        if (!inQuotes && (*p == L' ' || *p == L'\t')) {
            break;
        }

        size_t backslashes = 0;
        while (*p == L'\\') {
            ++backslashes;
            ++p;
        }

        if (*p == L'"') {
            for (size_t i = 0; i < backslashes / 2; ++i) {
                if (outIdx + 1 < maxChars) outBuf[outIdx++] = L'\\';
            }
            if ((backslashes % 2) == 0) {
                inQuotes = !inQuotes;
            } else {
                if (outIdx + 1 < maxChars) outBuf[outIdx++] = L'"';
            }
            ++p;
        } else {
            for (size_t i = 0; i < backslashes; ++i) {
                if (outIdx + 1 < maxChars) outBuf[outIdx++] = L'\\';
            }
            if (*p != L'\0') {
                if (outIdx + 1 < maxChars) outBuf[outIdx++] = *p;
                ++p;
            }
        }
    }

    if (maxChars > 0) outBuf[outIdx] = L'\0';
    while (*p == L' ' || *p == L'\t') ++p;
    if (nextPos) *nextPos = p;
    return true;
}

// 判断字符串是否以 .exe 结尾
static bool EndsWithExe(const wchar_t* s) {
    if (!s) return false;
    int len = lstrlenW(s);
    if (len < 4) return false;
    return CompareStringOrdinal(s + len - 4, 4, L".exe", 4, TRUE) == CSTR_EQUAL;
}

// 判断短名称（如 "chrome"）是否与完整 exe 路径（如 "C:\...\chrome.exe"）的文件名主干一致
static bool MatchesExeStem(const wchar_t* shortArg, const wchar_t* fullExePath) {
    if (!shortArg || !fullExePath) return false;
    const wchar_t* base = fullExePath;
    for (const wchar_t* p = fullExePath; *p; ++p) {
        if (*p == L'\\' || *p == L'/') base = p + 1;
    }
    int baseLen = lstrlenW(base);
    if (baseLen <= 4) return false;
    int stemLen = baseLen - 4;
    if (lstrlenW(shortArg) != stemLen) return false;
    return CompareStringOrdinal(shortArg, stemLen, base, stemLen, TRUE) == CSTR_EQUAL;
}

// 判断路径末尾文件名是否为 MDMRegistration.dll
static bool IsMdmFileName(const wchar_t* path) {
    if (!path || !*path) return false;
    const wchar_t* base = path;
    for (const wchar_t* p = path; *p; ++p) {
        if (*p == L'\\' || *p == L'/') base = p + 1;
    }
    return lstrcmpiW(base, L"MDMRegistration.dll") == 0;
}

// 向缓冲区追加带双引号包裹的程序路径
static void AppendQuotedArg(wchar_t* dst, size_t maxChars, size_t& pos, const wchar_t* arg) {
    if (pos + 4 >= maxChars) return;
    if (pos > 0) dst[pos++] = L' ';
    dst[pos++] = L'"';
    for (const wchar_t* p = arg; *p && pos + 3 < maxChars; ++p) {
        if (*p == L'"') dst[pos++] = L'\\';
        dst[pos++] = *p;
    }
    dst[pos++] = L'"';
    dst[pos] = L'\0';
}

// ===================== 2. MDMRegistration 断点接管逻辑 =====================

static uintptr_t g_cachedMdmRva = 0;

static uintptr_t GetMdmFuncRva() {
    if (g_cachedMdmRva != 0) return g_cachedMdmRva;

    HMODULE hMdm = LoadLibraryExW(L"MDMRegistration.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!hMdm) return 0;

    FARPROC pFn = GetProcAddress(hMdm, "IsDeviceRegisteredWithManagement");
    if (pFn) {
        g_cachedMdmRva = (uintptr_t)pFn - (uintptr_t)hMdm;
    }
    FreeLibrary(hMdm);
    return g_cachedMdmRva;
}

static bool IsMdmRegistrationDll(HANDLE hProcess, const LOAD_DLL_DEBUG_INFO& info) {
    wchar_t path[2048] = { 0 };

    if (info.hFile && info.hFile != INVALID_HANDLE_VALUE) {
        DWORD len = GetFinalPathNameByHandleW(info.hFile, path, ARRAYSIZE(path), FILE_NAME_NORMALIZED);
        if (len > 0 && len < ARRAYSIZE(path)) {
            return IsMdmFileName(path);
        }
    }

    if (info.lpImageName != nullptr) {
        PVOID remoteStrPtr = nullptr;
        if (ReadProcessMemory(hProcess, info.lpImageName, &remoteStrPtr, sizeof(remoteStrPtr), nullptr) &&
            remoteStrPtr != nullptr) {
            if (info.fUnicode) {
                if (ReadProcessMemory(hProcess, remoteStrPtr, path, sizeof(path) - sizeof(wchar_t), nullptr)) {
                    path[ARRAYSIZE(path) - 1] = L'\0';
                    return IsMdmFileName(path);
                }
            } else {
                char pathA[2048] = { 0 };
                if (ReadProcessMemory(hProcess, remoteStrPtr, pathA, sizeof(pathA) - 1, nullptr)) {
                    pathA[ARRAYSIZE(pathA) - 1] = L'\0';
                    if (MultiByteToWideChar(CP_ACP, 0, pathA, -1, path, ARRAYSIZE(path)) > 0) {
                        return IsMdmFileName(path);
                    }
                }
            }
        }
    }

    return false;
}

static bool HandleMdmBreakpoint(HANDLE hProcess, DWORD dwThreadId, uintptr_t retInstAddr) {
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, dwThreadId);
    if (!hThread) return false;

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &ctx)) {
        CloseHandle(hThread);
        return false;
    }

    ULONG_PTR pRegistered = ctx.Rcx;
    DWORD cchUPN = (DWORD)ctx.Rdx;
    ULONG_PTR pUPN = ctx.R8;

    HRESULT hr = S_OK;
    if (pRegistered == 0) {
        hr = E_INVALIDARG;
    } else {
        BOOL isReg = TRUE;
        WriteProcessMemory(hProcess, (LPVOID)pRegistered, &isReg, sizeof(isReg), nullptr);

        if (pUPN != 0 && cchUPN != 0) {
            wchar_t configured_upn[512] = L"";
            DWORD chars = GetEnvironmentVariableW(
                L"BROWSER_POLICY_MDM_UPN", configured_upn, ARRAYSIZE(configured_upn));
            if (chars == 0 || chars >= ARRAYSIZE(configured_upn)) {
                chars = GetEnvironmentVariableW(
                    L"EDGE_POLICY_MDM_UPN", configured_upn, ARRAYSIZE(configured_upn));
            }

            const wchar_t* upn =
                (chars > 0 && chars < ARRAYSIZE(configured_upn))
                    ? configured_upn
                    : L"browser-policy-shim@example.invalid";

            size_t upnLen = (size_t)lstrlenW(upn);
            if (upnLen >= cchUPN) {
                size_t copyChars = cchUPN - 1;
                if (copyChars > 0) {
                    WriteProcessMemory(hProcess, (LPVOID)pUPN, upn, copyChars * sizeof(wchar_t), nullptr);
                }
                wchar_t nul = L'\0';
                WriteProcessMemory(hProcess, (LPVOID)(pUPN + copyChars * sizeof(wchar_t)), &nul, sizeof(nul), nullptr);
                hr = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
            } else {
                WriteProcessMemory(hProcess, (LPVOID)pUPN, upn, (upnLen + 1) * sizeof(wchar_t), nullptr);
                hr = S_OK;
            }
        }
    }

    ctx.Rip = retInstAddr;
    ctx.Rax = (ULONG_PTR)(LONG_PTR)hr;

    SetThreadContext(hThread, &ctx);
    CloseHandle(hThread);
    return true;
}

static void LaunchTarget(const wchar_t* appPath, wchar_t* cmdLine, const STARTUPINFOW& inheritedSi, bool isChildProcess) {
    STARTUPINFOW si = inheritedSi;
    si.cb = sizeof(STARTUPINFOW);
    si.lpReserved = nullptr;
    si.cbReserved2 = 0;
    si.lpReserved2 = nullptr;
    si.dwFlags &= ~STARTF_USESTDHANDLES;

    PROCESS_INFORMATION pi = { 0 };
    LPCWSTR applicationName = (appPath && (MyWcsChr(appPath, L'\\') || MyWcsChr(appPath, L'/'))) ? appPath : nullptr;
    DWORD createFlags = isChildProcess ? DEBUG_ONLY_THIS_PROCESS : DEBUG_PROCESS;

    if (!CreateProcessW(
            applicationName,
            cmdLine,
            nullptr,
            nullptr,
            FALSE,
            createFlags,
            nullptr,
            nullptr,
            &si,
            &pi)) {
        return;
    }

    DebugSetProcessKillOnExit(FALSE);

    BOOL isTargetWow64 = FALSE;
    IsWow64Process(pi.hProcess, &isTargetWow64);

    if (isChildProcess || isTargetWow64) {
        DebugActiveProcessStop(pi.dwProcessId);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return;
    }

    DEBUG_EVENT ev = { 0 };
    LPVOID remoteMdmBase = nullptr;
    uintptr_t remoteFuncAddr = 0;
    bool initialBreakpointSeen = false;

    while (WaitForDebugEvent(&ev, INFINITE)) {
        DWORD continueStatus = DBG_CONTINUE;

        switch (ev.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            if (ev.u.CreateProcessInfo.hFile) {
                CloseHandle(ev.u.CreateProcessInfo.hFile);
            }
            if (ev.dwProcessId != pi.dwProcessId) {
                if (ev.u.CreateProcessInfo.hThread) {
                    CloseHandle(ev.u.CreateProcessInfo.hThread);
                }
                if (ev.u.CreateProcessInfo.hProcess) {
                    CloseHandle(ev.u.CreateProcessInfo.hProcess);
                }
                DebugActiveProcessStop(ev.dwProcessId);
                continue;
            }
            break;

        case LOAD_DLL_DEBUG_EVENT:
            if (ev.dwProcessId == pi.dwProcessId && remoteFuncAddr == 0 &&
                IsMdmRegistrationDll(pi.hProcess, ev.u.LoadDll)) {
                uintptr_t rva = GetMdmFuncRva();
                if (rva != 0) {
                    remoteMdmBase = ev.u.LoadDll.lpBaseOfDll;
                    remoteFuncAddr = (uintptr_t)remoteMdmBase + rva;
                    BYTE patch[2] = { 0xCC, 0xC3 };
                    if (WriteProcessMemory(pi.hProcess, (LPVOID)remoteFuncAddr, patch, sizeof(patch), nullptr)) {
                        FlushInstructionCache(pi.hProcess, (LPVOID)remoteFuncAddr, sizeof(patch));
                    } else {
                        remoteFuncAddr = 0;
                    }
                }
            }
            if (ev.u.LoadDll.hFile) {
                CloseHandle(ev.u.LoadDll.hFile);
            }
            break;

        case UNLOAD_DLL_DEBUG_EVENT:
            if (ev.dwProcessId == pi.dwProcessId && ev.u.UnloadDll.lpBaseOfDll == remoteMdmBase) {
                remoteMdmBase = nullptr;
                remoteFuncAddr = 0;
            }
            break;

        case EXCEPTION_DEBUG_EVENT: {
            DWORD code = ev.u.Exception.ExceptionRecord.ExceptionCode;
            uintptr_t addr = (uintptr_t)ev.u.Exception.ExceptionRecord.ExceptionAddress;

            if (code == EXCEPTION_BREAKPOINT) {
                if (ev.dwProcessId == pi.dwProcessId && remoteFuncAddr != 0 && addr == remoteFuncAddr) {
                    HandleMdmBreakpoint(pi.hProcess, ev.dwThreadId, remoteFuncAddr + 1);
                    continueStatus = DBG_CONTINUE;
                } else if (ev.dwProcessId == pi.dwProcessId && !initialBreakpointSeen) {
                    initialBreakpointSeen = true;
                    continueStatus = DBG_CONTINUE;
                } else {
                    continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                }
            } else {
                continueStatus = DBG_EXCEPTION_NOT_HANDLED;
            }
            break;
        }

        case EXIT_PROCESS_DEBUG_EVENT:
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
            if (ev.dwProcessId == pi.dwProcessId) {
                goto cleanup;
            }
            continue;

        default:
            break;
        }

        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, continueStatus);
    }

cleanup:
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

// ===================== 3. Zero-CRT 原生入口点 =====================

extern "C" void WINAPI wWinMainCRTStartup() {
    STARTUPINFOW currentSi = { sizeof(currentSi) };
    GetStartupInfoW(&currentSi);
    bool isLaunchedFromShortcut = (currentSi.dwFlags & STARTF_TITLEISLINKNAME) != 0;

    const wchar_t* rawFullCmd = GetCommandLineW();
    const wchar_t* rawTargetCmd = nullptr;

    wchar_t selfPath[2048] = { 0 };
    if (!NextCmdArg(rawFullCmd, selfPath, ARRAYSIZE(selfPath), &rawTargetCmd) || !rawTargetCmd) {
        ExitProcess(0);
    }

    wchar_t firstTargetArg[2048] = { 0 };
    const wchar_t* restArgs = nullptr;
    NextCmdArg(rawTargetCmd, firstTargetArg, ARRAYSIZE(firstTargetArg), &restArgs);

    const wchar_t* appPath = nullptr;
    bool prependExeToCmd = false;

    bool firstHasSlash = (MyWcsChr(firstTargetArg, L'\\') != nullptr || MyWcsChr(firstTargetArg, L'/') != nullptr);
    bool titleIsFullExe = (!isLaunchedFromShortcut && currentSi.lpTitle &&
                           (MyWcsChr(currentSi.lpTitle, L'\\') || MyWcsChr(currentSi.lpTitle, L'/')) &&
                           EndsWithExe(currentSi.lpTitle));

    if (firstTargetArg[0] != L'-' && firstTargetArg[0] != L'/' && EndsWithExe(firstTargetArg)) {
        appPath = (!firstHasSlash && titleIsFullExe) ? currentSi.lpTitle : firstTargetArg;
    } else if (titleIsFullExe) {
        appPath = currentSi.lpTitle;
        if (!firstHasSlash && MatchesExeStem(firstTargetArg, currentSi.lpTitle)) {
            prependExeToCmd = false;
        } else {
            prependExeToCmd = true;
        }
    } else {
        ExitProcess(0);
    }

    const size_t kBufSize = 32768;
    wchar_t* newCmd = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, kBufSize * sizeof(wchar_t));
    if (!newCmd) {
        ExitProcess(0);
    }

    bool isChildProcess = false;

    if (isLaunchedFromShortcut) {
        size_t pos = 0;
        AppendQuotedArg(newCmd, kBufSize, pos, appPath);
    } else {
        if (prependExeToCmd) {
            size_t pos = 0;
            AppendQuotedArg(newCmd, kBufSize, pos, appPath);
            if (*rawTargetCmd && pos + 1 < kBufSize) {
                newCmd[pos++] = L' ';
                lstrcpynW(newCmd + pos, rawTargetCmd, (int)(kBufSize - pos));
            }
        } else {
            lstrcpynW(newCmd, rawTargetCmd, (int)kBufSize);
        }

        wchar_t argBuf[512] = { 0 };
        const wchar_t* scan = prependExeToCmd ? rawTargetCmd : restArgs;
        while (scan && NextCmdArg(scan, argBuf, ARRAYSIZE(argBuf), &scan)) {
            if (MyWcsNCmp(argBuf, L"--type=", 7) == 0 ||
                MyWcsNCmp(argBuf, L"--mojo-platform-channel-handle=", 31) == 0) {
                isChildProcess = true;
                break;
            }
        }
    }

    LaunchTarget(appPath, newCmd, currentSi, isChildProcess);

    HeapFree(GetProcessHeap(), 0, newCmd);
    ExitProcess(0);
}