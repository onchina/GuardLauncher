#ifndef _WIN64
#error "此代码针对 x64 架构编写，请使用 x64 编译器编译。"
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifndef STARTF_TITLEISLINKNAME
#define STARTF_TITLEISLINKNAME 0x00000800
#endif

#ifndef STATUS_OBJECT_NAME_NOT_FOUND
#define STATUS_OBJECT_NAME_NOT_FOUND ((DWORD)0xC0000034L)
#endif

// ===================== 0. Zero-CRT 编译器内在函数支持 =====================
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

static bool EndsWithExe(const wchar_t* s) {
    if (!s) return false;
    int len = lstrlenW(s);
    if (len < 4) return false;
    return CompareStringOrdinal(s + len - 4, 4, L".exe", 4, TRUE) == CSTR_EQUAL;
}

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

static bool IsMdmFileName(const wchar_t* path) {
    if (!path || !*path) return false;
    const wchar_t* base = path;
    for (const wchar_t* p = path; *p; ++p) {
        if (*p == L'\\' || *p == L'/') base = p + 1;
    }
    return lstrcmpiW(base, L"MDMRegistration.dll") == 0;
}

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

// ===================== 2. 断点接管逻辑（MDM 策略 + 子进程 IFEO 屏蔽） =====================

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

// 获取 ntdll!LdrQueryImageFileExecutionOptionsEx 地址（同系统下 ntdll 映射基址全进程一致）
static uintptr_t GetLdrQueryIfeoAddr() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return 0;
    FARPROC pFn = GetProcAddress(hNtdll, "LdrQueryImageFileExecutionOptionsEx");
    if (!pFn) {
        pFn = GetProcAddress(hNtdll, "LdrQueryImageFileExecutionOptions");
    }
    return (uintptr_t)pFn;
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

// 处理 LdrQueryImageFileExecutionOptionsEx(SubKey, ValueName, ...) 断点：
// 当浏览器主进程创建子进程查询 "Debugger" 键值时，返回 STATUS_OBJECT_NAME_NOT_FOUND 以跳过 IFEO
static bool HandleIfeoQueryBreakpoint(
    HANDLE hProcess,
    DWORD dwThreadId,
    uintptr_t ldrFuncAddr,
    const BYTE origBytes[2],
    DWORD& outSingleStepThreadId) {
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, dwThreadId);
    if (!hThread) return false;

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &ctx)) {
        CloseHandle(hThread);
        return false;
    }

    // x64 调用约定：RCX = PUNICODE_STRING SubKey, RDX = PCWSTR ValueName
    wchar_t valName[16] = { 0 };
    bool isDebuggerQuery = false;
    if (ctx.Rdx != 0 &&
        ReadProcessMemory(hProcess, (LPCVOID)ctx.Rdx, valName, sizeof(valName) - sizeof(wchar_t), nullptr)) {
        valName[ARRAYSIZE(valName) - 1] = L'\0';
        if (lstrcmpiW(valName, L"Debugger") == 0) {
            isDebuggerQuery = true;
        }
    }

    if (isDebuggerQuery) {
        // 拦截 "Debugger" 查询，执行紧随其后的 0xC3 (RET) 并返回 STATUS_OBJECT_NAME_NOT_FOUND
        ctx.Rip = ldrFuncAddr + 1;
        ctx.Rax = (ULONG_PTR)STATUS_OBJECT_NAME_NOT_FOUND;
        outSingleStepThreadId = 0;
    } else {
        // 其他查询（如 GlobalFlag / MitigationOptions）：临时恢复原 2 字节并用单步标志放行原指令
        WriteProcessMemory(hProcess, (LPVOID)ldrFuncAddr, origBytes, 2, nullptr);
        FlushInstructionCache(hProcess, (LPVOID)ldrFuncAddr, 2);
        ctx.Rip = ldrFuncAddr;
        ctx.EFlags |= 0x100; // Trap Flag (单步执行 1 条指令后触发 EXCEPTION_SINGLE_STEP 重新下断)
        outSingleStepThreadId = dwThreadId;
    }

    SetThreadContext(hThread, &ctx);
    CloseHandle(hThread);
    return true;
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

    // 仅调试当前主进程，并在挂起状态下先部署断点再恢复运行
    DWORD createFlags = DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED;

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
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return;
    }

    // 在主进程开始执行前，在 ntdll!LdrQueryImageFileExecutionOptionsEx 部署断点屏蔽子进程 IFEO
    uintptr_t ldrIfeoAddr = GetLdrQueryIfeoAddr();
    BYTE origLdrBytes[2] = { 0 };
    bool ldrHooked = false;

    if (ldrIfeoAddr != 0 &&
        ReadProcessMemory(pi.hProcess, (LPCVOID)ldrIfeoAddr, origLdrBytes, sizeof(origLdrBytes), nullptr)) {
        BYTE patch[2] = { 0xCC, 0xC3 };
        if (WriteProcessMemory(pi.hProcess, (LPVOID)ldrIfeoAddr, patch, sizeof(patch), nullptr)) {
            FlushInstructionCache(pi.hProcess, (LPVOID)ldrIfeoAddr, sizeof(patch));
            ldrHooked = true;
        }
    }

    // 恢复主进程执行
    ResumeThread(pi.hThread);

    DEBUG_EVENT ev = { 0 };
    LPVOID remoteMdmBase = nullptr;
    uintptr_t remoteMdmFuncAddr = 0;
    DWORD singleStepThreadId = 0;
    bool initialBreakpointSeen = false;

    while (WaitForDebugEvent(&ev, INFINITE)) {
        DWORD continueStatus = DBG_CONTINUE;

        switch (ev.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            if (ev.u.CreateProcessInfo.hFile) {
                CloseHandle(ev.u.CreateProcessInfo.hFile);
            }
            break;

        case LOAD_DLL_DEBUG_EVENT:
            if (ev.dwProcessId == pi.dwProcessId && remoteMdmFuncAddr == 0 &&
                IsMdmRegistrationDll(pi.hProcess, ev.u.LoadDll)) {
                uintptr_t rva = GetMdmFuncRva();
                if (rva != 0) {
                    remoteMdmBase = ev.u.LoadDll.lpBaseOfDll;
                    remoteMdmFuncAddr = (uintptr_t)remoteMdmBase + rva;
                    BYTE patch[2] = { 0xCC, 0xC3 };
                    if (WriteProcessMemory(pi.hProcess, (LPVOID)remoteMdmFuncAddr, patch, sizeof(patch), nullptr)) {
                        FlushInstructionCache(pi.hProcess, (LPVOID)remoteMdmFuncAddr, sizeof(patch));
                    } else {
                        remoteMdmFuncAddr = 0;
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
                remoteMdmFuncAddr = 0;
            }
            break;

        case EXCEPTION_DEBUG_EVENT: {
            DWORD code = ev.u.Exception.ExceptionRecord.ExceptionCode;
            uintptr_t addr = (uintptr_t)ev.u.Exception.ExceptionRecord.ExceptionAddress;

            if (code == EXCEPTION_BREAKPOINT) {
                if (ev.dwProcessId == pi.dwProcessId && ldrHooked && addr == ldrIfeoAddr) {
                    HandleIfeoQueryBreakpoint(pi.hProcess, ev.dwThreadId, ldrIfeoAddr, origLdrBytes, singleStepThreadId);
                    continueStatus = DBG_CONTINUE;
                } else if (ev.dwProcessId == pi.dwProcessId && remoteMdmFuncAddr != 0 && addr == remoteMdmFuncAddr) {
                    HandleMdmBreakpoint(pi.hProcess, ev.dwThreadId, remoteMdmFuncAddr + 1);
                    continueStatus = DBG_CONTINUE;
                } else if (ev.dwProcessId == pi.dwProcessId && !initialBreakpointSeen) {
                    initialBreakpointSeen = true;
                    continueStatus = DBG_CONTINUE;
                } else {
                    continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                }
            } else if (code == EXCEPTION_SINGLE_STEP &&
                       ev.dwProcessId == pi.dwProcessId &&
                       singleStepThreadId != 0 &&
                       ev.dwThreadId == singleStepThreadId) {
                // 单步放行 1 条原指令后，立即重新写入 0xCC, 0xC3 断点
                BYTE patch[2] = { 0xCC, 0xC3 };
                WriteProcessMemory(pi.hProcess, (LPVOID)ldrIfeoAddr, patch, sizeof(patch), nullptr);
                FlushInstructionCache(pi.hProcess, (LPVOID)ldrIfeoAddr, sizeof(patch));
                singleStepThreadId = 0;
                continueStatus = DBG_CONTINUE;
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
