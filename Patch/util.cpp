// util.cpp

#include "util.h"


//=============================================================================
// Logger
//=============================================================================


static CAtlFile gLogFile;


void LogInit(LPCWSTR lpFileName)
{
    gLogFile.Create(lpFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_ALWAYS);
    gLogFile.Seek(0, FILE_END);
}


void LogWrite(LPCSTR lpMessage, ...)
{
    CStringA str;
    va_list args;

    va_start(args, lpMessage);
    str.FormatV(lpMessage, args);
    va_end(args);

    CStringW ucs = AnsiToUcs2(CP_ACP, str);
    CStringA utf = Ucs2ToUtf8(ucs);

    gLogFile.Write(utf.GetString(), utf.GetLength());
}


void LogWrite(LPCWSTR lpMessage, ...)
{
    CStringW str;
    va_list args;

    va_start(args, lpMessage);
    str.FormatV(lpMessage, args);
    va_end(args);

    CStringA utf = Ucs2ToUtf8(str);
    gLogFile.Write(utf.GetString(), utf.GetLength());
}


void LogWriteLine(LPCSTR lpMessage, ...)
{
    CStringA str;
    va_list args;

    time_t t;
    char tstr[32];
    time(&t);
    ctime_s(tstr, _countof(tstr), &t);

    str.Append(tstr);
    str.AppendChar(' ');

    va_start(args, lpMessage);
    str.AppendFormatV(lpMessage, args);
    va_end(args);

    str.Append("\r\n");

    CStringW ucs = AnsiToUcs2(CP_ACP, str);
    CStringA utf = Ucs2ToUtf8(ucs);

    gLogFile.Write(utf.GetString(), utf.GetLength());
}


void LogWriteLine(LPCWSTR lpMessage, ...)
{
    CStringW str;
    va_list args;

    time_t t;
    wchar_t tstr[32];
    time(&t);
    _wctime_s(tstr, _countof(tstr), &t);

    str.Append(tstr);
    str.AppendChar(L' ');

    va_start(args, lpMessage);
    str.AppendFormatV(lpMessage, args);
    va_end(args);

    str.Append(L"\r\n");

    CStringA utf = Ucs2ToUtf8(str);
    gLogFile.Write(utf.GetString(), utf.GetLength());
}

void MakeConsole()
{
	FILE* fp = NULL;
	AllocConsole();
    SetConsoleTitle(L"Debug Console");
	SetConsoleCtrlHandler(NULL, true);
	freopen_s(&fp, "CONIN$", "r", stdin);
	freopen_s(&fp, "CONOUT$", "w", stdout);
}

//=============================================================================
// Pattern Search Helper
//=============================================================================


PVOID GetModuleBase(HMODULE hModule)
{
    MEMORY_BASIC_INFORMATION mem;

    if (!VirtualQuery(hModule, &mem, sizeof(mem)))
        return NULL;

    return mem.AllocationBase;
}


DWORD GetModuleSize(HMODULE hModule)
{
    return ((IMAGE_NT_HEADERS*)((DWORD_PTR)hModule + ((IMAGE_DOS_HEADER*)hModule)->e_lfanew))->OptionalHeader.SizeOfImage;
}


PVOID SearchPattern(PVOID lpStartSearch, DWORD dwSearchLen, const char* lpPattern, DWORD dwPatternLen)
{
    ULONG_PTR dwStartAddr = (ULONG_PTR)lpStartSearch;
    ULONG_PTR dwEndAddr = dwStartAddr + dwSearchLen - dwPatternLen;

    while (dwStartAddr < dwEndAddr)
    {
        bool found = true;

        for (DWORD i = 0; i < dwPatternLen; i++)
        {
            char code = *(char*)(dwStartAddr + i);

            if (lpPattern[i] != 0x2A && lpPattern[i] != code)
            {
                found = false;
                break;
            }
        }

        if (found)
            return (PVOID)dwStartAddr;

        dwStartAddr++;
    }

    return 0;
}


//=============================================================================
// Patch Helper
//=============================================================================

void PatchRead(LPVOID lpAddr, LPVOID lpBuf, DWORD nSize)
{
    _ASSERT(lpAddr != NULL);
    _ASSERT(lpBuf != NULL);
    _ASSERT(nSize != 0);

    DWORD dwProtect;
    if (VirtualProtect(lpAddr, nSize, PAGE_EXECUTE_READWRITE, &dwProtect))
    {
        CopyMemory(lpBuf, lpAddr, nSize);
        VirtualProtect(lpAddr, nSize, dwProtect, &dwProtect);
    }
    else
    {
        FatalError("Failed to modify protection at %08X !", lpAddr);
    }
}


void PatchWrite(LPVOID lpAddr, LPCVOID lpBuf, DWORD nSize)
{
    _ASSERT(lpAddr != NULL);
    _ASSERT(lpBuf != NULL);
    _ASSERT(nSize != 0);

    DWORD dwProtect;
    if (VirtualProtect(lpAddr, nSize, PAGE_EXECUTE_READWRITE, &dwProtect))
    {
        CopyMemory(lpAddr, lpBuf, nSize);
        VirtualProtect(lpAddr, nSize, dwProtect, &dwProtect);
    }
    else
    {
        FatalError("Failed to modify protection at %08X !", lpAddr);
    }
}


void PatchNop(LPVOID lpAddr, int nCount)
{
    _ASSERT(lpAddr != NULL);
    _ASSERT(nCount != 0);

    DWORD dwProtect;
    if (VirtualProtect(lpAddr, nCount, PAGE_EXECUTE_READWRITE, &dwProtect))
    {
        memset(lpAddr, 0x90, nCount);
        VirtualProtect(lpAddr, nCount, dwProtect, &dwProtect);
    }
    else
    {
        FatalError("Failed to modify protection at %08X !", lpAddr);
    }
}


void PatchWriteStringA(LPVOID lpAddr, LPCSTR lpBuf)
{
    _ASSERT(lpAddr != NULL);
    _ASSERT(lpBuf != NULL);
    DWORD srcLen = strlen((LPCSTR)lpAddr);
    DWORD newLen = strlen(lpBuf);
    if (newLen > srcLen)
        FatalError("PatchWriteStringA: No enough space.");
    DWORD nSize = newLen + 1;
    PatchWrite(lpAddr, lpBuf, nSize);
}


void PatchWriteStringW(LPVOID lpAddr, LPCWSTR lpBuf)
{
    _ASSERT(lpAddr != NULL);
    _ASSERT(lpBuf != NULL);
    DWORD srcLen = wcslen((LPCWSTR)lpAddr);
    DWORD newLen = wcslen(lpBuf);
    if (newLen > srcLen)
        FatalError("PatchWriteStringW: No enough space.");
    DWORD nSize = (newLen + 1) * sizeof(WCHAR);
    PatchWrite(lpAddr, lpBuf, nSize);
}


void FixR6002(HMODULE BaseAddr)
{
	//   004947D5  |.  8B40 24                      MOV EAX,DWORD PTR DS:[EAX+24]
	//   004947D8  |.  C1E8 1F                      SHR EAX,1F
	//   004947DB  |.  F7D0                         NOT EAX
	//   004947DD  |.  83E0 01                      AND EAX,00000001
    SignaturePatch(BaseAddr, R6002SIG, '\xC8', 9);
	//PVOID nNWAddress = SearchPattern(GetModuleBase((HMODULE)(BaseAddr)), GetModuleSize((HMODULE)(BaseAddr)), R6002SIG, sizeofsig(R6002SIG));
	//if (nNWAddress) 
 //   {
	//	// 83    C8
	//	// AND ->OR
 //       PatchWrite((LPVOID)((DWORD)nNWAddress + 9), '\xC8');
	//}
}


void PatchJump(DWORD base, DWORD hook_func, DWORD hook_position)
{
	hook_position += base;
	DWORD ret_addr = hook_func - (hook_position + 5);
	PatchWrite((LPVOID)hook_position, '\xE9');
	PatchWrite((LPVOID)(hook_position + 1), &ret_addr, sizeof(int));
}

void PatchCall(DWORD base, DWORD hook_func, DWORD hook_position)
{
	hook_position += base;
	DWORD ret_addr = hook_func - (hook_position + 5);
	PatchWrite((LPVOID)hook_position, '\xE8');
	PatchWrite((LPVOID)(hook_position + 1), &ret_addr, sizeof(int));
}

//=============================================================================
// Hook Helper
//=============================================================================


static inline PBYTE RvaAdjust(_Pre_notnull_ PIMAGE_DOS_HEADER pDosHeader, _In_ DWORD raddr)
{
    if (raddr != NULL) {
        return ((PBYTE)pDosHeader) + raddr;
    }
    return NULL;
}


BOOL IATHook(HMODULE hModule, PCSTR pszFileName, PCSTR pszProcName, PVOID pNewProc)
{
    _ASSERT(pszFileName != NULL);
    _ASSERT(pszProcName != NULL);
    _ASSERT(pNewProc != NULL);

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;

    if (hModule == NULL)
        pDosHeader = (PIMAGE_DOS_HEADER)GetModuleHandleW(NULL);

    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + pDosHeader->e_lfanew);

    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    if (pNtHeader->FileHeader.SizeOfOptionalHeader == 0)
        return FALSE;

    PIMAGE_IMPORT_DESCRIPTOR iidp = (PIMAGE_IMPORT_DESCRIPTOR)RvaAdjust(pDosHeader, pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    if (iidp == NULL)
        return FALSE;

    for (; iidp->OriginalFirstThunk != 0; iidp++)
    {
        PCSTR pszName = (PCHAR)RvaAdjust(pDosHeader, iidp->Name);

        if (pszName == NULL)
            return FALSE;

        if (_stricmp(pszName, pszFileName) != 0)
            continue;

        PIMAGE_THUNK_DATA pThunks = (PIMAGE_THUNK_DATA)RvaAdjust(pDosHeader, iidp->OriginalFirstThunk);
        PVOID* pAddrs = (PVOID*)RvaAdjust(pDosHeader, iidp->FirstThunk);

        if (pThunks == NULL)
            continue;

        for (DWORD nNames = 0; pThunks[nNames].u1.Ordinal; nNames++)
        {
            DWORD nOrdinal = 0;
            PCSTR pszFunc = NULL;

            if (IMAGE_SNAP_BY_ORDINAL(pThunks[nNames].u1.Ordinal))
                nOrdinal = (DWORD)IMAGE_ORDINAL(pThunks[nNames].u1.Ordinal);
            else
                pszFunc = (PCSTR)RvaAdjust(pDosHeader, (DWORD)pThunks[nNames].u1.AddressOfData + 2);

            if (pszFunc == NULL)
                continue;

            if (strcmp(pszFunc, pszProcName) != 0)
                continue;

            PatchWrite(&pAddrs[nNames], pNewProc);
            return TRUE;
        }
    }

    return FALSE;
}


//=============================================================================
// Encoding
//=============================================================================


CStringW AnsiToUcs2(int cp, const CStringA& str)
{
    if (str.GetLength() == 0)
        return CStringW();
    int nLen = MultiByteToWideChar(cp, 0, str.GetString(), str.GetLength(), NULL, 0);
    if (nLen == 0)
        return CStringW();
    CStringW ret(L'\0', nLen);
    if (MultiByteToWideChar(cp, 0, str.GetString(), str.GetLength(), ret.GetBuffer(), ret.GetAllocLength()) == 0)
        return CStringW();
    return ret;
}


CStringA Ucs2ToAnsi(int cp, const CStringW& str, LPCCH defChar)
{
    if (str.GetLength() == 0)
        return CStringA();
    int nLen = WideCharToMultiByte(cp, 0, str.GetString(), str.GetLength(), NULL, 0, NULL, NULL);
    if (nLen == 0)
        return CStringA();
    CStringA ret('\0', nLen);
    if (WideCharToMultiByte(cp, 0, str.GetString(), str.GetLength(), ret.GetBuffer(), ret.GetAllocLength(), defChar, NULL) == 0)
        return CStringA();
    return ret;
}


CStringW Utf8ToUcs2(const CStringA& str)
{
    return AnsiToUcs2(CP_UTF8, str);
}


CStringA Ucs2ToUtf8(const CStringW& str)
{
    return Ucs2ToAnsi(CP_UTF8, str, "?");
}


CStringW ShiftJisToUcs2(const CStringA& str)
{
    return AnsiToUcs2(CP_SHIFTJIS, str);
}


CStringA Ucs2ToShiftJis(const CStringW& str)
{
    return Ucs2ToAnsi(CP_SHIFTJIS, str, "?");
}


CStringW GbkToUcs2(const CStringA& str)
{
    return AnsiToUcs2(CP_GBK, str);
}


CStringA Ucs2ToGbk(const CStringW& str)
{
    return Ucs2ToAnsi(CP_GBK, str, "?");
}


//=============================================================================
// String Helper
//=============================================================================


void ConvertStringCodePage(LPSTR lpBuf, int srcCP, int dstCP, LPCCH defChar)
{
    _ASSERT(lpBuf != NULL);
    CStringW ucs = AnsiToUcs2(srcCP, lpBuf);
    CStringA ansi = Ucs2ToAnsi(dstCP, ucs, defChar);
    PatchWriteStringA(lpBuf, ansi);
}


//=============================================================================
// File & Path
//=============================================================================


CPathA GetAppDirectoryA()
{
    CHAR szPath[MAX_PATH];
    GetModuleFileNameA(GetModuleHandleA(NULL), szPath, ARRAYSIZE(szPath));
    if (GetLastError() != ERROR_SUCCESS)
        return CPathA();
    CPathA ret(szPath);
    if (ret.RemoveFileSpec() != TRUE)
        return CPathA();
    return ret;
}


CPathW GetAppDirectoryW()
{
    WCHAR szPath[MAX_PATH];
    GetModuleFileNameW(GetModuleHandleW(NULL), szPath, ARRAYSIZE(szPath));
    if (GetLastError() != ERROR_SUCCESS)
        return CPathW();
    CPathW ret(szPath);
    if (ret.RemoveFileSpec() != TRUE)
        return CPathW();
    return ret;
}


CPathA GetAppPathA()
{
    CHAR szPath[MAX_PATH];
    GetModuleFileNameA(GetModuleHandleA(NULL), szPath, ARRAYSIZE(szPath));
    if (GetLastError() != ERROR_SUCCESS)
        return CPathA();
    return CPathA(szPath);
}


CPathW GetAppPathW()
{
    WCHAR szPath[MAX_PATH];
    GetModuleFileNameW(GetModuleHandleW(NULL), szPath, ARRAYSIZE(szPath));
    if (GetLastError() != ERROR_SUCCESS)
        return CPathW();
    return CPathW(szPath);
}


//=============================================================================
// Error Handling
//=============================================================================


__declspec(noreturn) void FatalError(LPCSTR lpMessage, ...)
{
    CStringA strMsg;
    va_list args;

    va_start(args, lpMessage);
    strMsg.FormatV(lpMessage, args);
    va_end(args);

    MessageBoxA(GetActiveWindow(), strMsg, "Fatal Error", MB_OK | MB_ICONERROR);
    ExitProcess(1);
}


__declspec(noreturn) void FatalError(LPCWSTR lpMessage, ...)
{
    CStringW strMsg;
    va_list args;

    va_start(args, lpMessage);
    strMsg.FormatV(lpMessage, args);
    va_end(args);

    MessageBoxW(GetActiveWindow(), strMsg, L"Fatal Error", MB_OK | MB_ICONERROR);
    ExitProcess(1);
}


void Inform(LPCSTR lpMessage, ...)
{
	CStringA strMsg;
	va_list args;

	va_start(args, lpMessage);
	strMsg.FormatV(lpMessage, args);
	va_end(args);

	MessageBoxA(NULL, strMsg, "Information", MB_OK | MB_ICONINFORMATION);
}



void Inform(LPCWSTR lpMessage, ...)
{
	CStringW strMsg;
	va_list args;

	va_start(args, lpMessage);
	strMsg.FormatV(lpMessage, args);
	va_end(args);

	MessageBoxW(NULL, strMsg, L"Information", MB_OK | MB_ICONINFORMATION);
}

//=============================================================================
// PE Helper
//=============================================================================


PIMAGE_SECTION_HEADER FindSectionFromModule(HMODULE hModule, PCSTR pName)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;

    if (hModule == NULL)
        pDosHeader = (PIMAGE_DOS_HEADER)GetModuleHandleW(NULL);

    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + pDosHeader->e_lfanew);

    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    if (pNtHeader->FileHeader.SizeOfOptionalHeader == 0)
        return NULL;

    PIMAGE_SECTION_HEADER pSectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)pNtHeader + sizeof(pNtHeader->Signature) + sizeof(pNtHeader->FileHeader) + pNtHeader->FileHeader.SizeOfOptionalHeader);

    for (DWORD n = 0; n < pNtHeader->FileHeader.NumberOfSections; n++)
    {
        if (strcmp((PCHAR)pSectionHeaders[n].Name, pName) == 0)
        {
            if (pSectionHeaders[n].VirtualAddress == 0 || pSectionHeaders[n].SizeOfRawData == 0)
                return NULL;

            return &pSectionHeaders[n];
        }
    }

    return NULL;
}


//=============================================================================
// GUI
//=============================================================================


#ifdef _UNICODE
#if defined _M_IX86
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_X64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#else
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif
#endif


static HANDLE ActCtx = INVALID_HANDLE_VALUE;
static ULONG_PTR ActCookie = 0;

void InitComCtl(HMODULE hModule)
{
    if (ActCtx != INVALID_HANDLE_VALUE)
        return;

    ACTCTXW ctx = {};
    ctx.cbSize = sizeof(ctx);
    ctx.dwFlags = ACTCTX_FLAG_HMODULE_VALID | ACTCTX_FLAG_RESOURCE_NAME_VALID;
    ctx.lpResourceName = MAKEINTRESOURCEW(2);
    ctx.hModule = hModule;
    // This sample implies your DLL stores Common Controls version 6.0 manifest in its resources with ID 2.

    ActCtx = CreateActCtxW(&ctx);

    if (ActCtx == INVALID_HANDLE_VALUE)
        return;

    ActivateActCtx(ActCtx, &ActCookie);
}


void ReleaseComCtl()
{
    if (ActCtx == INVALID_HANDLE_VALUE)
        return;

    DeactivateActCtx(0, ActCookie);
    ReleaseActCtx(ActCtx);
}

