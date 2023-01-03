// main.cpp
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlwapi.h>
#include <detours.h>
#include <codecvt>
#include "../ThirdParty/LeksysINI/iniparser.hpp"

int WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nShowCmd)
{
    static WCHAR szDirPath[2048];
    static WCHAR szAppPath[2048];
    static WCHAR szCfgPath[2048];

    GetModuleFileNameW(hInstance, szDirPath, ARRAYSIZE(szDirPath));
    if (GetLastError() != ERROR_SUCCESS)
        return 1;

    PathRemoveFileSpecW(szDirPath);
    PathAddBackslashW(szDirPath);
    PathCombineW(szCfgPath, szDirPath, L"config.ini");

    INI::File conf;

    std::ifstream ifs(szCfgPath, std::ios::binary);
    if (ifs.is_open())
    {
        ifs >> conf;
        ifs.close();
    }
    else 
    {
        MessageBoxW(NULL, L"无法打开配置文件，请确保当前目录下有config.ini！", L"错误", MB_OK|MB_APPLMODAL);
        exit(-1);
    }
	std::wstring_convert<std::codecvt_utf8<wchar_t> > convert;
    PathCombineW(szAppPath, szDirPath, convert.from_bytes(conf.GetSection("StartupSettings")->GetValue("Target").AsString()).c_str());

    STARTUPINFOW startupInfo = { sizeof(startupInfo) };
    PROCESS_INFORMATION processInfo = {};
    LPCSTR rgDlls[1] = { "payload.dll" };

    if (DetourCreateProcessWithDllsW(szAppPath, NULL, NULL, NULL, FALSE, NULL, NULL, szDirPath, &startupInfo, &processInfo, ARRAYSIZE(rgDlls), rgDlls, NULL) != TRUE)
        return 1;

#if 0
    WaitForSingleObject(processInfo.hProcess, INFINITE);

    DWORD exitCode;
    GetExitCodeProcess(processInfo.hProcess, &exitCode);

    return exitCode;
#else
    return 0;
#endif
}
