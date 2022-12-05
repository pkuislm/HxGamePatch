// dllmain.cpp

#include "util.h"
#include <detours.h>
#include <iostream>
#include "tp_stub.h"
#include "signatures.h"
#include <fstream>
#include <thread>
#include <sstream>

extern "C"
{
	typedef HRESULT(_stdcall* tTVPV2LinkProc)(iTVPFunctionExporter*);
	typedef HRESULT(_stdcall* tTVPV2UnlinkProc)();
}

//fastcall是thiscall的替代，因为fastcall使用eax, ecx传递前两个参数，而thiscall用ecx传递this指针，使用时只需抛弃掉第一个参数即可
typedef tTJSString*         (__fastcall* CSMFS_GetPathHash)	 (void*, void*, tTJSString*, tTJSString*);
typedef bool                (__fastcall* CSMFS_FindEntry)    (void*, void*, tTJSString*, tTJSString*, tTJSString*, tTJSVariant*);
typedef int                 (__fastcall* CSMFS_Mount)        (void*, void*, tTJSVariant*, tTJSVariant*, tTJSVariant*);


typedef bool                (__cdecl* CSMFS_CheckExistenceStorage)	(void*, tTJSString*);
typedef tTJSBinaryStream*	(__cdecl* CSMFS_Open)                   (void*, tTJSString*, int);
typedef int                 (__cdecl* CSMFS_Constructor)            (void**, tTJSVariant*, int, tTJSVariant**);

//#define COUT(x) std::cout << x << std::endl;
//#define ONLY_BYPASS_SIGCHECK                  //仅过验证，不安装文件相关hook
constexpr int PACKAGE_AMOUNT = 5;               //游戏一共（至少）要加载多少封包

static HMODULE EBaseAddr = 0;//game.exe基址
static HMODULE CBaseAddr = 0;//cxdec.dll基址
static DWORD pMyLoadCXAndPatch = 0;
//放一个标志指示Cxdec是否已经加载
static bool IsLoadedCxdec = false;
//指示文件系统是否加载完成，即是否可以dump文件
static bool IsFSInitialized = false;
//记录游戏一共调用Mount加载了几个封包（根据这个判断是否加载完成）
static int PackagesLoaded = 0;

//这个类的详细定义并不在tp_stub.h里，因为他是一个内部类
class tTJSBinaryStream
{
public:
	virtual tjs_uint64 TJS_INTF_METHOD Seek(tjs_int64 offset, tjs_int whence) = 0;
	virtual tjs_uint TJS_INTF_METHOD Read(void* buffer, tjs_uint read_size) = 0;
	virtual tjs_uint TJS_INTF_METHOD Write(const void* buffer, tjs_uint write_size) = 0;
	virtual void TJS_INTF_METHOD SetEndOfStorage() = 0;
	virtual tjs_uint64 TJS_INTF_METHOD GetSize() = 0;
	virtual ~tTJSBinaryStream() { }
};


void DumpAllScripts();
tTJSBinaryStream* MyOpen(void* a, tTJSString* name, int flags);
int __fastcall MyMount(void* a, void* notused, tTJSVariant* b, tTJSVariant* c, tTJSVariant* d);
bool __fastcall MyFindEntry(void* a, void* notused, tTJSString* b, tTJSString* c, tTJSString* d, tTJSVariant* e);
bool MyCheckExistenceStorage(void* a, tTJSString* b);


//在这里设置并存储this指针以及相关成员函数的指针
//因为this里有vftable，所以可能有点多此一举
struct CX_Funcs
{
	CSMFS_GetPathHash m_GetPathHash;
	CSMFS_FindEntry m_FindEntry;
	CSMFS_CheckExistenceStorage m_CheckExistenceStorage;
	CSMFS_Open m_Open;
    CSMFS_Mount m_Mount;
	void* m_this;

	void SetUpFuncPointers(void* CompoundStorageMedia)
	{
        auto base = GetModuleBase(CBaseAddr);
        auto size = GetModuleSize(CBaseAddr);
        m_this = CompoundStorageMedia;
        m_CheckExistenceStorage = (CSMFS_CheckExistenceStorage)SearchPattern(base, size, CX_CSMediaFS_CheckExistenceStorage, sizeofsig(CX_CSMediaFS_CheckExistenceStorage));
        m_FindEntry = (CSMFS_FindEntry)SearchPattern(base, size, CX_CSMediaFS_FindEntry, sizeofsig(CX_CSMediaFS_FindEntry));
        m_GetPathHash = (CSMFS_GetPathHash)SearchPattern(base, size, CX_CSMediaFS_GetPathHash, sizeofsig(CX_CSMediaFS_GetPathHash));
        m_Open = (CSMFS_Open)SearchPattern(base, size, CX_CSMediaFS_Open, sizeofsig(CX_CSMediaFS_Open));
        m_Mount = (CSMFS_Mount)SearchPattern(base, size, CX_CSMediaFS_Mount, sizeofsig(CX_CSMediaFS_Mount));
        
        //函数劫持
        InlineHook(m_Open, MyOpen);
        InlineHook(m_Mount, MyMount);
        //InlineHook(m_FindEntry, MyFindEntry);
        InlineHook(m_CheckExistenceStorage, MyCheckExistenceStorage);

        printf("-----\nthis: 0x%08X\nCheckExistenceStorage: 0x%08X\nFindEntry: 0x%08X\nGetPathHash: 0x%08X\nOpen: 0x%08X\nMount: 0x%08X\n-----\n", 
            reinterpret_cast<int>(m_this), 
            reinterpret_cast<int>(m_CheckExistenceStorage), 
            reinterpret_cast<int>(m_FindEntry), 
            reinterpret_cast<int>(m_GetPathHash), 
            reinterpret_cast<int>(m_Open), 
            reinterpret_cast<int>(m_Mount));
    }

	//在vftable里直接拿指针（这样完全不保证准确度和稳定性）
	void SetUpFuncPointersVftable(void* CompoundStorageMedia)
	{
		//   CompoundStorageMedia
		//+0 +----lpvftable
		//	 +00  +-Addref
		//	 +04  +-GetName
		//   +08  +-NormalizeDomainName
		//   +0C  +-NormalizePathName
		//   +10  +-NormalizePathName
		//   +14  +-CheckExistentStorage
		//   +18  +-Open
		//   +1C  +-nullsub
		//   +20  +-GetLocallyAccessibleName
		//   +24  +-Release
	}
}static_CXFuncs;


#pragma region Replaced_Function
//自定义CheckExistenceStorage和Open可以实现添加封包内本不存在的文件（例如tjs脚本）
bool MyCheckExistenceStorage(void* a, tTJSString* b)
{
    //std::cout << "Check: " << Ucs2ToGbk(b->c_str()) << std::endl;
    return static_CXFuncs.m_CheckExistenceStorage(a, b);
}


tTJSBinaryStream* __cdecl MyOpen(void* a, tTJSString* name, int flags)
{
	//std::cout << "Open: " << Ucs2ToGbk(name->c_str()) << std::endl;
	return static_CXFuncs.m_Open(a, name, flags);
}


int __fastcall MyMount(void* a, void* notused, tTJSVariant* b, tTJSVariant* c, tTJSVariant* d)
{
    tTJSString path(c->AsString());
    //std::cout << "Mount: " << Ucs2ToGbk(path.c_str()) << std::endl;
    PackagesLoaded++;
    return static_CXFuncs.m_Mount(a, notused, b, c, d);
}


bool __fastcall MyFindEntry(void* a, void* notused, tTJSString* domain_name, tTJSString* path_name, tTJSString* file_name, tTJSVariant* e)
{
    std::cout << "FindDomain: \"" << Ucs2ToGbk(domain_name->c_str()) << "\", FindPath: \"" << Ucs2ToGbk(path_name->c_str()) << "\", FindFile: \"" << Ucs2ToGbk(file_name->c_str()) << std::endl;
    return static_CXFuncs.m_FindEntry(a, notused, domain_name, path_name, file_name, e);
}
#pragma endregion

void SimpleDecrypt(byte* check, size_t size) 
{
	if (check[0] == 0xFE && check[1] == 0xFE && check[2] == 0x01 && check[3] == 0xFF && check[4] == 0xFE) 
    {
		byte r;
		for (int i = 5; i < size; i++) 
        {
			r = check[i];
            check[i] = ((r & 0xaaaaaaaa) >> 1) | ((r & 0x55555555) << 1);
		}
	}
}

void DumpAllScripts()
{
	CPathW w = GetAppDirectoryW();
	w.AddBackslash();
	w += L"ScriptDump\\All";

	tTJSString file("./!scnlist.txt");
	if (!static_CXFuncs.m_CheckExistenceStorage(static_CXFuncs.m_this, &file))
	{
		std::cout << "Cannot Find \"!scnlist.txt\"!" << std::endl;
		return;
	}

	// Create the directory
	auto fo = SHCreateDirectory(NULL, w);
	if (fo != ERROR_SUCCESS && fo != ERROR_ALREADY_EXISTS) {
		std::cout << "Failed to create directory!" << std::endl;
		return;
	}

	auto stream = static_CXFuncs.m_Open(static_CXFuncs.m_this, &file, 0);
    if (stream)
    {
		auto s = stream->GetSize();
        char* buffer = new char[s];

        stream->Read(buffer, s);
        SimpleDecrypt((byte*)buffer, s);
		delete stream;

		std::ofstream ofst("./ScriptDump/!scnlist.txt", std::ios::binary);
		ofst.write(buffer + 5, s - 5);
		ofst.flush();
		ofst.close();

		wchar_t* file_data = reinterpret_cast<wchar_t*>(buffer+5);

		std::list<std::wstring> files;
		std::wstringstream wss;

		int state = 0;
		wchar_t ch;
		for (int i = 0; i < ((s-5) >> 1);)
		{
			ch = file_data[i];
			switch (ch)
			{
				case L'\n':
				case L'\r':
				case L' ':
					state = 4;
					break;
				case L'#'://注释
					state = 3;
					break;
				case L':'://标签结尾处
					state = 2;
					break;
				case L'\t'://脚本起始indent
					state = 1;
					break;
				default:
					state = 0;
					break;
			}

			switch (state)
			{
				case 0:
					wss << ch;
					i++;
					break;
				case 1:
					i++;
					wss << L"./";
					while (file_data[i] != L'\r' && file_data[i] != L'\n') ch = file_data[i++], wss << ch;
					files.emplace_back(wss.str());
					wss.str(L"");
					break;
				case 2:
					wss.str(L"");
					i++;
					break;
				case 3:
					while (file_data[i] != L'\r' && file_data[i] != L'\n') i++;
					break;
				case 4:
					i++;
					break;
			}
		}

		delete[] buffer;

		for (auto& f : files)
		{
			file = f.c_str();
			//找下文件到底在不在
			if (!static_CXFuncs.m_CheckExistenceStorage(static_CXFuncs.m_this, &file))
			{
				file += L".scn";
				if (!static_CXFuncs.m_CheckExistenceStorage(static_CXFuncs.m_this, &file))
				{
					std::wcout << L"[WARN][NotFound]:" << f << std::endl;
					continue;
				}
			}
			stream = static_CXFuncs.m_Open(static_CXFuncs.m_this, &file, 0);
			if (stream)
			{
				s = stream->GetSize();
				buffer = new char[s];

				stream->Read(buffer, s);
				delete stream;

				std::wcout << L"[INFO][Dump]:" << f << std::endl;
				std::ofstream ofst(L"./ScriptDump/All/" + f.substr(2), std::ios::binary);
				ofst.write(buffer, s);
				ofst.flush();
				ofst.close();
				delete[] buffer;
			}
			else 
			{
				std::wcout << L"[WARN][CannotCreateStream]:" << f << std::endl;
			}
		}
    }
}

void CheckAndDump()
{
    while (PackagesLoaded < PACKAGE_AMOUNT)
    {
        Sleep(1000);
    }
    IsFSInitialized = true;
    std::cout << "FS Initialized successfully." << std::endl;
    DumpAllScripts();
}

//劫持插件加载流程
void HijackCxdecLoadRouting()
{
	SignaturePatch(EBaseAddr, LoadCXSIG, &pMyLoadCXAndPatch, sizeofsig(LoadCXSIG));
}


//劫持CompoundStorageMedia的构造函数，获得this指针，以便后续调用其成员函数
CSMFS_Constructor pfnCSMFS_Constructor;
int __cdecl MyCSMFSConstructor(void** CompoundStorageMedia, tTJSVariant* b, int c, tTJSVariant** d)
{
	auto ret = pfnCSMFS_Constructor(CompoundStorageMedia, b, c, d);
	//std::cout << "called constructor, this: 0x" << std::hex << *a << std::endl;
    static_CXFuncs.SetUpFuncPointers(*CompoundStorageMedia);
	return ret;
}


//用于向krkr中注册插件
//注册完成后可以使用tp_stub内声明的引擎函数
tTVPV2LinkProc pfnV2Link;
HRESULT _stdcall HookV2Link(iTVPFunctionExporter* exporter)
{
    //在这里取消Hook，毕竟只要拿到exporter就好
    UnInlineHook(pfnV2Link, HookV2Link);
    HRESULT ret = S_FALSE;
    if (TVPInitImportStub(exporter))
    {
        std::cout << "Plugin successfully initialized." << std::endl;
        ret = pfnV2Link(exporter);
    }
    return ret;
}


HANDLE WINAPI MyLoadCXAndPatch(LPCWSTR lpLibFileName)
{
    CBaseAddr = LoadLibraryW(lpLibFileName);
    if (!IsLoadedCxdec && CBaseAddr)
    {
        IsLoadedCxdec = true;
        //bypass完整性验证
        SignaturePatch(CBaseAddr, CX_SIGCHECK, CX_SIGPATCH);
#ifndef ONLY_BYPASS_SIGCHECK
        //设置CompoundStorageMedia构造体Hook
        pfnCSMFS_Constructor = (CSMFS_Constructor)SearchPattern(GetModuleBase(CBaseAddr), GetModuleSize(CBaseAddr), CX_CSMediaFS_Constructor, sizeofsig(CX_CSMediaFS_Constructor));
        InlineHook(pfnCSMFS_Constructor, MyCSMFSConstructor);
        //捕获调用V2Link时的exporter，在cxdec之前完成插件注册
        pfnV2Link = (tTVPV2LinkProc)GetProcAddress(CBaseAddr, "V2Link");
        InlineHook(pfnV2Link, HookV2Link);

        //创建一个线程用于检测是否完成封包加载等工作
		std::thread t(CheckAndDump);
		t.detach();
#endif
    }
    return CBaseAddr;
}


//=============================================================================
// DLL Entry Point
//=============================================================================


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        {
			EBaseAddr = GetModuleHandle(NULL);
			pMyLoadCXAndPatch = (DWORD)MyLoadCXAndPatch;

            // See https://github.com/microsoft/Detours/wiki/DetourRestoreAfterWith
            DetourRestoreAfterWith();
            MakeConsole();
			setlocale(LC_ALL, "zh-cn");
            //std::cout << MyCSMFSConstructor << std::endl;
            //std::cout << FixR6002 << std::endl;
            //std::cout << FuncTest << std::endl;

            FixR6002(EBaseAddr);

            SignaturePatch(EBaseAddr, SteamARG, SbeamARG, 0, false);

            HijackCxdecLoadRouting();

            break;
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}


//=============================================================================
// Dummy Export Symbol
//=============================================================================


BOOL APIENTRY CreateObject()
{
    return TRUE;
}
