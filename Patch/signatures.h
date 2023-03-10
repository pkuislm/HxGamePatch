#pragma once
//不用constexpr是因为用了之后我那个找特征码的就会寄（太菜了不知道哪里出了问题）

//坏事了，这个位置不仅仅加载Cxdec嘞
//不过Cxdec总是第一个加载，暂且这么用着吧
//位置：游戏主程序
//00421397 | C645 FC 03     | MOV     BYTE PTR SS : [EBP - 4] , 3          |
//0042139B | 8378 14 08     | CMP     DWORD PTR DS : [EAX + 14] , 8        |
//0042139F | 72 02          | JB      game.4213A3                          |
//004213A1 | 8B00           | MOV     EAX, DWORD PTR DS : [EAX]            |
//004213A3 | 50             | PUSH    EAX                                  |
//004213A4 | FF15 0C036C00  | CALL    DWORD PTR DS : [<&LoadLibraryW>]     | <-这里就是我们要进行替换的地方，将要被替换成MyLoadCXAndPatch
//需要注意的是，这里的汇编是0xFF15，也就是说他像是call (*p)一样的，所以这个位置放的得是一个指针。
#define LoadCXSIG "\xC6\x45\xFC\x03\x83\x78\x14\x08\x72\x02\x8B\x00\x50\xFF\x15"

//在steam上发布的游戏会检查并加载krkrsteam.dll，而这个krkrsteam.dll很麻烦
//好在游戏内的steam.tjs只是根据游戏启动时的命令行决定是否加载
//这里给他随便改一改让他找不到这个属性就行
//位置：游戏主程序
// -> steam="yes"
#define SteamARG "\x73\x74\x65\x61\x6D\x3D\x22\x79\x65\x73\x22"
// -> sbeam="yes" ：）
//当然不知道以后的krz游戏还会不会这样弄，说不定会加强
#define SbeamARG "\x73\x62\x65\x61\x6D\x3D\x22\x79\x65\x73\x22"


//爆破完整性检查的特征码
//位置：游戏CXDEC
//79CCD460 | 55             | PUSH    EBP                                  |
//79CCD461 | 8BEC           | MOV     EBP, ESP                             |
//79CCD463 | 837D 08 00     | CMP     DWORD PTR SS : [EBP + 8] , 0         | [ebp + 8] : L"c:\\users\\...\\appdata\\local\\temp\\krkr_54ebb1969ee7_724031046_124336\\6fa8320e4fe2.dll"
//79CCD467 | 53             | PUSH    EBX                                  |
//79CCD468 | 56             | PUSH    ESI                                  |
//79CCD469 | 8BF1           | MOV     ESI, ECX                             |
#define CX_SIGCHECK "\x55\x8B\xEC\x83\x7D\x08\x00\x53\x56\x8B\xF1"
//要什么函数流程，我们直接叫他返回true，还能加快游戏载入速度捏
//79CCD460 | B0 01          | MOV     AL, 1                                |
//79CCD462 | C2 0800        | RET     8                                    |
//79CCD465 | CC             | INT3                                         |
//79CCD466 | CC             | INT3                                         |
#define CX_SIGPATCH "\xB0\x01\xC2\x08\x00\xCC\xCC"


//int __cdecl sub_100059F0(CompoundStorageMediaFS **a1, tTJSVariant *a2, int optnum, tTJSVariant **optargs)
//构造方法。拦截该函数以获得this指针
#define CX_CSMediaFS_Constructor "\x55\x8B\xEC\x6A\xFF\x68\x2A\x2A\x2A\x2A\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x08\x56\xA1\x2A\x2A\x2A\x2A\x33\xC5\x50\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\xA1\x2A\x2A\x2A\x2A\x85\xC0\x75\x12"


//tTJSString * __thiscall CompoundStorageMediaFS::GetPathHash(CompoundStorageMediaFS *this, tTJSString *domain, tTJSString *path_name)
//路径查找函数
//返回值为0，则代表该路径不存在
#define CX_CSMediaFS_GetPathHash "\x55\x8B\xEC\x6A\xFF\x68\x2A\x2A\x2A\x2A\x64\xA1\x00\x00\x00\x00\x50\x51\x56\x57\xA1\x2A\x2A\x2A\x2A\x33\xC5\x50\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\x8B\xF9\xFF\x75\x08\x8D\x45\xF0\x50\x8D\x4F\x2C\xE8"


//bool __thiscall CompoundStorageMediaFS::FindEntry(CompoundStorageMediaFS *this, tTJSString *domain_name, tTJSString *path_name, tTJSString *file_name, tTJSVariant *entryInfo)
//entryinfo -> tTJSVariant::tTJSVariant()
//存在可用路径时，结合文件名进行探测
#define CX_CSMediaFS_FindEntry "\x55\x8B\xEC\x6A\xFF\x68\x2A\x2A\x2A\x2A\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x08\x53\x56\x57\xA1\x2A\x2A\x2A\x2A\x33\xC5\x50\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\x8B\xF9\x8D\x77\x14\x56\x89\x75\xEC\xFF\x15\x2A\x2A\x2A\x2A\xFF\x75\x0C\x8B\xCF\xFF\x75\x08\xC7\x45\xFC\x00\x00\x00\x00"


//bool __cdecl CompoundStorageMediaFS::CheckExistentStorage(CompoundStorageMediaFS *this, tTJSString *name)
//最简单的，但最不可控（因为需要构建路径以及文件名）
#define CX_CSMediaFS_CheckExistenceStorage "\x55\x8B\xEC\x6A\xFF\x68\x2A\x2A\x2A\x2A\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x0C\x53\xA1\x2A\x2A\x2A\x2A\x33\xC5\x50\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\xA1\x2A\x2A\x2A\x2A\x85\xC0\x75\x12\x68\x2A\x2A\x2A\x2A\xE8\x2A\x2A\x2A\x2A\x83\xC4\x04"


//tTJSBinaryStream* __cdecl CompoundStorageMediaFS::Open(CompoundStorageMediaFS* this, tTJSString* name, int flags)
//创建一个解密流（文件不存在时，返回nullptr）
#define CX_CSMediaFS_Open "\x55\x8B\xEC\x6A\xFF\x68\x2A\x2A\x2A\x2A\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x0C\x56\xA1\x2A\x2A\x2A\x2A\x33\xC5\x50\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\xA1\x2A\x2A\x2A\x2A\x85\xC0\x75\x12\x68\x2A\x2A\x2A\x2A\xE8"


//int __thiscall* CompoundStorageMediaFS::Mount(CompoundStorageMediaFS* this, tTJSVariant* result, tTJSVariant* archivepath, tTJSVariant* a4);
//注册一个封包
#define CX_CSMediaFS_Mount "\x55\x8B\xEC\x6A\xFF\x68\x2A\x2A\x2A\x2A\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x18\x53\x56\x57\xA1\x2A\x2A\x2A\x2A\x33\xC5\x50\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\x8B\xF9\x89\x7D\xEC"


//游戏内置的operator new
#define KRKRZ_OPERATOR_NEW_SIG "\x55\x8B\xEC\x83\xEC\x10\xEB\x0D\xFF\x75\x08\xE8\x2A\x2A\x2A\x2A\x59\x85\xC0\x74\x0F\xFF\x75\x08\xE8\x2A\x2A\x2A\x2A\x59\x85\xC0"


//游戏内置的operator delete
#define KRKRZ_FREE_SIG "\x55\x8B\xEC\x83\x7D\x08\x00\x74\x2D\xFF\x75\x08\x6A\x00\xFF\x35\x2A\x2A\x2A\x2A\xFF\x15\x2A\x2A\x2A\x2A\x85\xC0\x75\x18\x56\xE8\x2A\x2A\x2A\x2A\x8B\xF0"