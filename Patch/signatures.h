#pragma once

//�����ˣ����λ�ò���������Cxdec��
//����Cxdec���ǵ�һ�����أ�������ô���Ű�
//λ�ã���Ϸ������
//00421397 | C645 FC 03     | MOV     BYTE PTR SS : [EBP - 4] , 3          |
//0042139B | 8378 14 08     | CMP     DWORD PTR DS : [EAX + 14] , 8        |
//0042139F | 72 02          | JB      game.4213A3                          |
//004213A1 | 8B00           | MOV     EAX, DWORD PTR DS : [EAX]            |
//004213A3 | 50             | PUSH    EAX                                  |
//004213A4 | FF15 0C036C00  | CALL    DWORD PTR DS : [<&LoadLibraryW>]     | <-�����������Ҫ�����滻�ĵط�����Ҫ���滻��MyLoadCXAndPatch
constexpr auto LoadCXSIG = "\xC6\x45\xFC\x03\x83\x78\x14\x08\x72\x02\x8B\x00\x50\xFF\x15";


//��steam�Ϸ�������Ϸ���鲢����krkrsteam.dll�������krkrsteam.dll���鷳
//������Ϸ�ڵ�steam.tjsֻ�Ǹ�����Ϸ����ʱ�������о����Ƿ����
//�����������һ�������Ҳ���������Ծ���
// -> steam="yes"
constexpr auto SteamARG = "\x73\x74\x65\x61\x6D\x3D\x22\x79\x65\x73\x22";
// -> sbeam="yes" ����
constexpr auto SbeamARG = "\x73\x62\x65\x61\x6D\x3D\x22\x79\x65\x73\x22";


//���������Լ���������
//λ�ã���ϷCXDEC
//79CCD460 | 55             | PUSH    EBP                                  |
//79CCD461 | 8BEC           | MOV     EBP, ESP                             |
//79CCD463 | 837D 08 00     | CMP     DWORD PTR SS : [EBP + 8] , 0         | [ebp + 8] : L"c:\\users\\...\\appdata\\local\\temp\\krkr_54ebb1969ee7_724031046_124336\\6fa8320e4fe2.dll"
//79CCD467 | 53             | PUSH    EBX                                  |
//79CCD468 | 56             | PUSH    ESI                                  |
//79CCD469 | 8BF1           | MOV     ESI, ECX                             |
constexpr auto CX_SIGCHECK = "\x55\x8B\xEC\x83\x7D\x08\x00\x53\x56\x8B\xF1";
//Ҫʲô�������̣�����ֱ�ӽ�������true�����ܼӿ���Ϸ�����ٶ���
//79CCD460 | B0 01          | MOV     AL, 1                                |
//79CCD462 | C2 0800        | RET     8                                    |
//79CCD465 | CC             | INT3                                         |
//79CCD466 | CC             | INT3                                         |
constexpr auto CX_SIGPATCH = "\xB0\x01\xC2\x08\x00\xCC\xCC";


//int __cdecl sub_100059F0(CompoundStorageMediaFS **a1, tTJSVariant *a2, int optnum, tTJSVariant **optargs)
//���췽�������ظú����Ի��thisָ��
constexpr auto CX_CSMediaFS_Constructor = "\x55\x8B\xEC\x6A\xFF\x68\x2A\x2A\x2A\x2A\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x08\x56\xA1\x2A\x2A\x2A\x2A\x33\xC5\x50\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\xA1\x2A\x2A\x2A\x2A\x85\xC0\x75\x12";


//tTJSString * __thiscall CompoundStorageMediaFS::GetPathHash(CompoundStorageMediaFS *this, tTJSString *domain, tTJSString *path_name)
//·�����Һ���
//����ֵΪ0���������·��������
constexpr auto CX_CSMediaFS_GetPathHash = "\x55\x8B\xEC\x6A\xFF\x68\x2A\x2A\x2A\x2A\x64\xA1\x00\x00\x00\x00\x50\x51\x56\x57\xA1\x2A\x2A\x2A\x2A\x33\xC5\x50\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\x8B\xF9\xFF\x75\x08\x8D\x45\xF0\x50\x8D\x4F\x2C\xE8";


//bool __thiscall CompoundStorageMediaFS::FindEntry(CompoundStorageMediaFS *this, tTJSString *domain_name, tTJSString *path_name, tTJSString *file_name, tTJSVariant *entryInfo)
//entryinfo -> tTJSVariant::tTJSVariant()
//���ڿ���·��ʱ������ļ�������̽��
constexpr auto CX_CSMediaFS_FindEntry = "\x55\x8B\xEC\x6A\xFF\x68\x2A\x2A\x2A\x2A\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x08\x53\x56\x57\xA1\x2A\x2A\x2A\x2A\x33\xC5\x50\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\x8B\xF9\x8D\x77\x14\x56\x89\x75\xEC\xFF\x15\x2A\x2A\x2A\x2A\xFF\x75\x0C\x8B\xCF\xFF\x75\x08\xC7\x45\xFC\x00\x00\x00\x00";


//bool __cdecl CompoundStorageMediaFS::CheckExistentStorage(CompoundStorageMediaFS *this, tTJSString *name)
//��򵥵ģ�����ɿأ���Ϊ��Ҫ����·���Լ��ļ�����
constexpr auto CX_CSMediaFS_CheckExistenceStorage = "\x55\x8B\xEC\x6A\xFF\x68\x2A\x2A\x2A\x2A\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x0C\x53\xA1\x2A\x2A\x2A\x2A\x33\xC5\x50\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\xA1\x2A\x2A\x2A\x2A\x85\xC0\x75\x12\x68\x2A\x2A\x2A\x2A\xE8\x2A\x2A\x2A\x2A\x83\xC4\x04";


//tTJSBinaryStream* __cdecl CompoundStorageMediaFS::Open(CompoundStorageMediaFS* this, tTJSString* name, int flags)
//����һ�����������ļ�������ʱ������nullptr��
constexpr auto CX_CSMediaFS_Open = "\x55\x8B\xEC\x6A\xFF\x68\x2A\x2A\x2A\x2A\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x0C\x56\xA1\x2A\x2A\x2A\x2A\x33\xC5\x50\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\xA1\x2A\x2A\x2A\x2A\x85\xC0\x75\x12\x68\x2A\x2A\x2A\x2A\xE8";


//int __thiscall* CompoundStorageMediaFS::Mount(CompoundStorageMediaFS* this, tTJSVariant* result, tTJSVariant* archivepath, tTJSVariant* a4);
//ע��һ�����
constexpr auto CX_CSMediaFS_Mount = "\x55\x8B\xEC\x6A\xFF\x68\x2A\x2A\x2A\x2A\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x18\x53\x56\x57\xA1\x2A\x2A\x2A\x2A\x33\xC5\x50\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\x8B\xF9\x89\x7D\xEC";