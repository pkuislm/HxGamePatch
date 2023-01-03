#include "libpkpkgZ.h"
#include <unordered_map>
#include <list>
#include <string>
#include <codecvt>
#include <algorithm>
using byte = unsigned char;

using namespace libpkpkgZ;

struct PkPatchFile
{
	PkArchive *m_patch_arc;
	std::unordered_map <std::wstring, PkgEntry> m_patch_files;

	~PkPatchFile()
	{
		if (m_patch_arc != nullptr)
		{
			m_patch_arc->close();
		}
	}
};
//static files
std::unordered_map <std::string, PkPatchFile*> patch_archives;


const std::string ws2utf8(const std::wstring& src)
{
	std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
	return conv.to_bytes(src);
}

const std::wstring utf82ws(const std::string& src)
{
	std::wstring_convert<std::codecvt_utf8<wchar_t> > conv;
	return conv.from_bytes(src);
}


bool SetUpFileTable(const std::string& package, bool echo, bool append)
{
	if (!append)
	{
		for (auto &i : patch_archives)
		{
			i.second->~PkPatchFile();
		}
		patch_archives.clear();
	}
	PkArchive *zf = new PkArchive(package);
	zf->open(PkArchive::ReadOnly);
	if (zf->isOpen())
	{
		PkPatchFile* pfile = new PkPatchFile;
		pfile->m_patch_arc = zf;
		std::vector<PkgEntry> entries = zf->getEntries();
		for (auto& it : entries)
		{
			auto s = it.getName();
			transform(s.begin(), s.end(), s.begin(), ::tolower);
			if (echo) wprintf_s(L"[PkPackageZ] Adding: %s\n", utf82ws(s).c_str());
			pfile->m_patch_files.emplace(std::make_pair(utf82ws(s), std::move(it)));
		}
		patch_archives.emplace(std::make_pair(package, pfile));
		return true;
	}
	return false;
}

bool UpdateFileTable(const std::string& OrigName, const std::string& package, bool echo)
{
	if (patch_archives.find(OrigName) != patch_archives.end())
	{
		auto a = patch_archives[OrigName];

		PkArchive* zf = new PkArchive(package);
		zf->open();
		if (zf->isOpen())
		{
			PkPatchFile* pfile = new PkPatchFile;
			pfile->m_patch_arc = zf;
			std::vector<PkgEntry> entries = zf->getEntries();
			for (auto& it : entries)
			{
				auto s = it.getName();
				transform(s.begin(), s.end(), s.begin(), ::tolower);
				if (a->m_patch_files.find(utf82ws(s)) != a->m_patch_files.end())
				{
					if (echo) wprintf_s(L"[PkPackageZ] Replacing: %s\n", utf82ws(s).c_str());
					a->m_patch_files[utf82ws(s)] = std::move(it);
				}
				else 
				{
					//This enables nested file patch?
					if (echo) wprintf_s(L"[PkPackageZ] Adding: %s\n", utf82ws(s).c_str());
					pfile->m_patch_files.emplace(std::make_pair(utf82ws(s), std::move(it)));
				}
			}
			patch_archives.emplace(std::make_pair(package, std::move(pfile)));
			return true;
		}
	}
	return false;
}

bool IsPkgFileExists(const std::wstring& filename)
{
	for (auto& i : patch_archives)
	{
		if (i.second->m_patch_files.find(filename) != i.second->m_patch_files.end())
		{
			return true;
		}
	}
	return false;
}

bool GetFileSizeIfExists(const std::wstring& filename, uint64_t* size)
{
	for (auto& i : patch_archives)
	{
		if (i.second->m_patch_files.find(filename) != i.second->m_patch_files.end())
		{
			*size = i.second->m_patch_files[filename].getSize();
			return true;
		}
	}
	return false;
}

bool TryOpenPkgFile(const std::wstring& filename, std::vector<byte>& dst)
{
	try 
	{
		for (auto &i:patch_archives)
		{
			if (i.second->m_patch_files.find(filename) != i.second->m_patch_files.end())
			{
				i.second->m_patch_files[filename].readAsBinaryToVector(dst);
				return true;
			}
		}
		return false;
	}
	catch (std::exception e)
	{
		printf("[PkPackageZ] Error while reading package: %s\n", e.what());
		return false;
	}
}