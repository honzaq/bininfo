
#include <windows.h>
#include <tchar.h>
#include <assert.h>
#include <iostream>
#include "scope_guard.h"

void print_fileheader(const IMAGE_FILE_HEADER& fileheader)
{
	if (fileheader.Machine == IMAGE_FILE_MACHINE_I386) {
		std::cout << "Machine: x32";
	}
	else if (fileheader.Machine == IMAGE_FILE_MACHINE_AMD64) {
		std::cout << "Machine: x64";
	}
	else if (fileheader.Machine == IMAGE_FILE_MACHINE_IA64) {
		std::cout << "Machine: I64";
	}
	else {
		std::cout << "Machine: Unsupported type";
	}
}

void read_data(const wchar_t* fileName)
{
	HANDLE hFile = nullptr;
	HANDLE hFileMapping = nullptr;
	LPVOID lpBaseAddress = nullptr;

	//////////////////////////////////////////////////////////////////////////
	// Open file 
	hFile = ::CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		assert(false && "Could not open file");
		throw std::exception("Could not open file");
	}
	scope_guard file_guard = [&]() {
		if (hFile != INVALID_HANDLE_VALUE) {
			::CloseHandle(hFile);
		}
	};

	DWORD fileSize = ::GetFileSize(hFile, NULL);

	//////////////////////////////////////////////////////////////////////////
	// Mapping Given EXE file to Memory
	hFileMapping = ::CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hFileMapping == NULL) {
		assert(false && "Could not map file exe");
		throw std::exception("Could not map file exe");
	}
	scope_guard filemap_guard = [&]() {
		if (hFileMapping != NULL) {
			::CloseHandle(hFileMapping);
		}
	};

	lpBaseAddress = ::MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (lpBaseAddress == NULL) {
		assert(false && "Map view of file fail");
		throw std::exception("Map view of file fail");
	}
	scope_guard filemapview_guard = [&]() {
		if (lpBaseAddress != NULL) {
			::UnmapViewOfFile(lpBaseAddress);
		}
	};

	//////////////////////////////////////////////////////////////////////////
	PIMAGE_DOS_HEADER pDOSHeader = static_cast<PIMAGE_DOS_HEADER>(lpBaseAddress);
	if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		assert(false && "Not PE file");
		throw std::exception("Not PE file");
	}
	PIMAGE_NT_HEADERS pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>((PBYTE)lpBaseAddress + pDOSHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE) {
		assert(false && "Not NT PE file");
		throw std::exception("Not NT PE file");
	}
	
	print_fileheader(pNTHeader->FileHeader);

	// Maybe later
	//PIMAGE_OPTIONAL_HEADER pOptionalHeader = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>((PBYTE)&pNTHeader->OptionalHeader);
	//if (IMAGE_NT_OPTIONAL_HDR32_MAGIC != pNTHeader->OptionalHeader.Magic) {
	//	assert(false && "File is not 32b");
	//	throw std::exception("File is not 32b");
	//}
	//PIMAGE_SECTION_HEADER pSECTIONHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>((PBYTE)pNTHeader + sizeof(IMAGE_NT_HEADERS));

	//DWORD exeSize = 0;
	//DWORD maxpointer = 0;
	//for (WORD i = 0; i < pNTHeader->FileHeader.NumberOfSections; ++i) {
	//	if (pSECTIONHeader->PointerToRawData > maxpointer) {
	//		maxpointer = pSECTIONHeader->PointerToRawData;
	//		exeSize = pSECTIONHeader->PointerToRawData + pSECTIONHeader->SizeOfRawData;
	//	}
	//	pSECTIONHeader++;
	//}
}

int _tmain(int argc, const _TCHAR* argv[])
{

	if (argv[1]) {
		
		try
		{
			read_data(argv[1]);
		}
		catch (const std::exception& e)
		{
			std::cout << "Exception during read " << e.what();
			return 2;
		}
	}
	else {
		std::cout << "Missing binary parameter." << std::endl;
		std::cout << "How it should be run:" << std::endl;
		std::cout << "   $> biinfo.exe <filename>" << std::endl;
	}

    return 0;
}
