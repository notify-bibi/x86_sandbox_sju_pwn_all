
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include<Windows.h>
#include<stdio.h>
#include <stdint.h>
void study() {
    FILE* fp;
    fopen_s(&fp, "hkdemo32.dll", "rb");//"C:\\Users\\bibi\\source\\repos\\hk32\\hk32\\ws2_32.bck.dll"
    IMAGE_DOS_HEADER    image_dos_header;
    IMAGE_NT_HEADERS32	image_nt_headers32;
    IMAGE_SECTION_HEADER SectionHeaders;
    IMAGE_BASE_RELOCATION RelocTable;
    fread(&image_dos_header, sizeof(image_dos_header), 1, fp);
    fseek(fp, image_dos_header.e_lfanew, SEEK_SET);
    fread(&image_nt_headers32, sizeof(image_nt_headers32), 1, fp);
    do {
        fread(&SectionHeaders, sizeof(SectionHeaders), 1, fp);
        if (!strcmp(".reloc", (char*)SectionHeaders.Name)) {
            fseek(fp, SectionHeaders.PointerToRawData, SEEK_SET);
            break;
        }
    } while (*(UINT64*)(SectionHeaders.Name));
    fread(&RelocTable, sizeof(RelocTable), 1, fp);
    ULONG ulBlockNum = (RelocTable.SizeOfBlock - 8) / 2;
    (IMAGE_IMPORT_DESCRIPTOR*)(image_nt_headers32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for (int i = 0; i < ulBlockNum; i++) {

    }

    fclose(fp);
}

int parse(HMODULE hMod) {
    int nRetCode = 0;
    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)hMod;
    IMAGE_NT_HEADERS* NtHeader = (IMAGE_NT_HEADERS*)((BYTE*)hMod + ((IMAGE_DOS_HEADER*)hMod)->e_lfanew);
    IMAGE_IMPORT_DESCRIPTOR* pImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hMod + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    while (pImportDesc->FirstThunk)
    {
        char* pszDllName = (char*)((BYTE*)hMod + pImportDesc->Name);
        IMAGE_THUNK_DATA* pThunk = (IMAGE_THUNK_DATA*)((BYTE*)hMod + pImportDesc->OriginalFirstThunk);
        IMAGE_THUNK_DATA* pThunkGot = (IMAGE_THUNK_DATA*)((BYTE*)hMod + pImportDesc->FirstThunk);

        HMODULE imphMod = ::GetModuleHandle(pszDllName);
        IMAGE_NT_HEADERS* impNtHeader = (IMAGE_NT_HEADERS*)((BYTE*)imphMod + ((IMAGE_DOS_HEADER*)imphMod)->e_lfanew);
        IMAGE_EXPORT_DIRECTORY* ExportDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)imphMod + impNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        printf("\nÄ£¿éÃû³Æ:%s\n", pszDllName);
        int nFidx = 0;
        while (pThunk[nFidx].u1.Function)
        {
            PDWORD fucaddr = 0;
            if (pThunk[nFidx].u1.Function >> 31) {
                DWORD idx = (pThunk[nFidx].u1.Ordinal & 0x7fffffff) - ExportDir->Base;
                if (idx >= ExportDir->NumberOfFunctions) {
                    printf("error");
                    exit(0);
                }
                DWORD* Functions = (DWORD*)((char*)imphMod + ExportDir->AddressOfFunctions);
                fucaddr = (PDWORD)((char*)imphMod + Functions[idx]);
            }
            else {
                IMAGE_IMPORT_BY_NAME* pIN = (IMAGE_IMPORT_BY_NAME*)((BYTE*)hMod + (DWORD)pThunk[nFidx].u1.AddressOfData);
                printf("%x %-25s ", pIN->Hint, pIN->Name);
                fucaddr = (PDWORD)pThunkGot[nFidx].u1.Function;
            }
            printf("p:%p addr :%p\n", &pThunkGot[nFidx], fucaddr);
            nFidx++;
        }
        pImportDesc++;
    }
    return nRetCode;
}

int main(int argc, char* argv[])
{
    study();
    HMODULE he = LoadLibraryA("hkdemo32.dll");
    HMODULE h = LoadLibraryA("xx2_32.dll");
    HMODULE hMod = ::GetModuleHandle("xx2_32.dll");
    parse(he); return 1;
}