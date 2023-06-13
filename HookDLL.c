#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

#define DEF_DLL "USER32.dll"
#define DEF_FUNC "MessageBoxW"

typedef int(WINAPI* PFMessageBoxW)(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);

BYTE g_OrgByte[14] = { 0, };

BOOL Hook_Code(LPCSTR szDllName, LPCSTR szFuncName, PROC pfNew) {
    FARPROC pfOrg;
    DWORD dwOldProtect, dwAddress;
    BYTE pBuf1[10] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; //mov rax, 0x0000000000000000
    BYTE pBuf2[2] = { 0xff, 0xe0 }; //jmp rax
    PBYTE pByte;

    //Get The Target API Address
    pfOrg = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
    pByte = (PBYTE)pfOrg;

    //Already Hooked
    if (pByte[0] == 0x48 && pByte[1] == 0xb8) {
        return FALSE;
    }


    VirtualProtect((LPVOID)pfOrg, 12, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    memcpy(g_OrgByte, pfOrg, 12);
    memcpy(pBuf1+2, &pfNew, 8);

    memcpy(pfOrg, pBuf1, 10);
    memcpy((LPVOID)((DWORD_PTR)pfOrg + 10), pBuf2, 2);

    VirtualProtect((LPVOID)pfOrg, 12, dwOldProtect, &dwOldProtect);

    return TRUE;
}

BOOL UnHook_Code(LPCSTR szDllName, LPCSTR szFuncName) {
    FARPROC pFunc;
    DWORD dwOldProtect;
    PBYTE pByte;

    pFunc = GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
    pByte = (PBYTE)pFunc;

    if (pByte[0] != 0x48 && pByte[1] != 0xb8)
        return FALSE;

    VirtualProtect((LPVOID)pFunc, 12, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    memcpy(pFunc, g_OrgByte, 12);
    VirtualProtect((LPVOID)pFunc, 12, dwOldProtect, &dwOldProtect);

    return TRUE;

}

int WINAPI New_MessageBoxW(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) {
    FARPROC pf_msgboxw;
    UINT return_val;

    UnHook_Code(DEF_DLL, DEF_FUNC);

    pf_msgboxw = GetProcAddress(GetModuleHandleA(DEF_DLL), DEF_FUNC);
    return_val = ((PFMessageBoxW)pf_msgboxw)(0, L"Hooked!", lpCaption, uType);

    Hook_Code(DEF_DLL, DEF_FUNC, (PROC)New_MessageBoxW);
    return return_val;
}

BOOL WINAPI DllMain(HMODULE hModule,
    DWORD  fdwReason,
    LPVOID lpReserved
)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        Hook_Code(DEF_DLL, DEF_FUNC, (PROC)New_MessageBoxW);
        break;
    case DLL_PROCESS_DETACH:
        UnHook_Code(DEF_DLL, DEF_FUNC);
        break;
    }
    return TRUE;
}