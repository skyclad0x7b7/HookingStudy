// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

#pragma pack(1)
struct code_t
{
	SHORT  Opcode;
	LPVOID lpTarget;
};
#pragma pack()

typedef HANDLE WINAPI tCreateFile(
	_In_     LPCTSTR,
	_In_     DWORD,
	_In_     DWORD,
	_In_opt_ LPSECURITY_ATTRIBUTES,
	_In_     DWORD,
	_In_     DWORD,
	_In_opt_ HANDLE);

tCreateFile*  prevFunction;

HANDLE WINAPI NewCreateFile(
	_In_     LPCTSTR               lpFileName,
	_In_     DWORD                 dwDesiredAccess,
	_In_     DWORD                 dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_     DWORD                 dwCreationDisposition,
	_In_     DWORD                 dwFlagsAndAttributes,
	_In_opt_ HANDLE                hTemplateFile
)
{
	return prevFunction(
		L"c:\\fuck.you",
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile);
}

void tryHook() 
{
	DWORD    dwOldProtect;
	LPVOID   lpOriginal = GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileW");
	
	code_t*  lpFuncObj = (code_t*)VirtualAlloc(nullptr, sizeof(code_t), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	code_t	 newFuncObj;

	VirtualProtect(lpOriginal, 6, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	
	prevFunction = (tCreateFile*)lpFuncObj;
	
	memcpy_s(lpFuncObj, 6, lpOriginal, 6);

	newFuncObj.Opcode   = 0x25FF;
	newFuncObj.lpTarget = &NewCreateFile;

	memcpy_s(lpOriginal, 6, &newFuncObj, 6);

	VirtualProtect(lpOriginal, 6, dwOldProtect, NULL);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		tryHook();
		break;
	case DLL_PROCESS_DETACH:

		break;
	}
	return TRUE;
}

