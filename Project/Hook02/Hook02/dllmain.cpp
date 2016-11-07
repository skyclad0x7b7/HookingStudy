// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef NTSTATUS tNtReadFile(
	_In_     HANDLE           FileHandle,
	_In_opt_ HANDLE           Event,
	_In_opt_ PVOID			  ApcRoutine,
	_In_opt_ PVOID            ApcContext,
	_Out_    PIO_STATUS_BLOCK IoStatusBlock,
	_Out_    PVOID            Buffer,
	_In_     ULONG            Length,
	_In_opt_ PLARGE_INTEGER   ByteOffset,
	_In_opt_ PULONG           Key
);

typedef tNtReadFile * PFNTREADFILE;

void * newFunc;
tNtReadFile *oldFunc;
BYTE org_bytes[5];

BOOL hook(LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew, PBYTE pOrgBytes);
BOOL unHook(LPCSTR szDllName, LPCSTR szFuncName, PBYTE pOrgBytes);

/************************************************************************/

NTSTATUS NewNtReadFile(
	_In_     HANDLE           FileHandle,
	_In_opt_ HANDLE           Event,
	_In_opt_ PVOID			  ApcRoutine,
	_In_opt_ PVOID            ApcContext,
	_Out_    PIO_STATUS_BLOCK IoStatusBlock,
	_Out_    PVOID            Buffer,
	_In_     ULONG            Length,
	_In_opt_ PLARGE_INTEGER   ByteOffset,
	_In_opt_ PULONG           Key
) {
	unHook("ntdll.dll", "NtReadFile", org_bytes);
	PROC pFunc;
	NTSTATUS ret;
	pFunc = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadFile");
	ret = ((PFNTREADFILE)pFunc)(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
	MessageBox(NULL, NULL, NULL, NULL);
	hook("ntdll.dll", "NtReadFile", (PROC)NewNtReadFile, org_bytes);
	return ret;
}

BOOL hook(LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew, PBYTE pOrgBytes) {
	DWORD dwOldProtect, dwAddress;
	PROC lpOriginal = GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	PBYTE pByte = (PBYTE)lpOriginal;
	if (pByte[0] == 0xE9) // already hooked
		return FALSE;

	BYTE pBuf[5] = { 0xE9, 0, };

	// backup old codes
	memcpy_s(pOrgBytes, 5, lpOriginal, 5);

	// calculate address of new function
	dwAddress = (DWORD)pfnNew - (DWORD)lpOriginal - 5;
	memcpy_s(pBuf + 1, 4, &dwAddress, 4);

	VirtualProtect(lpOriginal, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	memcpy_s(lpOriginal, 5, pBuf, 5);
	VirtualProtect(lpOriginal, 5, dwOldProtect, NULL);
	return TRUE;
}

BOOL unHook(LPCSTR szDllName, LPCSTR szFuncName, PBYTE pOrgBytes) {
	DWORD dwOldProtect;
	PROC pFunc;

	pFunc = GetProcAddress(GetModuleHandleA(szDllName), szFuncName);

	VirtualProtect(pFunc, 5, PAGE_READWRITE, &dwOldProtect);
	memcpy_s(pFunc, 5, pOrgBytes, 5);
	VirtualProtect(pFunc, 5, dwOldProtect, NULL);
	return TRUE;
}

void tryHook() 
{
	hook("ntdll.dll", "NtReadFile", (PROC)NewNtReadFile, org_bytes);
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
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

