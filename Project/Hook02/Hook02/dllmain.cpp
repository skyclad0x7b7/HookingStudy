// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include <stdio.h>

struct NtStruct {
	BYTE		mov1;
	DWORD		addr1;
	BYTE		mov2;
	DWORD		addr2;
	SHORT		CALL_EDX;
	BYTE		RET24[3];
};

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

tNtReadFile *prevFunction;

/************************************************************************/

NTSTATUS __declspec(naked) NewNtReadFile(
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
	__asm {
		push ebp
		mov  ebp, esp
		sub  esp, 0x40
	}
	prevFunction(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
	__asm {
		mov esp, ebp
		pop ebp
		ret
	}
}

BOOL hook(LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew) {
	DWORD dwOldProtect;
	PROC lpOriginal = GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	PBYTE pByte = (PBYTE)lpOriginal;
	if (pByte[0] == 0x90) // already hooked
		return FALSE;

	BYTE pBuf[12] = { 0x90, 0x90, 0x90, 0x90, 0x90,		// mov eax, ~~
					  0xBA, 0, 0, 0, 0,					// mov edx, ~~
					  0xFF, 0xD2 } ;					// call edx

	NtStruct *lpOldFunc = (NtStruct *)VirtualAlloc(nullptr, 15, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy_s(lpOldFunc, 15, lpOriginal, 15);
	prevFunction = (tNtReadFile *)lpOldFunc;

	memcpy_s(pBuf + 6, 4, &pfnNew, 4);

	VirtualProtect(lpOriginal, 12, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	memcpy_s(lpOriginal, 12, pBuf, 12);
	VirtualProtect(lpOriginal, 12, dwOldProtect, NULL);
	return TRUE;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		hook("ntdll.dll", "NtReadFile", (PROC)NewNtReadFile);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

