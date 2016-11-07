// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>

#pragma pack(1)
struct IAT_STRUCT {
	SHORT opcode;
	LPVOID lpTarget;
};
#pragma pack()

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

LPVOID newFunc;
tNtReadFile *oldFunc;

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
	return oldFunc(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

VOID testFunction() {
	MessageBox(NULL, NULL, NULL, NULL);
}

void tryHook() 
{
	DWORD dwOldProtect;
	LPVOID lpOriginal = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadFile");

	IAT_STRUCT *lpSavedFunc = (IAT_STRUCT *)VirtualAlloc(nullptr, sizeof(IAT_STRUCT), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	IAT_STRUCT newIATSTRUCT;

	memcpy_s(lpSavedFunc, 6, lpOriginal, 6);

	newFunc = &testFunction;
	oldFunc = (tNtReadFile*)lpSavedFunc->lpTarget;

	newIATSTRUCT.opcode = 0x25FF;
	newIATSTRUCT.lpTarget = &newFunc;

	VirtualProtect(lpOriginal, 6, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	memcpy_s(lpOriginal , 6, &newIATSTRUCT, 6);
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
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

