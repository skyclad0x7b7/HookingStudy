// 32-bit notepad.exe - WriteFile Hooking (IAT)

#include <stdio.h>
#include <Windows.h>

#pragma pack(1)
struct IAT_STRUCT
{
	SHORT Opcode;
	LPVOID lpTarget;
};

typedef BOOL WINAPI tWriteFile(
	_In_        HANDLE       hFile,
	_In_        LPCVOID      lpBuffer,
	_In_        DWORD        nNumberOfBytesToWrite,
	_Out_opt_   LPDWORD      lpNumberOfBytesWritten,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
);

tWriteFile* prevFunction = NULL;
tWriteFile* newFunction = NULL;

BOOL WINAPI NewWriteFile(
	_In_        HANDLE       hFile,
	_In_        LPCVOID      lpBuffer,
	_In_        DWORD        nNumberOfBytesToWrite,
	_Out_opt_   LPDWORD      lpNumberOfBytesWritten,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
)
{
	if (nNumberOfBytesToWrite > 0)
		MessageBoxA(NULL, (LPCSTR)lpBuffer, NULL, NULL);
	return prevFunction(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

DWORD WINAPI Hook()
{
	// Get address of target function
	LPVOID lpOrgFunc = NULL;
	if ((lpOrgFunc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile")) == NULL)
		return -1;

	// Backup old protect
	DWORD dwOldProtect;
	if (VirtualProtect(lpOrgFunc, 6, PAGE_EXECUTE_READWRITE, &dwOldProtect) == NULL)
		return -1;

	// Backup old function IAT
	IAT_STRUCT*  lpSavedFunc = (IAT_STRUCT*)VirtualAlloc(NULL, sizeof(IAT_STRUCT), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	IAT_STRUCT   newFuncObj;
	memcpy_s(lpSavedFunc, 6, lpOrgFunc, 6);
	prevFunction = (tWriteFile*)lpSavedFunc;

	// Absolute Jump
	newFuncObj.Opcode = 0x25FF;

	// Set new functon to replace
	newFunction = &NewWriteFile;
	newFuncObj.lpTarget = &newFunction;

	// Replacing
	memcpy_s(lpOrgFunc, 6, &newFuncObj, 6);

	// Rollback protection
	VirtualProtect(lpOrgFunc, 6, dwOldProtect, NULL);
	return 0;
}

DWORD WINAPI UnHook()
{
	// Get address of target function
	LPVOID lpOrgFunc = NULL;
	if ((lpOrgFunc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile")) == NULL)
		return -1;

	// Backup old protect
	DWORD dwOldProtect;
	if (VirtualProtect(lpOrgFunc, 6, PAGE_EXECUTE_READWRITE, &dwOldProtect) == NULL)
		return -1;

	// Replacing
	memcpy_s(lpOrgFunc, 6, prevFunction, 6);

	// Rollback protection
	VirtualProtect(lpOrgFunc, 6, dwOldProtect, NULL);
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		Hook();
		break;
	case DLL_PROCESS_DETACH:
		UnHook();
		break;
	}
	return TRUE;
}