// 32-bit WSASend Hooking (Code patching)

#include <stdio.h>
#include <iostream>
#include <fstream>
#include <WinSock2.h>
#include <Windows.h>
#include <Shlwapi.h>

#define LOG_FILE "E:\\test\\test.log"

#pragma pack(push, 1)
struct IAT_STRUCT
{
	SHORT Opcode;
	LPVOID lpTarget;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct NEW_FUNC {
	BYTE relJmp;
	LPVOID lpTarget;
	SHORT shortJmp;
};
#pragma pack(pop)

typedef int WINAPI tWSASend(
	_In_  SOCKET                             s,
	_In_  LPWSABUF                           lpBuffers,
	_In_  DWORD                              dwBufferCount,
	_Out_ LPDWORD                            lpNumberOfBytesSent,
	_In_  DWORD                              dwFlags,
	_In_  LPWSAOVERLAPPED                    lpOverlapped,
	_In_  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);

tWSASend *prevFunction;
tWSASend *newFunction;

int WINAPI NewWSASend(
	_In_  SOCKET                             s,
	_In_  LPWSABUF                           lpBuffers,
	_In_  DWORD                              dwBufferCount,
	_Out_ LPDWORD                            lpNumberOfBytesSent,
	_In_  DWORD                              dwFlags,
	_In_  LPWSAOVERLAPPED                    lpOverlapped,
	_In_  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
	char errBuf[128] = { 0, };
	std::ofstream myLogFile;
	while (!myLogFile.is_open()) 
		myLogFile.open("E:\\test\\test.log", std::ios::out | std::ios::app | std::ios::binary);
	for (unsigned int i = 0; i < dwBufferCount; i++) {
		myLogFile.write(lpBuffers[i].buf, lpBuffers[i].len);
	}
	myLogFile.close();
	return prevFunction(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
}

DWORD WINAPI Hook()
{
	// Get handle of target dll
	HMODULE hModule = NULL;
	if ((hModule = GetModuleHandleA("Ws2_32.dll")) == INVALID_HANDLE_VALUE)
		return -1;

	// Get address of target function
	LPVOID lpOrgFunc = NULL;
	if ((lpOrgFunc = GetProcAddress(hModule, "WSASend")) == NULL)
		return -1;

	DWORD hookLength = 0;
	if ((*(SHORT *)lpOrgFunc) == 0x25FF)
		hookLength = 6;
	else
		hookLength = 7;

	if (hookLength == 6) // IAT Hooking
	{
		// Backup old function IAT
		DWORD dwOldProtect = NULL;
		IAT_STRUCT*  lpSavedFunc = (IAT_STRUCT*)VirtualAlloc(NULL, sizeof(IAT_STRUCT), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		IAT_STRUCT   newFuncObj;
		memcpy_s(lpSavedFunc, 6, lpOrgFunc, 6);
		prevFunction = (tWSASend*)lpSavedFunc;

		// Absolute Jump
		newFuncObj.Opcode = 0x25FF;

		// Set new functon to replace
		newFunction = &NewWSASend;
		newFuncObj.lpTarget = &newFunction;

		// Replacing
		memcpy_s(lpOrgFunc, 6, &newFuncObj, 6);

		// Rollback protection
		if (VirtualProtect(lpOrgFunc, 7, dwOldProtect, NULL) == NULL)
			return -1;
	}
	else // Code patching
	{
		// Backup set new protect and old protect
		DWORD dwOldProtect = NULL;
		if (VirtualProtect((LPVOID)((DWORD)lpOrgFunc - 5), 7, PAGE_EXECUTE_READWRITE, &dwOldProtect) == NULL)
			return -1;

		// Backup old function
		NEW_FUNC *lpSavedFunc = (NEW_FUNC *)VirtualAlloc(NULL, sizeof(NEW_FUNC), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		NEW_FUNC newFuncObj;
		memcpy_s(lpSavedFunc, 7, (LPVOID)((DWORD)lpOrgFunc - 5), 7);
		prevFunction = (tWSASend *)((DWORD)lpOrgFunc + 2);

		// Set OPCODE
		newFuncObj.relJmp = 0xE9;
		newFuncObj.shortJmp = (short)0xF9EB;

		// Set new functon to replace
		newFuncObj.lpTarget = (LPVOID)((DWORD)&NewWSASend - ((DWORD)lpOrgFunc - 5) - 5);

		// Replacing
		memcpy_s((LPVOID)((DWORD)lpOrgFunc - 5), 7, &newFuncObj, 7);

		// Rollback protection
		if (VirtualProtect((LPVOID)((DWORD)lpOrgFunc - 5), 7, dwOldProtect, NULL) == NULL)
			return -1;
	}
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
		break;
	}
	return TRUE;
}