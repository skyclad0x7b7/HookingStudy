// 32-bit WSASend Hooking (Code patching)

#include "NewFunctions.h"

#include <stdio.h>

#include <WinSock2.h>
#include <Windows.h>
#include <Shlwapi.h>

#define LOG_FILE "E:\\test\\test.log"

#pragma pack(push, 1)
struct HOOK_5BYTES
{
	SHORT Opcode;
	LPVOID lpTarget;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct HOOK_7BYTES {
	BYTE relJmp;
	LPVOID lpTarget;
	SHORT shortJmp;
};
#pragma pack(pop)

DWORD WINAPI WSASendHook()
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
		HOOK_5BYTES*  lpSavedFunc = (HOOK_5BYTES*)VirtualAlloc(NULL, sizeof(HOOK_5BYTES), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		HOOK_5BYTES   newFuncObj;
		memcpy_s(lpSavedFunc, 6, lpOrgFunc, 6);
		PrevWSASendFunction = (tWSASend*)lpSavedFunc;

		// Absolute Jump
		newFuncObj.Opcode = 0x25FF;

		// Set new functon to replace
		NewWSASendFunction = &NewWSASend;
		newFuncObj.lpTarget = &NewWSASendFunction;

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
		HOOK_7BYTES *lpSavedFunc = (HOOK_7BYTES *)VirtualAlloc(NULL, sizeof(HOOK_7BYTES), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		HOOK_7BYTES newFuncObj;
		memcpy_s(lpSavedFunc, 7, (LPVOID)((DWORD)lpOrgFunc - 5), 7);
		PrevWSASendFunction = (tWSASend *)((DWORD)lpOrgFunc + 2);

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

DWORD WINAPI WSARecvHook()
{
	// Get handle of target dll
	HMODULE hModule = NULL;
	if ((hModule = GetModuleHandleA("Ws2_32.dll")) == INVALID_HANDLE_VALUE)
		return -1;

	// Get address of target function
	LPVOID lpOrgFunc = NULL;
	if ((lpOrgFunc = GetProcAddress(hModule, "WSARecv")) == NULL)
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
		HOOK_5BYTES*  lpSavedFunc = (HOOK_5BYTES*)VirtualAlloc(NULL, sizeof(HOOK_5BYTES), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		HOOK_5BYTES   newFuncObj;
		memcpy_s(lpSavedFunc, 6, lpOrgFunc, 6);
		PrevWSARecvFunction = (tWSARecv*)lpSavedFunc;

		// Absolute Jump
		newFuncObj.Opcode = 0x25FF;

		// Set new functon to replace
		NewWSARecvFunction = &NewWSARecv;
		newFuncObj.lpTarget = &NewWSARecvFunction;

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
		HOOK_7BYTES *lpSavedFunc = (HOOK_7BYTES *)VirtualAlloc(NULL, sizeof(HOOK_7BYTES), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		HOOK_7BYTES newFuncObj;
		memcpy_s(lpSavedFunc, 7, (LPVOID)((DWORD)lpOrgFunc - 5), 7);
		PrevWSARecvFunction = (tWSARecv*)((DWORD)lpOrgFunc + 2);

		// Set OPCODE
		newFuncObj.relJmp = 0xE9;
		newFuncObj.shortJmp = (short)0xF9EB;

		// Set new functon to replace
		newFuncObj.lpTarget = (LPVOID)((DWORD)&NewWSARecv - ((DWORD)lpOrgFunc - 5) - 5);

		// Replacing
		memcpy_s((LPVOID)((DWORD)lpOrgFunc - 5), 7, &newFuncObj, 7);

		// Rollback protection
		if (VirtualProtect((LPVOID)((DWORD)lpOrgFunc - 5), 7, dwOldProtect, NULL) == NULL)
			return -1;
	}
	return 0;
}

DWORD WINAPI SendHook()
{
	// Get handle of target dll
	HMODULE hModule = NULL;
	if ((hModule = GetModuleHandleA("Ws2_32.dll")) == INVALID_HANDLE_VALUE)
		return -1;

	// Get address of target function
	LPVOID lpOrgFunc = NULL;
	if ((lpOrgFunc = GetProcAddress(hModule, "send")) == NULL)
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
		HOOK_5BYTES*  lpSavedFunc = (HOOK_5BYTES*)VirtualAlloc(NULL, sizeof(HOOK_5BYTES), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		HOOK_5BYTES   newFuncObj;
		memcpy_s(lpSavedFunc, 6, lpOrgFunc, 6);
		PrevSendFunction = (tSend*)lpSavedFunc;

		// Absolute Jump
		newFuncObj.Opcode = 0x25FF;

		// Set new functon to replace
		NewSendFunction = &NewSend;
		newFuncObj.lpTarget = &NewSendFunction;

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
		HOOK_7BYTES *lpSavedFunc = (HOOK_7BYTES *)VirtualAlloc(NULL, sizeof(HOOK_7BYTES), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		HOOK_7BYTES newFuncObj;
		memcpy_s(lpSavedFunc, 7, (LPVOID)((DWORD)lpOrgFunc - 5), 7);
		PrevSendFunction = (tSend *)((DWORD)lpOrgFunc + 2);

		// Set OPCODE
		newFuncObj.relJmp = 0xE9;
		newFuncObj.shortJmp = (short)0xF9EB;

		// Set new functon to replace
		newFuncObj.lpTarget = (LPVOID)((DWORD)&NewSend - ((DWORD)lpOrgFunc - 5) - 5);

		// Replacing
		memcpy_s((LPVOID)((DWORD)lpOrgFunc - 5), 7, &newFuncObj, 7);

		// Rollback protection
		if (VirtualProtect((LPVOID)((DWORD)lpOrgFunc - 5), 7, dwOldProtect, NULL) == NULL)
			return -1;
	}
	return 0;
}

DWORD WINAPI RecvHook()
{
	// Get handle of target dll
	HMODULE hModule = NULL;
	if ((hModule = GetModuleHandleA("Ws2_32.dll")) == INVALID_HANDLE_VALUE)
		return -1;

	// Get address of target function
	LPVOID lpOrgFunc = NULL;
	if ((lpOrgFunc = GetProcAddress(hModule, "recv")) == NULL)
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
		HOOK_5BYTES*  lpSavedFunc = (HOOK_5BYTES*)VirtualAlloc(NULL, sizeof(HOOK_5BYTES), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		HOOK_5BYTES   newFuncObj;
		memcpy_s(lpSavedFunc, 6, lpOrgFunc, 6);
		PrevRecvFunction = (tRecv*)lpSavedFunc;

		// Absolute Jump
		newFuncObj.Opcode = 0x25FF;

		// Set new functon to replace
		NewRecvFunction = &NewRecv;
		newFuncObj.lpTarget = &NewRecvFunction;

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
		HOOK_7BYTES *lpSavedFunc = (HOOK_7BYTES *)VirtualAlloc(NULL, sizeof(HOOK_7BYTES), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		HOOK_7BYTES newFuncObj;
		memcpy_s(lpSavedFunc, 7, (LPVOID)((DWORD)lpOrgFunc - 5), 7);
		PrevRecvFunction = (tRecv *)((DWORD)lpOrgFunc + 2);

		// Set OPCODE
		newFuncObj.relJmp = 0xE9;
		newFuncObj.shortJmp = (short)0xF9EB;

		// Set new functon to replace
		newFuncObj.lpTarget = (LPVOID)((DWORD)&NewRecv - ((DWORD)lpOrgFunc - 5) - 5);

		// Replacing
		memcpy_s((LPVOID)((DWORD)lpOrgFunc - 5), 7, &newFuncObj, 7);

		// Rollback protection
		if (VirtualProtect((LPVOID)((DWORD)lpOrgFunc - 5), 7, dwOldProtect, NULL) == NULL)
			return -1;
	}
	return 0;
}

DWORD WINAPI Hook()
{
	WSASendHook();
	WSARecvHook();
	SendHook();
	RecvHook();
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