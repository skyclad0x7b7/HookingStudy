#include <stdio.h>
#include <WinSock2.h>
#include <Windows.h>
#include <Shlwapi.h>

#define LOG_FILE "E:\\test\\test.log"

#pragma pack(1)
struct NEW_FUNC {
	BYTE relJmp;
	LPVOID lpTarget;
	SHORT shortJmp;
};

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
	char writeBuf[32] = { 0, };
	HANDLE hFile = NULL;
	if (PathFileExists(LOG_FILE)) {
		if ((hFile = CreateFile(LOG_FILE, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE) {
			sprintf_s(errBuf, "[-] CreateFile (Make) Failed with %d", GetLastError());
			MessageBox(NULL, errBuf, "ERROR", NULL);
		}
	}
	else {
		if ((hFile = CreateFile(LOG_FILE, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, NULL, NULL)) == INVALID_HANDLE_VALUE) {
			sprintf_s(errBuf, "[-] First CreateFile (Open) Failed with %d", GetLastError());
			MessageBox(NULL, errBuf, "ERROR", NULL);
		}
	}
	for (int i = 0; i < dwBufferCount; i++) {
		sprintf_s(writeBuf, "[%d] : ", i);
		if (WriteFile(hFile, writeBuf, strlen(writeBuf), NULL, NULL) != NULL) {
			sprintf_s(errBuf, "[-] First WriteFile Failed with %d", GetLastError());
			MessageBox(NULL, errBuf, "ERROR", NULL);
		}
		if (WriteFile(hFile, lpBuffers[i].buf, lpBuffers[i].len, NULL, NULL) != NULL) {
			sprintf_s(errBuf, "[-] Second WriteFile Failed with %d", GetLastError());
			MessageBox(NULL, errBuf, "ERROR", NULL);
		}
	}
	CloseHandle(hFile);
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
	newFuncObj.shortJmp = 0xF9EB;

	// Set new functon to replace
	newFuncObj.lpTarget = (LPVOID)((DWORD)&NewWSASend - ((DWORD)lpOrgFunc - 5) - 5);

	// Replacing
	memcpy_s((LPVOID)((DWORD)lpOrgFunc - 5), 7, &newFuncObj, 7);

	// Rollback protection
	if (VirtualProtect((LPVOID)((DWORD)lpOrgFunc - 5), 7, dwOldProtect, NULL) == NULL)
		return -1;
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