#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <Shlwapi.h>

BOOL injection(const char *, const char *);
DWORD findPID(LPCTSTR szProcessName);
BOOL injectDLL(DWORD dwPID, LPCTSTR szDLLName);

int main(int argc, char *argv[])
{
	// Arguments check
	if (argc != 3) {
		printf("[*] Usage : %s [inject/eject] [Target] [DLL]\n", argv[0]);
		return 1;
	}

	if (!strcmp(argv[1], "inject")) {
		// DLL Injection
		if (injection(argv[2], argv[3]) == FALSE)
			printf("[-] Injection Failed\n");
		else
			printf("[-] Injection Successed\n");
	}
	else if (!strcmp(argv[1], "eject")) {
		// DLL Ejection
	}
	else
		printf("[*] Usage : %s [inject/eject] [Target] [DLL]\n", argv[0]);

	return 0;
}

BOOL injection(const char *procName, const char *dllName)
{
	if (!PathFileExists(dllName)) {
		printf("[-] DLL Not Exists : %s\n", dllName);
		return FALSE;
	}

	DWORD pid = findPID(procName);
	if (pid == 0xFFFFFFFF) {
		printf("[-] Process not found\n");
		return FALSE;
	}
	else {
		printf("[*] pid : %u\n", pid);
	}
	if (!injectDLL(pid, procName)) 
		return FALSE;

	return TRUE;
}

DWORD findPID(LPCTSTR szProcessName)
{
	DWORD dwPID = 0xFFFFFFFF;
	HANDLE hSnapshot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe;

	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("[*] CreateToolhelp32Snapshot Error\n");
		return 0xFFFFFFFF;
	}

	Process32First(hSnapshot, &pe);
	do {
		if (!_stricmp(szProcessName, pe.szExeFile)) {
			dwPID = pe.th32ProcessID;
			break;
		}
	} while (Process32Next(hSnapshot, &pe));

	CloseHandle(hSnapshot);
	return dwPID;
}

BOOL injectDLL(DWORD dwPID, LPCTSTR szDLLName)
{
	HANDLE hProcess, hThread;
	HMODULE hMod;

	LPVOID pRemoteBuf;
	DWORD dwBufSize = lstrlen(szDLLName) + 1;
	LPTHREAD_START_ROUTINE pThreadProc;

	// Get target process handle
	if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)) == INVALID_HANDLE_VALUE) {
		printf("[-] OpenProcess Error\n");
		printf("[-] gle : 0x%x\n", GetLastError());
		return FALSE;
	}

	// Allocate memory to target process
	if ((pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE)) == INVALID_HANDLE_VALUE) {
		printf("[-] VirtualAllocEx Error\n");
		printf("[-] gle : 0x%x\n", GetLastError());
		return FALSE;
	}

	// Write DLL name to target process memory
	if (WriteProcessMemory(hProcess, pRemoteBuf, szDLLName, dwBufSize, NULL) == FALSE) {
		printf("[-] WriteProcessMemory Error\n");
		printf("[-] gle : 0x%x\n", GetLastError());
		return FALSE;
	}

	// Get handle of "kernel32.dll"
	if ((hMod = GetModuleHandle("kernel32.dll")) == INVALID_HANDLE_VALUE) {
		printf("[-] GetModuleHandle Error\n");
		printf("[-] gle : 0x%x\n", GetLastError());
		return FALSE;
	}

	// Get address of "LoadLibraryA"
	if ((pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryA")) == INVALID_HANDLE_VALUE) {
		printf("[-] GetProcAddress Error\n");
		printf("[-] gle : 0x%x\n", GetLastError());
		return FALSE;
	}

	// Create and run remote thread in target process
	if ((hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[-] CreateRemoteThread Error\n");
		printf("[-] gle : 0x%x\n", GetLastError());
		return FALSE;
	}

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	CloseHandle(hProcess);
	return TRUE;
}