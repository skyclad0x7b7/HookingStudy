#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <Shlwapi.h>

BOOL injection(LPCTSTR procName, LPCTSTR dllName);
BOOL ejection(LPCTSTR procName, LPCTSTR dllName);
DWORD findPID(LPCTSTR szProcessName);
BOOL injectDLL(DWORD dwPID, LPCTSTR szDLLName);
BOOL ejectDLL(DWORD dwPID, LPCTSTR szDLLName);

HANDLE hTargetMod = NULL;

int main(int argc, char *argv[])
{
	// Arguments check
	if (argc != 4) {
		printf("[*] Usage : %s [inject/eject] [TargetProcess] [DLL]\n", argv[0]);
		return 1;
	}

	if (!strcmp(argv[1], "inject")) {
		// DLL Injection
		if (injection(argv[2], argv[3]) == FALSE)
			printf("[-] Injection Failed\n");
		else
			printf("[+] Injection Successed\n");
		system("pause");
		ejection(argv[2], argv[3]);
	}
	else if (!strcmp(argv[1], "eject")) {
		if (ejection(argv[2], argv[3]) == FALSE)
			printf("[-] ejection Failed\n");
		else
			printf("[+] ejection Successed\n");
	}
	else
		printf("[*] Usage : %s [inject/eject] [Target] [DLL]\n", argv[0]);

	return 0;
}

BOOL injection(LPCTSTR procName, LPCTSTR dllName)
{
	// Check DLL Existence
	if (!PathFileExists(dllName)) {
		printf("[-] DLL Not Exists : %s\n", dllName);
		return FALSE;
	}

	// Find ProcessID
	DWORD pid = findPID(procName);
	if (pid == 0xFFFFFFFF) {
		printf("[-] Process not found\n");
		return FALSE;
	}
	else {
		printf("[*] pid : %u\n", pid);
	}
	
	// Try Injecting DLL
	if (!injectDLL(pid, dllName))
		return FALSE;

	return TRUE;
}

BOOL ejection(LPCTSTR procName, LPCTSTR dllName)
{
	// Find ProcessID
	DWORD pid = findPID(procName);
	if (pid == 0xFFFFFFFF) {
		printf("[-] Process not found\n");
		return FALSE;
	}
	else {
		printf("[*] pid : %u\n", pid);
	}

	// Try Injecting DLL
	if (!ejectDLL(pid, dllName))
		return FALSE;

	return TRUE;
}

DWORD findPID(LPCTSTR szProcessName)
{
	// Get Snapshots
	HANDLE hSnapshot = NULL;
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("[*] CreateToolhelp32Snapshot Error\n");
		return 0xFFFFFFFF;
	}

	// Find Process
	DWORD dwPID = 0xFFFFFFFF;
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
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
	// Get target process handle
	HANDLE hProcess = NULL;
	if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)) == INVALID_HANDLE_VALUE) {
		printf("[-] OpenProcess Error\n");
		printf("[-] gle : 0x%x\n", GetLastError());
		return FALSE;
	}

	// Allocate memory to target process
	LPVOID pRemoteBuf = NULL;
	DWORD dwBufSize = lstrlen(szDLLName) + 1;
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
	HMODULE hMod = NULL;
	if ((hMod = GetModuleHandle("kernel32.dll")) == INVALID_HANDLE_VALUE) {
		printf("[-] GetModuleHandle Error\n");
		printf("[-] gle : 0x%x\n", GetLastError());
		return FALSE;
	}

	// Get address of "LoadLibraryA"
	LPTHREAD_START_ROUTINE pThreadProc = NULL;
	if ((pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryA")) == INVALID_HANDLE_VALUE) {
		printf("[-] GetProcAddress Error\n");
		printf("[-] gle : 0x%x\n", GetLastError());
		return FALSE;
	}

	// Create and run remote thread in target process
	HANDLE hThread = NULL;
	if ((hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[-] CreateRemoteThread Error\n");
		printf("[-] gle : 0x%x\n", GetLastError());
		return FALSE;
	}

	WaitForSingleObject(hThread, INFINITE);
	GetExitCodeThread(hThread, (LPDWORD)&hTargetMod);
	CloseHandle(hThread);
	CloseHandle(hProcess);
	return TRUE;
}

BOOL ejectDLL(DWORD dwPID, LPCTSTR szDLLName)
{
	// Get target process handle
	HANDLE hProcess = NULL;
	if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)) == INVALID_HANDLE_VALUE) {
		printf("[-] OpenProcess Error\n");
		printf("[-] gle : 0x%x\n", GetLastError());
		return FALSE;
	}

	// Get handle of "kernel32.dll"
	HMODULE hMod = NULL;
	if ((hMod = GetModuleHandle("kernel32.dll")) == INVALID_HANDLE_VALUE) {
		printf("[-] Second GetModuleHandle Error\n");
		printf("[-] gle : 0x%x\n", GetLastError());
		return FALSE;
	}

	// Get address of "FreeLibrary"
	LPTHREAD_START_ROUTINE pThreadProc = NULL;
	if ((pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "FreeLibrary")) == NULL) {
		printf("[-] GetProcAddress Error\n");
		printf("[-] gle : 0x%x\n", GetLastError());
		return FALSE;
	}

	// Create and run remote thread in target process
	HANDLE hThread = NULL;
	if ((hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, hTargetMod, 0, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[-] CreateRemoteThread Error\n");
		printf("[-] gle : 0x%x\n", GetLastError());
		return FALSE;
	}

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	CloseHandle(hProcess);
	return TRUE;
}