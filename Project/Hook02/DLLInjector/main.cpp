#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

DWORD findPID(LPCTSTR szProcessName);
BOOL injectDLL(DWORD dwPID, LPCTSTR szDLLName);

int main(int argc, char *argv[])
{
	char *target = "notepad.exe";
	char *dll = "E:\\workspace\\Personal Project\\HookingStudy\\Project\\Hook02\\Debug\\Hook02.dll";

	DWORD pid = findPID(target);
	if (pid == 0xFFFFFFFF) {
		printf("[*] Process not found\n");
		return 1;
	}
	else {
		printf("[*] pid : %u\n", pid);
	}
	if (!injectDLL(pid, dll)) {
		printf("[*] Injection Failed\n");
		return 1;
	}
	else {
		printf("[*] Injection Successed\n");
	}
	return 0;
}

DWORD findPID(LPCTSTR szProcessName)
{
	DWORD dwPID = 0xFFFFFFFF;
	HANDLE hSnapshot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe;
	
	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("[*] CreateToolhelp32Snapshot Error");
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

	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID))) return FALSE;
	if (hProcess == INVALID_HANDLE_VALUE) {
		printf("[*] OpenProcess Error");
		return FALSE;
	}

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
	if (pRemoteBuf == INVALID_HANDLE_VALUE) {
		printf("[*] VirtualAllocEx Error");
		return FALSE;
	}

	WriteProcessMemory(hProcess, pRemoteBuf, szDLLName, dwBufSize, NULL);

	hMod = GetModuleHandle("kernel32.dll");
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryA");
	if (pThreadProc == INVALID_HANDLE_VALUE) {
		printf("[*] GetProcAddress Error");
		return FALSE;
	}

	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
	if (hThread == INVALID_HANDLE_VALUE) {
		printf("[*] CreateRemoteThread Error");
		return FALSE;
	}

	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return TRUE;
}