#pragma once

#include <iostream>
#include <fstream>
#include <WinSock2.h>
#include <Windows.h>

/* WSASend */
typedef int WINAPI tWSASend(
	_In_  SOCKET                             s,
	_In_  LPWSABUF                           lpBuffers,
	_In_  DWORD                              dwBufferCount,
	_Out_ LPDWORD                            lpNumberOfBytesSent,
	_In_  DWORD                              dwFlags,
	_In_  LPWSAOVERLAPPED                    lpOverlapped,
	_In_  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);

tWSASend *PrevWSASendFunction;
tWSASend *NewWSASendFunction;

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
	myLogFile << "\r\n ========= [WSASend] ========= \r\n";
	for (unsigned int i = 0; i < dwBufferCount; i++) {
		myLogFile.write(lpBuffers[i].buf, lpBuffers[i].len);
	}
	myLogFile << "\r\n ============================= \r\n";
	myLogFile.close();
	return PrevWSASendFunction(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
}

/* WSARecv */
typedef int WINAPI tWSARecv(
	_In_    SOCKET                             s,
	_Inout_ LPWSABUF                           lpBuffers,
	_In_    DWORD                              dwBufferCount,
	_Out_   LPDWORD                            lpNumberOfBytesRecvd,
	_Inout_ LPDWORD                            lpFlags,
	_In_    LPWSAOVERLAPPED                    lpOverlapped,
	_In_    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);

tWSARecv *PrevWSARecvFunction;
tWSARecv *NewWSARecvFunction;

int WINAPI NewWSARecv(
	_In_    SOCKET                             s,
	_Inout_ LPWSABUF                           lpBuffers,
	_In_    DWORD                              dwBufferCount,
	_Out_   LPDWORD                            lpNumberOfBytesRecvd,
	_Inout_ LPDWORD                            lpFlags,
	_In_    LPWSAOVERLAPPED                    lpOverlapped,
	_In_    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
	char errBuf[128] = { 0, };
	std::ofstream myLogFile;
	while (!myLogFile.is_open())
		myLogFile.open("E:\\test\\test.log", std::ios::out | std::ios::app | std::ios::binary);
	myLogFile << "\r\n ========= [WSARecv] ========= \r\n";
	for (unsigned int i = 0; i < dwBufferCount; i++) {
		myLogFile.write(lpBuffers[i].buf, lpBuffers[i].len);
	}
	myLogFile << "\r\n ============================= \r\n";
	myLogFile.close();
	return PrevWSARecvFunction(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
}


/* send */
typedef int WINAPI tSend(
	_In_       SOCKET s,
	_In_ const char   *buf,
	_In_       int    len,
	_In_       int    flags
);

tSend *PrevSendFunction;
tSend *NewSendFunction;

int WINAPI NewSend(
	_In_       SOCKET s,
	_In_ const char   *buf,
	_In_       int    len,
	_In_       int    flags
)
{
	char errBuf[128] = { 0, };
	std::ofstream myLogFile;
	while (!myLogFile.is_open())
		myLogFile.open("E:\\test\\test.log", std::ios::out | std::ios::app | std::ios::binary);
	myLogFile << "\r\n ========= [Send] ========= \r\n";
	myLogFile.write(buf, len);
	myLogFile << "\r\n ========================== \r\n";
	myLogFile.close();
	return PrevSendFunction(s, buf, len, flags);
}


/* recv */
typedef int WINAPI tRecv(
	_In_  SOCKET s,
	_Out_ char   *buf,
	_In_  int    len,
	_In_  int    flags
);

tRecv *PrevRecvFunction;
tRecv *NewRecvFunction;

int WINAPI NewRecv(
	_In_  SOCKET s,
	_Out_ char   *buf,
	_In_  int    len,
	_In_  int    flags
)
{
	char errBuf[128] = { 0, };
	std::ofstream myLogFile;
	while (!myLogFile.is_open())
		myLogFile.open("E:\\test\\test.log", std::ios::out | std::ios::app | std::ios::binary);
	myLogFile << "\r\n ========= [Recv] ========= \r\n";
	myLogFile.write(buf, len);
	myLogFile << "\r\n ========================== \r\n";
	myLogFile.close();
	return PrevRecvFunction(s, buf, len, flags);
}