// YoloService.cpp : définit le point d'entrée pour l'application console.
//

#include "stdafx.h"
#include <windows.h>
#include <tchar.h>
#include <strsafe.h>
#include <psapi.h>
#include "YoloInject.h"

const char yoloDllPath[] = "C:\\Users\\admin\\Documents\\Dll\\YoloDll\\Release\\YoloDll.dll";

VOID __stdcall InstallReinstallSvc(BOOL reinstall);
VOID __stdcall UninstallSvc();
VOID __stdcall StartSvc();
VOID WINAPI SvcMain(DWORD dwArgc, LPTSTR *lpszArgv);
void setLogFileService();
VOID SvcInit(DWORD dwArgc, LPTSTR *lpszArgv);
VOID ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint);
DWORD WINAPI Thread(LPVOID lpParam);
VOID WINAPI CtrlHandler(DWORD dwCtrl);

SERVICE_STATUS          gSvcStatus;
SERVICE_STATUS_HANDLE   gSvcStatusHandle;

// Communication API with SCM
#pragma comment(lib, "advapi32.lib")
#define SVCNAME TEXT("YoloService")

int __cdecl _tmain(int argc, _TCHAR* argv[])
{
	if (lstrcmpi(argv[1], TEXT("install")) == 0){
		printf("install service\n");
		InstallReinstallSvc(true);
		system("pause");
		return 0;
	}

	if (lstrcmpi(argv[1], TEXT("start")) == 0){
		printf("start service\n");
		StartSvc();
		system("pause");
		return 0;
	}

	if (lstrcmpi(argv[1], TEXT("uninstall")) == 0){
		printf("uninstall service\n");
		UninstallSvc();
		system("pause");
		return 0;
	}
	SERVICE_TABLE_ENTRY DispatchTable[] =
	{
		{ SVCNAME, (LPSERVICE_MAIN_FUNCTION)SvcMain },
		{ NULL, NULL }
	};

	if (!StartServiceCtrlDispatcher(DispatchTable))
	{
		return 0;
	}
}

// Install SVCNAME service
VOID __stdcall InstallReinstallSvc(BOOL reinstall)
{
	SC_HANDLE schSCManager;

	TCHAR ServicePath[MAX_PATH];

	if (!GetModuleFileName(NULL, ServicePath, MAX_PATH))
	{
		printf("Cannot install service (%d)\n", GetLastError());
		return;
	}

	// Get a handle to the SCM database. 
	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == schSCManager)
	{
		printf("OpenSCManager failed (%d)\n", GetLastError());
		return;
	}

	SC_HANDLE yoloService = OpenService(schSCManager, SVCNAME, SC_MANAGER_ALL_ACCESS);
	if (yoloService && reinstall == TRUE) {
		printf("Delete previous service.\n");
		DeleteService(yoloService);
	}

	CloseServiceHandle(yoloService);

	// Create the service
	yoloService = CreateService(
		schSCManager,              // SCM database 
		SVCNAME,                   // name of service 
		SVCNAME,                   // service name to display 
		SERVICE_ALL_ACCESS,        // desired access 
		SERVICE_WIN32_OWN_PROCESS, // service type 
		SERVICE_DEMAND_START,      // start type 
		SERVICE_ERROR_NORMAL,      // error control type 
		ServicePath,               // path to service's binary 
		NULL,                      // no load ordering group 
		NULL,                      // no tag identifier 
		NULL,                      // no dependencies 
		NULL,                      // LocalSystem account 
		NULL);                     // no password 

	if (yoloService == NULL)
	{
		printf("CreateService failed (%d)\n", GetLastError());
		CloseServiceHandle(schSCManager);
		return;
	}
	else printf("Service installed successfully\n");

	if (!StartService(yoloService, 0, NULL)) {
		printf("Couldn't start service. error: %i\n", GetLastError());
	}
	
	CloseServiceHandle(yoloService);
	CloseServiceHandle(schSCManager);
}

VOID __stdcall UninstallSvc() {
	SC_HANDLE schSCManager;

	// Get a handle to the SCM database. 
	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == schSCManager)
	{
		printf("OpenSCManager failed (%d)\n", GetLastError());
		return;
	}

	SC_HANDLE yoloService = OpenService(schSCManager, SVCNAME, SC_MANAGER_ALL_ACCESS);
	if (yoloService) {
		printf("Delete previous service.\n");
		DeleteService(yoloService);
	}
	CloseServiceHandle(yoloService);
	CloseServiceHandle(schSCManager);
}

void __stdcall StartSvc() {
	SC_HANDLE schSCManager;
	// Get a handle to the SCM database. 
	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == schSCManager)
	{
		printf("OpenSCManager failed (%d)\n", GetLastError());
		return;
	}

	SC_HANDLE yoloService = OpenService(schSCManager, SVCNAME, SC_MANAGER_ALL_ACCESS);
	if (!yoloService) {
		printf("No yoloService: stopping\n");
		return;
	}
	if (!StartService(yoloService, 0, NULL)) {
		printf("Couldn't start service. error: %i\n", GetLastError());
	}

	CloseServiceHandle(yoloService);
	CloseServiceHandle(schSCManager);
}




VOID WINAPI SvcMain(DWORD dwArgc, LPTSTR *lpszArgv)
{
	// Register the handler function for the service
	gSvcStatusHandle = RegisterServiceCtrlHandler(SVCNAME, CtrlHandler);

	if (!gSvcStatusHandle)
	{
		printf("Couldn't register status");
		return;
	}
	//printf("OK");

	// These SERVICE_STATUS members remain as set here

	gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	gSvcStatus.dwServiceSpecificExitCode = 0;

	// Report initial status to the SCM

	ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

	// Perform service-specific initialization and work.

	SvcInit(dwArgc, lpszArgv);
}


VOID SvcInit(DWORD dwArgc, LPTSTR *lpszArgv)
{
	// Report running status when initialization is complete.
	ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);

	// Start a thread that will perform the main task of the service

	HANDLE hThread = CreateThread(NULL, 0, Thread, NULL, 0, NULL);


	// Check whether to stop the service.
	WaitForSingleObject(hThread, INFINITE);

	ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
}


VOID ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
{
	static DWORD dwCheckPoint = 1;

	// Fill in the SERVICE_STATUS structure.

	gSvcStatus.dwCurrentState = dwCurrentState;
	gSvcStatus.dwWin32ExitCode = dwWin32ExitCode;
	gSvcStatus.dwWaitHint = dwWaitHint;

	if (dwCurrentState == SERVICE_START_PENDING)
		gSvcStatus.dwControlsAccepted = 0;
	else gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

	if ((dwCurrentState == SERVICE_RUNNING) ||
		(dwCurrentState == SERVICE_STOPPED))
		gSvcStatus.dwCheckPoint = 0;
	else gSvcStatus.dwCheckPoint = dwCheckPoint++;

	// Report the status of the service to the SCM.
	SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
}


VOID WINAPI CtrlHandler(DWORD dwCtrl)
{
	// Handle the requested control code. 

	switch (dwCtrl)
	{
	case SERVICE_CONTROL_STOP:
		ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
		ReportSvcStatus(gSvcStatus.dwCurrentState, NO_ERROR, 0);

		return;

	case SERVICE_CONTROL_INTERROGATE:
		break;

	default:
		break;
	}

}

DWORD WINAPI Thread(LPVOID lpParam)
{
	setLogFileService();
	installExe();
	injectDll(yoloDllPath);
	return ERROR_SUCCESS;
}

void setLogFileService() {
	char filename[] = "C:\\Users\\admin\\Documents\\Dll\\YoloDll\\yolo_service_log.22.txt";
	FILE *out;
	freopen_s(&out, filename, "a+", stdout);
	printf("setLogFileService OK.\n");
}
