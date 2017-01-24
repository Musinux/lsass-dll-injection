#ifndef _INJECT_H
#define _INJECT_H
#include <Windows.h>

int injectDll(const char *);
int installExe();
DWORD getProcessId(char *processName);

#endif