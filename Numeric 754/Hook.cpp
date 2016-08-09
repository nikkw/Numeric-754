#include <Windows.h>
#include <stdio.h>
#include "Hook.h"
#include "Functions.h"

char Numeric[2][101];
char szClientIP[128][16];

char* __stdcall GetIPFromClient(INT32 ClientID){
	if(szClientIP[ClientID][1] == 0)
		return NULL;
	else
		return szClientIP[ClientID];
}

void __stdcall Hook::CloseUser(INT32 ClientID){
	Numeric[0][ClientID] = false;
	Numeric[1][ClientID] = 0;
	SecureZeroMemory(&szClientIP[ClientID], 16);
}

INT32 __stdcall Hook::AcceptUser(INT32 FixClientID, const char* szIPAddress){
	FILE* hFile = NULL;
	char szLocal[1024];
	INT32 dwBan = false;
	SecureZeroMemory(&szLocal, sizeof szLocal);
	sprintf_s(szLocal, "DataBase\\Accounts\\BanIP\\%s.txt", szIPAddress);
	fopen_s(&hFile, szLocal, "r");
	if(hFile){
		Functions* Function = new Functions();
		char szBan[11] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		fgets(szBan, 11, hFile);
		fclose(hFile);
		DWORD dwDateBan[3] = {0, 0, 0};
		DWORD dwDateTM[3] = {
			*(UINT16*)(0x00A5EA41C),
			*(UINT16*)(0x00A5EA420) + 1,
			*(UINT16*)(0x00A5EA424) + 1900
		};
		sscanf_s(szBan, "%d/%d/%d", &dwDateBan[0], &dwDateBan[1], &dwDateBan[2]);
		if(dwDateBan[0] >=  dwDateTM[0] && dwDateBan[1] >= dwDateTM[1] && dwDateBan[2] >= dwDateTM[2]){
			Function->CloseUser(FixClientID);
			dwBan = true;
		}
		delete Function;
	}
	if(!dwBan)
		strcpy_s(szClientIP[FixClientID], szIPAddress);
	return dwBan;
}

void __stdcall Hook::PacketControl(unsigned char* szBuffer, INT32 FixClientID){
	PacketHeader* Header = (PacketHeader*)szBuffer;
	Functions* Function = new Functions();

	switch(Header->OPCode){
		case 0xFDE:
			Header->ClientID = FixClientID;
			Function->Numeric754(szBuffer);
			break;
		default:
			if(Header->OPCode != 0x20D && Header->OPCode != 0xFDE && Header->OPCode != 0x3A0){
				if(!Numeric[0][FixClientID]){
					Header->OPCode = NULL;
					Function->SendClientMSG(FixClientID, "Wait a Moment");
				}
			}
			break;
	}
	delete Function;
}