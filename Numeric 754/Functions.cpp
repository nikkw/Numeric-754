#include <Windows.h>
#include "Hook.h"
#include "Functions.h"
#include <stdio.h>

Functions::Functions(){
	CloseUser = (void (__cdecl*)(INT32))0x00459440;
	SendClientMSG = (void (__cdecl*)(INT32, const char*))0x004010FF;
}

Functions::~Functions(){
}

void __stdcall Functions::Numeric754(unsigned char* szBuffer){
	pFDE Request;
	pFDE* Packet = (pFDE*)szBuffer;
	FILE* hFile = NULL;
	char szLocal[1024];
	char szNumeric[7] = {0, 0, 0, 0, 0, 0, 0};
	SecureZeroMemory(&szLocal, sizeof szLocal);
	sprintf_s(szLocal, "DataBase\\Accounts\\Numeric\\%s.txt", (char*)((Packet->Header.ClientID * 0xC4C) + 0x07B318C8));
	fopen_s(&hFile, szLocal, "r");
	if(!hFile){
		fopen_s(&hFile, szLocal, "w+");
		if(!hFile){
			SendClientMSG(Packet->Header.ClientID, "Erro ao definir senha, contate o administrador");
			return;
		}
		fputs(Packet->Numeric, hFile);
		fclose(hFile);
		SendClientMSG(Packet->Header.ClientID, "Senha definida com sucesso");
		Numeric[0][Packet->Header.ClientID] = true;
		return;
	}
	else{
		fgets(szNumeric, 6, hFile);
		fclose(hFile);
		if(Packet->ChangeNumeric == 1 && Numeric[0][Packet->Header.ClientID]){
			fopen_s(&hFile, szLocal, "w+");
			if(!hFile){
				SendClientMSG(Packet->Header.ClientID, "Erro ao alterar senha, contate o administrador");
				return;
			}
			fputs(Packet->Numeric, hFile);
			fclose(hFile);
			Request.Header.Size = sizeof pFDE;
			Request.Header.OPCode = 0xFDE;
			SendPacket(Packet->Header.ClientID, (unsigned char*)&Request, sizeof pFDE);
			SendClientMSG(Packet->Header.ClientID, "Senha Alterada");
			return;
		}
		else{
			if(!strcmp(szNumeric, Packet->Numeric)){
				Request.Header.Size = sizeof pFDE;
				Request.Header.OPCode = 0xFDE;
				SendPacket(Packet->Header.ClientID, (unsigned char*)&Request, sizeof pFDE);
				SendClientMSG(Packet->Header.ClientID, "Senha Correta");
				Numeric[0][Packet->Header.ClientID] = true;
				Numeric[1][Packet->Header.ClientID] = 0;
				return;
			}
			else{
				Request.Header.Size = 12;
				Request.Header.OPCode = 0xFDF;
				SendPacket(Packet->Header.ClientID, (unsigned char*)&Request, 12);
				SendClientMSG(Packet->Header.ClientID, "Senha Incorreta");
				Numeric[0][Packet->Header.ClientID] = false;
				Numeric[1][Packet->Header.ClientID] += 1;
				if(Numeric[1][Packet->Header.ClientID] >= 5){
					CloseUser(Packet->Header.ClientID);
				}
				return;
			}
		}
	}
}

void __stdcall Functions::SendPacket(INT32 ClientID, unsigned char* szBuffer, INT32 SizeOfPacket){
	static const DWORD dwSendPacket = 0x004198C0;
	const DWORD dwSocket = (ClientID * 0xC4C) + 0x07B318E8;
	__asm{
		PUSH SizeOfPacket
		PUSH szBuffer
		MOV ECX, dwSocket
		CALL dwSendPacket
	}
}