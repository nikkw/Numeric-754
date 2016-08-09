#include "main.h"
#include "Naked.h"
#include "Hook.h"
#include "Functions.h"

void SetJMP(INT32 dwOLD, INT32 dwNEW, INT32 Size){
	DWORD OldProt = PAGE_EXECUTE_READWRITE;
	VirtualProtect((void*)(dwOLD), Size, OldProt, &OldProt);
	memset((void*)(dwOLD), 0x90, Size);
	*(BYTE*)(dwOLD) = 0xE9;
	*(DWORD*)(dwOLD + 1) = dwNEW - dwOLD - 5;
	VirtualProtect((void*)(dwOLD), Size, OldProt, &OldProt);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved){
    switch (fdwReason){
        case DLL_PROCESS_ATTACH:
			ZeroMemory(&Numeric, sizeof Numeric);
			SetJMP(0x00459465, (INT32)&Naked::CloseUser, 7);
			SetJMP(0x0044AF6B, (INT32)&Naked::Recv, 6);
			SetJMP(0x0041A3E9, (INT32)&Naked::AcceptUser, 6);
			*(DWORD*)(0x00482DE0) = (DWORD)&GetIPFromClient;
			MessageBoxA(0, "Créditos: sizeof", "Numeric754", 4096);
			break;
    }
    return TRUE;
}