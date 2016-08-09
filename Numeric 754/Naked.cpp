#include <Windows.h>
#include "Naked.h"
#include "Hook.h"

void __declspec(naked) Naked::CloseUser(){
	static const DWORD dwContinue = 0x0045946C;
	__asm{
		PUSH DWORD PTR SS:[EBP+08h]
		CALL Hook::CloseUser
		MOV DWORD PTR SS:[EBP-08h], 00h
		JMP dwContinue
	}
}

void __declspec(naked) Naked::Recv(){
	static const DWORD dwContinue = 0x0044AF71;
	__asm{
		MOV EAX, DWORD PTR SS:[EBP-54h]
		MOV DWORD PTR SS:[EBP-58h], EAX
		PUSH DWORD PTR SS:[EBP-40h]
		PUSH DWORD PTR DS:[EBP-54h]
		CALL Hook::PacketControl
		JMP dwContinue
	}
}

void __declspec(naked) Naked::AcceptUser(){
	static const DWORD dwContinue[2] = {0x0041A3EF, 0x0041A411};
	__asm{
		MOV DWORD PTR SS:[EBP-20h], EAX
		PUSH EAX
		MOV EAX, DWORD PTR SS:[EBP-04h]
		SUB EAX, 07B318C8h
		MOV ECX, 0C4Ch
		XOR EDX, EDX
		IDIV ECX
		PUSH EAX
		CALL Hook::AcceptUser
		CMP EAX, 01h
		JE Banned
		MOV EAX, DWORD PTR SS:[EBP-04h]
		JMP dwContinue
	Banned:
		XOR EAX, EAX
		JMP dwContinue + 04h
	}
}