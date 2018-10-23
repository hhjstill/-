#include <stdio.h>
#include <windows.h>

//char* shellCode = "\xEB\x05\x48\x65\x6C\x6C\x00\xB8\x08\x10\x40\x00\x6A\x00\x6A\x00\x50\x6A\x00\x8B\x0D\x34\x20\x40\x00\xFF\xD1";
//                 // "\xEB\x05\x48\x65\x6C\x6C\x00\xB8\x08\x10\x40\x00\x6A\x00\x6A\x00\x50\x6A\x00\x8B\x0D\x34\x20\x40\x00\xFF\xD1"
//int main()
//{
//	_asm
//	{
//		mov ebx, shellCode;
//		push ebx;
//		ret;
//	}
//	//_asm
//	//{
//	//	jmp exu;
//	//data:
//	//	_emit 0x48;
//	//	_emit 0x65;
//	//	_emit 0x6C;
//	//	_emit 0x6C;
//	//	_emit 0;
//	//exu:
//	//	mov eax, data;
//	//	push 0;
//	//	push 0;
//	//	push eax;
//	//	push 0;
//	//	mov ecx, MessageBoxA;
//	//	call ecx;
//	//}
//	return 0;
//}

//int main()
//{
//	_asm  call FLAG_;
//FLAG_:
//	_asm  pop esi;
//	_asm mov[ebp - 0x10], esi;
//	_asm jmp ST_;
//	_asm
//	{
//	DATA_:
//		_emit 71; 
//		_emit 101; 
//		_emit 116; 
//		_emit 80; 
//		_emit 114; 
//		_emit 111;
//		_emit 99; 
//		_emit 65; 
//		_emit 100; 
//		_emit 100; 
//		_emit 114; 
//		_emit 101; 
//		_emit 115; 
//		_emit 115;
//	DATA2_:
//		_emit(0x4C);
//		_emit(0x6F);
//		_emit(0x61);
//		_emit(0x64);
//		_emit(0x4C);
//		_emit(0x69);
//		_emit(0x62);
//		_emit(0x72);
//		_emit(0x61);
//		_emit(0x72);
//		_emit(0x79);
//		_emit(0x45);
//		_emit(0x78);
//		_emit(0x41);
//	USER_:
//		_emit(0x75);
//		_emit(0x73);
//		_emit(0x65); 
//		_emit(0x72); 
//		_emit(0x33); 
//		_emit(0x32); 
//		_emit(0x2E); 
//		_emit(0x64); 
//		_emit(0x6C); 
//		_emit(0x6C); 
//		_emit(0);
//	MSG_:
//		_emit(0x4D);
//		_emit(0x65);
//		_emit(0x73);
//		_emit(0x73);
//		_emit(0x61);
//		_emit(0x67);
//		_emit(0x65);
//		_emit(0x42);
//		_emit(0x6F);
//		_emit(0x78);
//		_emit(0x41);
//		_emit(0);
//	EXIT_:
//		_emit(0x45); 
//		_emit(0x78); 
//		_emit(0x69); 
//		_emit(0x74); 
//		_emit(0x50); 
//		_emit(0x72); 
//		_emit(0x6F); 
//		_emit(0x63); 
//		_emit(0x65); 
//		_emit(0x73); 
//		_emit(0x73);
//		_emit(0);
//	HELLO:
//		_emit(0x48);
//		_emit(0x65);
//		_emit(0x6C);
//		_emit(0x6C);
//		_emit(0x6F);
//		_emit(0x20);
//		_emit(0x31);
//		_emit(0x35);
//		_emit(0x50);
//		_emit(0x42);
//		_emit(0x21);
//		_emit(0);
//	}
//	_asm
//	{
//	getApiAddr__:
//		push ebp;
//		mov ebp, esp;
//		sub esp, 0xC;
//		push edx;
//		push esi;
//		push edi;
//		//EAT va
//		mov[ebp - 4], edx;
//		//ENT va
//		mov[ebp - 8], esi;
//		//EOT va
//		mov[ebp - 0xC], edi;
//		xor eax, eax;
//		push ecx;
//		jmp ok_;
//	loop_:
//		inc eax;
//	ok_:
//		mov esi, [ebp - 8];
//		lea esi, [esi + 4 * eax];
//		mov ecx, [esi];
//		add ecx, ebx;
//		mov esi, ecx;
//		mov edi, [ebp + 8];
//		pop ecx;
//		push ecx;
//		repe cmpsb;
//		cmp ecx, 0;
//		jne loop_;
//		mov ecx, [ebp - 0xC];
//		lea ecx, [ecx + 2 * eax];
//		xor eax, eax;
//		mov ax, word ptr[ecx];
//		lea edx, [edx + 4 * eax];
//		mov edx, [edx];
//		add edx, ebx;
//		mov eax, edx;
//
//		pop ecx;
//		pop edi;
//		pop esi;
//		pop edx;
//		
//		mov esp, ebp;
//		pop ebp;
//		ret 4;
//	}
//	_asm
//	{
//	ST_:
//		sub esp, 0x50;
//		mov eax, fs:[0x30];
//		mov eax, [eax + 0xC];
//		mov eax, [eax + 0x1C];
//		mov eax, [eax];
//		mov eax, [eax + 8];
//		//eax = kernel32»ùÖ·
//		//mov ebx, [eax + 0x3c];
//		////ebx = NT header
//		//add ebx, eax;
//		////edx = opt header
//		//lea edx, [ebx + 18h];
//		
//		lea ebx, [eax + 0x170];
//		mov ecx, [ebx];
//		add ecx, eax;
//		//ecx = expAddrVA
//		//EAT
//		mov edx, [ecx + 0x1C];
//		add edx, eax;
//		//ENT
//		mov esi, [ecx + 0x20];
//		add esi, eax;
//		//EOT
//		mov edi, [ecx + 0x24];
//		add edi, eax;
//		//numOfName
//		mov ecx, [ecx + 0x18];
//		//±£´æ»ùÖ·
//		mov ebx, eax;
//		
//		//mov eax, DATA_;//
//		mov eax, [ebp - 0x10];
//		add eax, 9;
//
//		mov ecx, 0xE;
//		push eax;
//		call getApiAddr__;
//		mov[ebp - 4], eax;
//
//		//mov eax, DATA2_;
//		mov eax, [ebp - 0x10];
//		add eax, 23;
//
//		push eax;
//		mov ecx, 0xf;
//		call getApiAddr__;
//		mov[ebp - 8], eax;
//
//		//mov eax, MSG_;
//		mov eax, [ebp - 0x10];
//		add eax, 48;
//
//		push eax;
//		push 0;
//		push 0;
//
//		//mov eax, USER_;
//		mov eax, [ebp - 0x10];
//		add eax, 37;
//
//		push eax;
//		call[ebp - 8];
//		push eax;
//		call[ebp - 4];
//		push 0;
//		push 0;
//
//		//mov ecx, HELLO;
//		mov ecx, ebp;
//		add ecx, 72;
//
//		push ecx;
//		push 0;
//		call eax;
//
//		//mov eax, EXIT_;
//		mov ecx, [ebp - 0x10];
//		add ecx, 60;
//
//		push ecx;
//		push ebx;
//		call[ebp - 4];
//		push 0;
//		call eax;
//	}
//	return 0;
//}
//char* shell = "\xE9\x99\x00\x00\x00\x47\x65\x74\x50\x72\x6F\x63\x41\x64\x64\x72\x65\x73\x73\x4C\x6F\x61\x64\x4C\x69\x62\x72\x61\x72\x79\x45\x78\x41\x75\x73\x65\x72\x33\x32\x2E\x64\x6C\x6C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F\x78\x41\x00\x45\x78\x69\x74\x50\x72\x6F\x63\x65\x73\x73\x00\x48\x65\x6C\x6C\x6F\x20\x31\x35\x50\x42\x21\x00\x55\x8B\xEC\x83\xEC\x0C\x52\x56\x57\x89\x55\xFC\x89\x75\xF8\x89\x7D\xF4\x33\xC0\x51\xEB\x01\x40\x8B\x75\xF8\x8D\x34\x86\x8B\x0E\x03\xCB\x8B\xF1\x8B\x7D\x08\x59\x51\xF3\xA6\x83\xF9\x00\x75\xE7\x8B\x4D\xF4\x8D\x0C\x41\x33\xC0\x66\x8B\x01\x8D\x14\x82\x8B\x12\x03\xD3\x8B\xC2\x59\x5F\x5E\x5A\x8B\xE5\x5D\xC2\x04\x00\x83\xEC\x50\x64\xA1\x30\x00\x00\x00\x8B\x40\x0C\x8B\x40\x1C\x8B\x00\x8B\x40\x08\x8D\x98\x70\x01\x00\x00\x8B\x0B\x03\xC8\x8B\x51\x1C\x03\xD0\x8B\x71\x20\x03\xF0\x8B\x79\x24\x03\xF8\x8B\x49\x18\x8B\xD8\xB8\x0B\x10\x40\x00\xB9\x0E\x00\x00\x00\x50\xE8\x70\xFF\xFF\xFF\x89\x45\xFC\xB8\x19\x10\x40\x00\x50\xB9\x0F\x00\x00\x00\xE8\x5D\xFF\xFF\xFF\x89\x45\xF8\xB8\x32\x10\x40\x00\x50\x6A\x00\x6A\x00\xB8\x27\x10\x40\x00\x50\xFF\x55\xF8\x50\xFF\x55\xFC\x6A\x00\x6A\x00\xB9\x4A\x10\x40\x00\x51\x6A\x00\xFF\xD0\xB8\x3E\x10\x40\x00\x50\x53\xFF\x55\xFC\x6A\x00\xFF\xD0";
//
char* shell = "\xE8\x00\x00\x00\x00\x5E\x89\x75\xF0\xE9\x99\x00\x00\x00\x47\x65\x74\x50\x72\x6F\
\x63\x41\x64\x64\x72\x65\x73\x73\x4C\x6F\x61\x64\x4C\x69\x62\x72\x61\x72\x79\x45\x78\x41\x75\
\x73\x65\x72\x33\x32\x2E\x64\x6C\x6C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F\x78\x41\x00\x45\
\x78\x69\x74\x50\x72\x6F\x63\x65\x73\x73\x00\x48\x65\x6C\x6C\x6F\x20\x31\x35\x50\x42\x21\x00\
\x55\x8B\xEC\x83\xEC\x0C\x52\x56\x57\x89\x55\xFC\x89\x75\xF8\x89\x7D\xF4\x33\xC0\x51\xEB\x01\
\x40\x8B\x75\xF8\x8D\x34\x86\x8B\x0E\x03\xCB\x8B\xF1\x8B\x7D\x08\x59\x51\xF3\xA6\x83\xF9\x00\
\x75\xE7\x8B\x4D\xF4\x8D\x0C\x41\x33\xC0\x66\x8B\x01\x8D\x14\x82\x8B\x12\x03\xD3\x8B\xC2\x59\
\x5F\x5E\x5A\x8B\xE5\x5D\xC2\x04\x00\x83\xEC\x50\x64\xA1\x30\x00\x00\x00\x8B\x40\x0C\x8B\x40\
\x1C\x8B\x00\x8B\x40\x08\x8D\x98\x70\x01\x00\x00\x8B\x0B\x03\xC8\x8B\x51\x1C\x03\xD0\x8B\x71\
\x20\x03\xF0\x8B\x79\x24\x03\xF8\x8B\x49\x18\x8B\xD8\x8B\x45\xF0\x83\xC0\x09\xB9\x0E\x00\x00\
\x00\x50\xE8\x6F\xFF\xFF\xFF\x89\x45\xFC\x8B\x45\xF0\x83\xC0\x17\x50\xB9\x0F\x00\x00\x00\xE8\
\x5B\xFF\xFF\xFF\x89\x45\xF8\x8B\x45\xF0\x83\xC0\x30\x50\x6A\x00\x6A\x00\x8B\x45\xF0\x83\xC0\
\x25\x50\xFF\x55\xF8\x50\xFF\x55\xFC\x6A\x00\x6A\x00\x8B\x4D\xF0\x83\xC1\x48\x51\x6A\x00\xFF\
\xD0\x8B\x4D\xF0\x83\xC1\x3C\x51\x53\xFF\x55\xFC\x6A\x00\xFF\xD0";

int main()
{
	_asm {
		mov eax, shell;
		push eax;
		ret;
	}
	return 0;
}