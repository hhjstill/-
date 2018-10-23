// packDll.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include <stdlib.h>
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#pragma comment(lib, "ntdll.lib")
#pragma comment(linker,"/merge:.data=.text")
#pragma comment(linker,"/merge:.rdata=.text")
//#pragma comment(linker,"/merge:.tls=.text")
#pragma comment(linker, "/section:.text,RWE")

#include "aplib.h"
#pragma comment(lib,"aPlib.lib")
//增加DLL的TLS回调函数
//--------------------------------------------------------------------------
#pragma comment(linker, "/INCLUDE:__tls_used")
void NTAPI TlsCallBackFunction1(PVOID Handle, DWORD Reason, PVOID Reserve);
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK TlsCallBackArray[] = {
	TlsCallBackFunction1,
	//TlsCallBackFunction2,
	NULL
};
#pragma data_seg()
//-----------------------------------------------------------------------------

struct TypeOffset
{
	WORD offset : 12;
	WORD type : 4;
};
typedef struct DATA_START_OVER_
{
	DWORD startAddr;
	DWORD size;
	bool isEncrypt;
}DATA_START_OVER_;
typedef struct IMP_START_OVER_
{
	DWORD dllNameAddr;
	DWORD intAddr;
	DWORD iatAddr;
	DWORD numOfName;
}IMP_START_OVER_;
typedef struct DATA_DIRECTOR_
{
	DWORD virtualAddr;
	DWORD size;
}DATA_DIRECTOR_;
typedef struct STUB_CONFIG_
{
	DWORD oep;
	DWORD peImageBase;
	DWORD key;
	DWORD iatRva;
	DWORD iatSize;
	DWORD dataDirector_ImpTab;
	DWORD numOfEncrySection;
	DWORD numOfImportDll;
	DWORD dataDirector_RVA;
	DATA_DIRECTOR_ dataDirectorInfoArry[0x10];
	DATA_START_OVER_ dataStartAndOverArry[0x10];
	IMP_START_OVER_ impStartAndOverArry[0x10];
}STUB_CONFIG_;
typedef struct START_AND_SIZE_
{
	DWORD startAddrRva;
	DWORD size;
	DWORD originSize;
	DWORD sizeOfRawData;
	bool isPacked;
}START_AND_SIZE_;
typedef struct PACK_INFO_
{
	DWORD numOfSection;
	START_AND_SIZE_ packSectionInfo[0x10];
}PACK_INFO_;

//获取DOS头
IMAGE_DOS_HEADER* getDosHeader(_In_  char* pBaseAddr) {
	return (IMAGE_DOS_HEADER *)pBaseAddr;
}

// 获取NT头
IMAGE_NT_HEADERS* getNtHeader(_In_  char* pBaseAddr) {
	return (IMAGE_NT_HEADERS*)(getDosHeader(pBaseAddr)->e_lfanew + (SIZE_T)pBaseAddr);
}

//获取文件头
IMAGE_FILE_HEADER* getFileHeader(_In_  char* pBaseAddr) {
	return &getNtHeader(pBaseAddr)->FileHeader;
}

//获取扩展头
IMAGE_OPTIONAL_HEADER* getOptionHeader(_In_  char* pBaseAddr) {
	return &getNtHeader(pBaseAddr)->OptionalHeader;
}
typedef DWORD(WINAPI*pFnLoadLibrary)(LPVOID);
typedef LPVOID(WINAPI*pFnGetProcAddr)(HANDLE,LPVOID);
typedef BOOL(WINAPI*pFnVirtualProtect)(LPVOID ,SIZE_T ,DWORD ,PDWORD);
typedef LPVOID(WINAPI*pFnVirtualAlloc)(LPVOID ,SIZE_T ,DWORD ,DWORD);
typedef BOOL(WINAPI*pFnVirtualFree)( LPVOID , SIZE_T ,DWORD );
typedef int(WINAPI*pFnMessageBoxA)(HWND ,LPCSTR ,LPCSTR ,UINT );
typedef ATOM (WINAPI*pFnRegisterClassExA)(WNDCLASSEXA *);
typedef HWND (WINAPI*pFnCreateWindowExA)(
_In_ DWORD dwExStyle,
_In_opt_ LPCSTR lpClassName,
_In_opt_ LPCSTR lpWindowName,
_In_ DWORD dwStyle,
_In_ int X,
_In_ int Y,
_In_ int nWidth,
_In_ int nHeight,
_In_opt_ HWND hWndParent,
_In_opt_ HMENU hMenu,
_In_opt_ HINSTANCE hInstance,
_In_opt_ LPVOID lpParam);
typedef BOOL (WINAPI*pFnShowWindow)(_In_ HWND hWnd,_In_ int nCmdShow);
typedef BOOL(WINAPI*pFnUpdateWindow)(_In_ HWND hWnd);
typedef BOOL(WINAPI*pFnGetMessageA)(
	_Out_ LPMSG lpMsg,
	_In_opt_ HWND hWnd,
	_In_ UINT wMsgFilterMin,
	_In_ UINT wMsgFilterMax);
typedef BOOL(WINAPI*pFnTranslateMessage)(_In_ CONST MSG *lpMsg);
typedef LRESULT(WINAPI*pFnDispatchMessageA)(_In_ CONST MSG *lpMsg);
typedef VOID(WINAPI*pFnPostQuitMessage)(_In_ int nExitCode);
typedef HWND(WINAPI*pFnGetDlgItem)(_In_opt_ HWND hDlg,_In_ int nIDDlgItem);
typedef int(WINAPI*pFnGetWindowTextA)(_In_ HWND hWnd,_Out_writes_(nMaxCount) LPSTR lpString,_In_ int nMaxCount);
typedef LRESULT(WINAPI*pFnDefWindowProcA)(_In_ HWND hWnd,_In_ UINT Msg,_In_ WPARAM wParam,_In_ LPARAM lParam);
typedef HMODULE(WINAPI*pFnGetModuleHandleA)(_In_opt_ LPCSTR lpModuleName);
typedef VOID(WINAPI*pFnExitProcess)(_In_ UINT); 
//--------------------------------------------------------------------------------
typedef HANDLE(WINAPI*pFnCreateToolhelp32Snapshot)(DWORD,DWORD);
typedef BOOL(WINAPI*pFnProcess32FirstW)(HANDLE hSnapshot,LPPROCESSENTRY32W lppe);
typedef BOOL(WINAPI*pFnProcess32NextW)(HANDLE hSnapshot,LPPROCESSENTRY32W lppe);
typedef BOOL(WINAPI*pFnCloseHandle)(_In_ HANDLE hObject);
typedef UINT(WINAPI*pFnWinExec)(_In_ LPCSTR lpCmdLine,_In_ UINT uCmdShow);
typedef HINSTANCE(WINAPI*pFnShellExecuteA)(_In_opt_ HWND hwnd, _In_opt_ LPCSTR lpOperation, 
	_In_ LPCSTR lpFile, _In_opt_ LPCSTR lpParameters,_In_opt_ LPCSTR lpDirectory, _In_ INT nShowCmd);
typedef LPTOP_LEVEL_EXCEPTION_FILTER(WINAPI*pFnSetUnhandledExceptionFilter)(_In_opt_ LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);

pFnLoadLibrary myLoadLibrary;
pFnGetProcAddr myGetProcAddr;
pFnVirtualProtect myVirTualProtect;
pFnVirtualAlloc myVirtualAlloc;
pFnVirtualFree myVirtualFree;
pFnMessageBoxA myMessageBoxA;
pFnRegisterClassExA myRegisterClass;
pFnCreateWindowExA myCreateWindow;
pFnShowWindow myShowWindow;
pFnUpdateWindow myUpdateWindow;
pFnGetMessageA myGetMessage;
pFnTranslateMessage myTranslateMsg;
pFnDispatchMessageA myDispatchMsg;
pFnPostQuitMessage myPostMsg;
pFnGetDlgItem myGetDlgItem;
pFnGetWindowTextA myGetWindowText;
pFnDefWindowProcA myDefWindowProc;
pFnGetModuleHandleA myGetModuleHandle;
pFnExitProcess myExitProcess;
pFnSetUnhandledExceptionFilter mySetUeh;
//----------------------------------------------
pFnCreateToolhelp32Snapshot myCreateToolhelp;
pFnProcess32FirstW myProcessFirst;
pFnProcess32NextW myProcessNext;
pFnCloseHandle myCloseHandle;
pFnWinExec myWinExec;
pFnShellExecuteA myShellExec;

void decode();
void unpack();
void acquireFuncAddr();
void passwordCheck();
void fixOriginReloc();
void tlsCall();
DWORD randomImageBase;
extern "C"
{
	_declspec(dllexport) STUB_CONFIG_ cfg = {0};
	_declspec(dllexport) PACK_INFO_ pi = { 0 };
	_declspec(dllexport) char password[MAX_PATH] = {};
	_declspec(dllexport) _declspec(naked) void entry()
	{
		_asm pushad;
		_asm pushfd;
		//acquireFuncAddr();
		//randomImageBase = (DWORD)myGetModuleHandle(0);
		//解压缩
		unpack();
		//解密函数
		decode();
		passwordCheck();
		//tls调用
		tlsCall();
		cfg.oep += randomImageBase;
		_asm popfd;
		_asm popad;
		_asm jmp cfg.oep;
	}

}
void decode()
{
	//1.分别解密各个区段的数据(按照未对齐大小)
	//myLoadLibrary = (pFnLoadLibrary)cfg.loadLibAddr;//获取必要函数地址
	//myGetProcAddr = (pFnGetProcAddr)cfg.getProcAddr;
	//myVirTualProtect = (pFnVirtualProtect)cfg.virtualProtect;
	
	for (DWORD i = 0; i < cfg.numOfEncrySection; i++)
	{
		for (DWORD j = 0; j < cfg.dataStartAndOverArry[i].size; j++)
		{
			if (cfg.dataStartAndOverArry[i].isEncrypt)
			{
				PBYTE addr = PBYTE(cfg.dataStartAndOverArry[i].startAddr + randomImageBase + j);
				DWORD old = 0;
				myVirTualProtect(addr, 1, PAGE_READWRITE, &old);
				*addr ^= cfg.key;
				myVirTualProtect(addr, 1, old, &old);
			}
		}
	}
	fixOriginReloc();
	//2.修复IAT,并将IAT指针恢复

	for (DWORD i = 0; i < cfg.numOfImportDll; i++)
	{
		char* dllName = (char*)(cfg.impStartAndOverArry[i].dllNameAddr + randomImageBase);//DLL名称
		DWORD dllBase = myLoadLibrary(dllName);//获取DLL基址
		for (DWORD j = 0; j < cfg.impStartAndOverArry[i].numOfName; j++)
		{
			//char* nameStr = (char*)(DWORD((DWORD*)cfg.impStartAndOverArry[i].intAddr + j) + cfg.peImageBase);//得到INT中每个函数名称结构体的VA
			DWORD intVA = cfg.impStartAndOverArry[i].intAddr + randomImageBase;//INT数组首地址VA
			DWORD by_name_stc_VA = *((DWORD*)intVA + j) + randomImageBase;//名称结构体VA
			char* nameStr = (char*)(by_name_stc_VA + 2);
			//nameStr += 2;//函数名字符串,以0结尾
			DWORD funcAddr = (DWORD)myGetProcAddr((HANDLE)dllBase, nameStr);//获取函数地址
																			//填充IAT
			DWORD iatAddr = cfg.impStartAndOverArry[i].iatAddr + j * 4 + randomImageBase;//获取iat的VA
			DWORD old = 0;
			BYTE* pAllocAddr = (BYTE*)myVirtualAlloc(0, 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			//申请堆空间加一些简单的混淆
			DWORD temp = (DWORD)pAllocAddr;
			*(WORD*)pAllocAddr = 0xFFEB;
			temp += 2;
			*(pAllocAddr + 2) = 0x15;
			temp++;
			*(DWORD*)temp = DWORD(pAllocAddr) + 0xA;
			temp += 7;

			*(DWORD*)temp = DWORD(pAllocAddr) + 0x20;
			*(BYTE*)(pAllocAddr + 0x20) = 0x83;
			*(WORD*)(pAllocAddr + 0x21) = 0x4c4;
			*(WORD*)(pAllocAddr + 0x23) = 0xECEB;
			*(pAllocAddr + 7) = 0xC3;
			*(WORD*)(pAllocAddr + 8) = 0x25FF;
			*(WORD*)(pAllocAddr + 0xF) = 0x15ff;

			temp += 7;
			*(WORD*)temp = 0x25ff;
			temp += 2;
			*(DWORD*)temp = DWORD(pAllocAddr) + 0x1A;
			*(DWORD*)(pAllocAddr + 0x1A) = funcAddr;
			myVirTualProtect((LPVOID)iatAddr, 1, PAGE_READWRITE, &old);
			if (_stricmp(dllName, "MSVCP140D.DLL") == 0)
			{
				*(DWORD*)iatAddr = funcAddr;
			}
			else
				*(DWORD*)iatAddr = (DWORD)pAllocAddr;
			myVirTualProtect((LPVOID)iatAddr, 1, old, &old);
		}
	}
	DWORD old = 0;
	DWORD dataInfoAddrVA = cfg.dataDirector_RVA + randomImageBase;
	myVirTualProtect(LPVOID(dataInfoAddrVA), 1, PAGE_READWRITE, &old);
	//恢复原始数据目录表
	for (DWORD i = 0; i < 16; i++)
	{
		*(DWORD*)(dataInfoAddrVA + i * 8) = cfg.dataDirectorInfoArry[i].virtualAddr;
		*(DWORD*)(dataInfoAddrVA + i * 8 + 4) = cfg.dataDirectorInfoArry[i].size;
	}
	myVirTualProtect(LPVOID(dataInfoAddrVA), 1, old, &old);
	//修复重定位

	myMessageBoxA(0, "所有区段解密完毕!", "解密:", 0);
}

void acquireFuncAddr()
{
	// 1. 先获取kernel32的加载基址
	HMODULE hKernel32 = NULL;
	_asm
	{
		mov eax, FS:[0x30];
		mov eax, [eax + 0xc];
		mov eax, [eax + 0xc];
		mov eax, [eax];
		mov eax, [eax];
		mov eax, [eax + 0x18];
		mov hKernel32, eax;
	}
	// 2. 再获取LoadLibrayA和GetProcAddress函数的地址
	// 2.1 遍历导出表获取函数地址
	IMAGE_EXPORT_DIRECTORY* pExp = NULL;
	pExp = (IMAGE_EXPORT_DIRECTORY*)
		(getOptionHeader((char*)hKernel32)->DataDirectory[0].VirtualAddress + (DWORD)hKernel32);

	DWORD* pEAT = NULL, *pENT = NULL;
	WORD* pEOT = NULL;
	pEAT = (DWORD*)(pExp->AddressOfFunctions + (DWORD)hKernel32);
	pENT = (DWORD*)(pExp->AddressOfNames + (DWORD)hKernel32);
	pEOT = (WORD*)(pExp->AddressOfNameOrdinals + (DWORD)hKernel32);
	for (size_t i = 0; i < pExp->NumberOfNames; i++)
	{
		char* pName = pENT[i] + (char*)hKernel32;
		if (strcmp(pName, "GetProcAddress") == 0) {
			int index = pEOT[i];
			myGetProcAddr = (pFnGetProcAddr)(pEAT[index] + (DWORD)hKernel32);
			break;
		}
	}
	// 3. 通过这两个API获取其它的API
	myLoadLibrary =(pFnLoadLibrary)myGetProcAddr(hKernel32, "LoadLibraryA");
	myVirTualProtect = (pFnVirtualProtect)myGetProcAddr(hKernel32, "VirtualProtect");
	myVirtualAlloc = (pFnVirtualAlloc)myGetProcAddr(hKernel32, "VirtualAlloc");
	myVirtualFree = (pFnVirtualFree)myGetProcAddr(hKernel32, "VirtualFree");
	myGetModuleHandle = (pFnGetModuleHandleA)myGetProcAddr(hKernel32, "GetModuleHandleA");
	HANDLE hUser32 = (HANDLE)myLoadLibrary("User32.dll");
	myMessageBoxA = (pFnMessageBoxA)myGetProcAddr(hUser32, "MessageBoxA");
	myExitProcess = (pFnExitProcess)myGetProcAddr(hKernel32, "ExitProcess");
	myRegisterClass = (pFnRegisterClassExA)myGetProcAddr(hUser32, "RegisterClassExA");
	myCreateWindow = (pFnCreateWindowExA)myGetProcAddr(hUser32, "CreateWindowExA");
	myShowWindow = (pFnShowWindow)myGetProcAddr(hUser32, "ShowWindow");
	myUpdateWindow = (pFnUpdateWindow)myGetProcAddr(hUser32, "UpdateWindow");
	myGetMessage = (pFnGetMessageA)myGetProcAddr(hUser32, "GetMessageA");
	myTranslateMsg = (pFnTranslateMessage)myGetProcAddr(hUser32, "TranslateMessage");
	myDispatchMsg = (pFnDispatchMessageA)myGetProcAddr(hUser32, "DispatchMessageA");
	myPostMsg = (pFnPostQuitMessage)myGetProcAddr(hUser32, "PostQuitMessage");
	myGetDlgItem = (pFnGetDlgItem)myGetProcAddr(hUser32, "GetDlgItem");
	myGetWindowText = (pFnGetWindowTextA)myGetProcAddr(hUser32, "GetWindowTextA");
	myDefWindowProc = (pFnDefWindowProcA)myGetProcAddr(hUser32, "DefWindowProcA");
	mySetUeh = (pFnSetUnhandledExceptionFilter)myGetProcAddr(hKernel32, "SetUnhandledExceptionFilter");
	//----------------------------------------------------------------------------------------------------
	myCreateToolhelp = (pFnCreateToolhelp32Snapshot)myGetProcAddr(hKernel32, "CreateToolhelp32Snapshot");
	myProcessFirst = (pFnProcess32FirstW)myGetProcAddr(hKernel32, "Process32FirstW");
	myProcessNext = (pFnProcess32NextW)myGetProcAddr(hKernel32, "Process32NextW");
	myCloseHandle = (pFnCloseHandle)myGetProcAddr(hKernel32, "CloseHandle");
	myWinExec = (pFnWinExec)myGetProcAddr(hKernel32, "WinExec");
	//----------------------------------------------------------------------
	HANDLE hShellDll = (HANDLE)myLoadLibrary("SHELL32.DLL");
	myShellExec = (pFnShellExecuteA)myGetProcAddr(hShellDll, "ShellExecuteA");
}

void unpack()
{
	//将各个区段解压缩
	for (DWORD i = 0; i < pi.numOfSection; i++)
	{
		if (!pi.packSectionInfo[i].isPacked)
			continue;
		
		DWORD old = 0;
		BYTE* needUnpackAddr = (BYTE*)randomImageBase + pi.packSectionInfo[i].startAddrRva;
		DWORD needUpackSize = pi.packSectionInfo[i].size;
		//uncompress(tempBuffer, &dwWrite, needUnpackAddr, needUpackSize);

		//-----------------------------------
		//         解压：

		/* get original size */
		size_t compressed_size = needUpackSize;
		size_t orig_size = pi.packSectionInfo[i].originSize;

		/* allocate memory for decompressed data */
		//char *tempBuffer = new char[orig_size];
		//memset(tempBuffer, 0, orig_size);
		char* tempBuffer = (char*)myVirtualAlloc(0, orig_size, MEM_COMMIT, PAGE_READWRITE);

		/* decompress compressed[] to data[] */
		//aPsafe_depack(需要被解压数据首地址, 被压缩后大小, 解压到哪里去, 压缩前原始大小);
		DWORD outlength =  aPsafe_depack(needUnpackAddr, compressed_size, tempBuffer, orig_size);


		//-----------------------------------
		myVirTualProtect(needUnpackAddr, outlength, PAGE_READWRITE, &old);
		memcpy(needUnpackAddr, tempBuffer, outlength);
		myVirTualProtect(needUnpackAddr, outlength, old, &old);

		myVirtualFree(tempBuffer, 0, MEM_RELEASE);
		//delete[] tempBuffer;
		//tempBuffer = nullptr;
	}
	//恢复头部信息
	PIMAGE_NT_HEADERS pNt = getNtHeader((char*)randomImageBase);
	PIMAGE_SECTION_HEADER pSecHeader = IMAGE_FIRST_SECTION(pNt);
	DWORD old = 0;
	myVirTualProtect(pSecHeader, 1, PAGE_READWRITE, &old);
	for (DWORD i = 0; i < pi.numOfSection; i++)
	{
		if (pi.packSectionInfo[i].isPacked)
			pSecHeader->SizeOfRawData = pi.packSectionInfo[i].sizeOfRawData;
		pSecHeader++;
	}
	myVirTualProtect(pSecHeader, 1, old, &old);
	myMessageBoxA(0, "解压缩完毕!", "解压缩:", 0);
}

void fixOriginReloc()
{
	PIMAGE_NT_HEADERS pNt = getNtHeader((char*)randomImageBase);//被加壳程序的NT头
	
	
	PIMAGE_OPTIONAL_HEADER pOption = getOptionHeader((char*)randomImageBase);
	DWORD pRelocTabRva = cfg.dataDirectorInfoArry[5].virtualAddr;
	//重定位表VA
	PIMAGE_BASE_RELOCATION pRelocTabVa = PIMAGE_BASE_RELOCATION(randomImageBase + pRelocTabRva);

	while (pRelocTabVa->SizeOfBlock)
	{
		//if (pRelocTabVa->VirtualAddress >= nextVirAddr)break;//只修复代码段的重定位
		//每个块中需要重定位数据的个数
		DWORD nNum = (pRelocTabVa->SizeOfBlock - 8) / 2;
		TypeOffset* typeOffset = (TypeOffset*)((DWORD)pRelocTabVa + 8);
		DWORD oldPro = 0;
		
		for (DWORD i = 0; i < nNum; i++)
		{
			if (typeOffset[i].type == 3)
			{
				DWORD* dwNeedRelocAddr = (DWORD*)(randomImageBase + pRelocTabVa->VirtualAddress + typeOffset[i].offset);
				//修复
				myVirTualProtect((LPVOID)(dwNeedRelocAddr), 4, PAGE_READWRITE, &oldPro);
				*dwNeedRelocAddr = *dwNeedRelocAddr - 0x400000 + randomImageBase;
				myVirTualProtect((LPVOID)(dwNeedRelocAddr), 4, oldPro, &oldPro);
			}
		}
		//下一个重定位表块
		pRelocTabVa = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocTabVa + pRelocTabVa->SizeOfBlock);
	}

}
LRESULT CALLBACK wndProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l)
{
	switch (msg)
	{
	case WM_CREATE:
		myCreateWindow(0, "edit", "", WS_BORDER | WS_CHILD | WS_VISIBLE, 20, 20, 420, 30, hwnd, (HMENU)0x1001, 0, 0);
		myCreateWindow(0, "button", "OK", WS_BORDER | WS_CHILD | WS_VISIBLE, 200, 100, 50, 30, hwnd, (HMENU)0x1002, 0, 0);
		break;
	case WM_CLOSE:
		myPostMsg(0);
		break;
	case WM_COMMAND:
		if (LOWORD(w) == 0x1002)
		{
			HWND hEdit = myGetDlgItem(hwnd, 0x1001);
			char buffer[MAX_PATH]{};
			myGetWindowText(hEdit, buffer, MAX_PATH);
			if (strcmp(buffer, password) == 0)
			{
				myMessageBoxA(0, "OK!", "提示", 0);
				myPostMsg(0);
			}
			else
			{
				myMessageBoxA(0, "Error password!", "提示", 0);
			}
		}
		break;
	}
	return myDefWindowProc(hwnd, msg, w, l);
}
void passwordCheck()
{
	WNDCLASSEXA wc{};
	wc.cbSize = sizeof(WNDCLASSEXA);
	wc.lpszClassName = "password";
	wc.lpfnWndProc = wndProc;
	myRegisterClass(&wc);
	HWND hWnd = myCreateWindow(0, wc.lpszClassName, "test", WS_BORDER | WS_OVERLAPPEDWINDOW | WS_VISIBLE, 500, 250, 500, 200, 0, 0, 0, 0);
	myShowWindow(hWnd, SW_SHOW);
	myUpdateWindow(hWnd);
	MSG msg;
	while (myGetMessage(&msg, 0, 0, 0))
	{
		myTranslateMsg(&msg);
		myDispatchMsg(&msg);
	}
}
void tlsCall()
{
	HANDLE hExe = myGetModuleHandle(0);
	PIMAGE_OPTIONAL_HEADER pOptionHeader = getOptionHeader((char*)hExe);
	DWORD tlsRva = pOptionHeader->DataDirectory[9].VirtualAddress;
	if (!tlsRva)return;
	PIMAGE_TLS_DIRECTORY pTlsTabVa = PIMAGE_TLS_DIRECTORY(tlsRva + DWORD(hExe));
	DWORD tlsArryPointerVa = pTlsTabVa->AddressOfCallBacks;

	while (*(DWORD*)tlsArryPointerVa)
	{
		DWORD addr = *(DWORD*)tlsArryPointerVa;
		_asm
		{
			push 0;
			push 1;
			push 0;
			call addr;
		}
		tlsArryPointerVa += 4;
	}
}

bool isDebug_1()//判断BEINGDBG字段
{
	_asm {
		mov eax, fs:[0x30];
		mov al, byte ptr[eax + 2];
		cmp al, 0;
		je NO_DBG_;
		jmp DBG_;
	}
NO_DBG_:
	return false;
DBG_:
	return true;
}
bool isDebug_2()
{
	bool isDbg = false;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = getOptionHeader((char*)randomImageBase);
	DWORD ep = pOptionHeader->AddressOfEntryPoint;
	BYTE* epVa = (BYTE*)(ep + randomImageBase);
	//检查EP附近有没有int 3断点
	for (int i = 0; i < 10; i++)
	{
		if (*epVa == 0xCC)
		{
			isDbg = true;
			break;
		}
	}
	return isDbg;
}
//void isDebug_3()
//{
//	PROCESSENTRY32W pe{ sizeof(PROCESSENTRY32W) };
//	HANDLE hSnap = myCreateToolhelp(TH32CS_SNAPPROCESS, 0);
//	if (!hSnap)return;
//	BOOL bSuccess = myProcessFirst(hSnap, &pe);
//	DWORD pid = -1;
//	if (!bSuccess)return;
//	do {
//		if (wcscmp(pe.szExeFile, L"保护父进程不被调试.exe") == 0)
//		{
//			pid = pe.th32ProcessID;
//			break;
//		}
//	} while (myProcessNext(hSnap, &pe));
//	myCloseHandle(hSnap);
//	if (-1 == pid) {
//		CreateProcessA("check.exe")
//	}
//}
LONG fileterProc(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	switch (ExceptionInfo->ExceptionRecord->ExceptionCode)
	{
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
		myMessageBoxA(0, "Ueh is Called,Error code:  DIVIDE_BY_ZERO", "UEH:",0);
		ExceptionInfo->ContextRecord->Eip += 2;
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}
void NTAPI TlsCallBackFunction1(PVOID Handle, DWORD Reason, PVOID Reserve)
{
	if (Reason == DLL_PROCESS_ATTACH)
	{
		acquireFuncAddr();
		randomImageBase = (DWORD)myGetModuleHandle(0);
		if (isDebug_1() || isDebug_2())
		{
			myMessageBoxA(0, "shellcode TLS:Is Debugging,WTF!","TLS",0);
			myExitProcess(0);
		}
		myMessageBoxA(0, "shellcode TLS:NOT DBG!", "TLS", 0);
		mySetUeh((LPTOP_LEVEL_EXCEPTION_FILTER)fileterProc);
		_asm
		{
			push ebx;
			xor ebx, ebx;
			div ebx;
			pop ebx;
		}
	}
}