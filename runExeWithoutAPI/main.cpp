#include <stdio.h>
#include <windows.h>
struct TypeOffset
{
	WORD offset : 12;
	WORD type : 4;
};
bool fileBufferToImageBuffer(char*& fileBuffer, char*& imageBuffer)
{
	PIMAGE_NT_HEADERS pNt = PIMAGE_NT_HEADERS(fileBuffer + ((PIMAGE_DOS_HEADER)fileBuffer)->e_lfanew);
	if (pNt->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("invalid PE format!\n");
		return false;
	}
	DWORD imageSize = pNt->OptionalHeader.SizeOfImage;
	imageBuffer = new char[imageSize] {};

	memcpy(imageBuffer, fileBuffer, pNt->OptionalHeader.SizeOfHeaders);
	//区段头表地址
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

	for (DWORD i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		memcpy(imageBuffer + pSection[i].VirtualAddress, fileBuffer + pSection[i].PointerToRawData, pSection[i].SizeOfRawData);
	}
	return true;
}


int main()
{
	//1.申请一块空间模拟文件被加载到内存后的样子
	printf("Path name>>");
	char fullPathName[MAX_PATH]{};
	gets_s(fullPathName, MAX_PATH);
	HANDLE hFile = CreateFileA(fullPathName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("file not exists!\n");
		return 0;
	}
	DWORD fileSize = GetFileSize(hFile, 0);
	char* szBuff = new char[fileSize] {};
	DWORD dwRead = 0;
	if (!ReadFile(hFile, szBuff, fileSize, &dwRead, 0))
	{
		printf("fail to read file!\n");
		return 0;
	}
	CloseHandle(hFile);
	char* imageBuffer = NULL;
	if (!fileBufferToImageBuffer(szBuff, imageBuffer))
	{
		printf("fail to convert!\n");
		return 0;
	}
	printf("succeed to convert!\n");
	//2.修复重定位数据
	PIMAGE_NT_HEADERS pNt = PIMAGE_NT_HEADERS(imageBuffer + ((PIMAGE_DOS_HEADER)imageBuffer)->e_lfanew);
	DWORD pRelocTabRva = pNt->OptionalHeader.DataDirectory[5].VirtualAddress;
	if (!pRelocTabRva)
	{
		printf("no data needs reloc!\n");
	}
	else
	{
		//重定位表VA
		PIMAGE_BASE_RELOCATION pRelocTabVa = PIMAGE_BASE_RELOCATION(imageBuffer + pRelocTabRva);

		while (pRelocTabVa->SizeOfBlock)
		{
			//每个块中需要重定位数据的个数
			DWORD nNum = (pRelocTabVa->SizeOfBlock - 8) / 2;
			TypeOffset* typeOffset = (TypeOffset*)((DWORD)pRelocTabVa + 8);
			for (DWORD i = 0; i < nNum; i++)
			{
				if (typeOffset[i].type == 3)
				{
					DWORD* dwNeedRelocAddr = (DWORD*)(imageBuffer + pRelocTabVa->VirtualAddress + typeOffset[i].offset);
					*dwNeedRelocAddr = *dwNeedRelocAddr - pNt->OptionalHeader.ImageBase + (DWORD)imageBuffer;
				}
			}
			//下一个重定位表块
			pRelocTabVa = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocTabVa + pRelocTabVa->SizeOfBlock);
		}
	}
	pNt->OptionalHeader.ImageBase = (DWORD)imageBuffer;
	//3.填充IAT表:
	//3.1---------------------------
	//找到导入表地址
	DWORD impTabRva = pNt->OptionalHeader.DataDirectory[1].VirtualAddress;
	PIMAGE_IMPORT_DESCRIPTOR pImpTabVa = PIMAGE_IMPORT_DESCRIPTOR(imageBuffer + impTabRva);
	//3.2---------------------------
	//得到INT地址
	//3.3---------------------------
	//遍历INT表获取函数名或者序号
	//3.4---------------------------
	//根据函数名或者序号得到真正的函数地址,并填充IAT
	while (pImpTabVa->Name)
	{
		char* dllName = (char*)(imageBuffer + pImpTabVa->Name);
		printf("dllName:%s\n", dllName);
		PIMAGE_THUNK_DATA pIntArry = PIMAGE_THUNK_DATA(pImpTabVa->OriginalFirstThunk + imageBuffer);
		PIMAGE_THUNK_DATA pIatArry = PIMAGE_THUNK_DATA(pImpTabVa->FirstThunk + imageBuffer);
		DWORD funcAddr = 0;
		while (pIntArry->u1.Function)
		{

			if (pIntArry->u1.Ordinal & 0x80000000)//序号导入
			{
				printf("\t序号导入:%d\n", pIntArry->u1.Ordinal & 0xfffffff);
				funcAddr = (DWORD)GetProcAddress(LoadLibraryA(dllName), LPSTR(pIntArry->u1.Ordinal & 0xfffffff));
			}
			else                              //名称导入
			{
				PIMAGE_IMPORT_BY_NAME pImp_by_name_ = PIMAGE_IMPORT_BY_NAME(pIntArry->u1.Function + imageBuffer);
				printf("\t%s\n", pImp_by_name_->Name);
				funcAddr = (DWORD)GetProcAddress(LoadLibraryA(dllName), pImp_by_name_->Name);
			}
			pIatArry->u1.AddressOfData = funcAddr;
			pIntArry++;
			pIatArry++;
		}
		pImpTabVa++;
	}

	//4.开一个线程EIP指向模拟OEP
	HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)(pNt->OptionalHeader.AddressOfEntryPoint + imageBuffer), 0, 0, 0);
	if (!hThread)
	{
		printf("fail to createThread!\n");
		return 0;
	}

	WaitForSingleObject(hThread, -1);
	CloseHandle(hThread);
	return 0;
}