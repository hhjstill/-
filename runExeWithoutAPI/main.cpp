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
	//����ͷ���ַ
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

	for (DWORD i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		memcpy(imageBuffer + pSection[i].VirtualAddress, fileBuffer + pSection[i].PointerToRawData, pSection[i].SizeOfRawData);
	}
	return true;
}


int main()
{
	//1.����һ��ռ�ģ���ļ������ص��ڴ�������
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
	//2.�޸��ض�λ����
	PIMAGE_NT_HEADERS pNt = PIMAGE_NT_HEADERS(imageBuffer + ((PIMAGE_DOS_HEADER)imageBuffer)->e_lfanew);
	DWORD pRelocTabRva = pNt->OptionalHeader.DataDirectory[5].VirtualAddress;
	if (!pRelocTabRva)
	{
		printf("no data needs reloc!\n");
	}
	else
	{
		//�ض�λ��VA
		PIMAGE_BASE_RELOCATION pRelocTabVa = PIMAGE_BASE_RELOCATION(imageBuffer + pRelocTabRva);

		while (pRelocTabVa->SizeOfBlock)
		{
			//ÿ��������Ҫ�ض�λ���ݵĸ���
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
			//��һ���ض�λ���
			pRelocTabVa = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocTabVa + pRelocTabVa->SizeOfBlock);
		}
	}
	pNt->OptionalHeader.ImageBase = (DWORD)imageBuffer;
	//3.���IAT��:
	//3.1---------------------------
	//�ҵ�������ַ
	DWORD impTabRva = pNt->OptionalHeader.DataDirectory[1].VirtualAddress;
	PIMAGE_IMPORT_DESCRIPTOR pImpTabVa = PIMAGE_IMPORT_DESCRIPTOR(imageBuffer + impTabRva);
	//3.2---------------------------
	//�õ�INT��ַ
	//3.3---------------------------
	//����INT���ȡ�������������
	//3.4---------------------------
	//���ݺ�����������ŵõ������ĺ�����ַ,�����IAT
	while (pImpTabVa->Name)
	{
		char* dllName = (char*)(imageBuffer + pImpTabVa->Name);
		printf("dllName:%s\n", dllName);
		PIMAGE_THUNK_DATA pIntArry = PIMAGE_THUNK_DATA(pImpTabVa->OriginalFirstThunk + imageBuffer);
		PIMAGE_THUNK_DATA pIatArry = PIMAGE_THUNK_DATA(pImpTabVa->FirstThunk + imageBuffer);
		DWORD funcAddr = 0;
		while (pIntArry->u1.Function)
		{

			if (pIntArry->u1.Ordinal & 0x80000000)//��ŵ���
			{
				printf("\t��ŵ���:%d\n", pIntArry->u1.Ordinal & 0xfffffff);
				funcAddr = (DWORD)GetProcAddress(LoadLibraryA(dllName), LPSTR(pIntArry->u1.Ordinal & 0xfffffff));
			}
			else                              //���Ƶ���
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

	//4.��һ���߳�EIPָ��ģ��OEP
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