#include <stdio.h>
#include <windows.h>

DWORD fileBufferSize = 0;
DWORD test = 0;

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
bool imageBufferTofileBuffer(char*& imageBuffer, char*& fileBuffer)
{
	PIMAGE_NT_HEADERS pNt = PIMAGE_NT_HEADERS(imageBuffer + ((PIMAGE_DOS_HEADER)imageBuffer)->e_lfanew);
	if (pNt->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("invalid PE format!\n");
		return false;
	}
	fileBuffer = new char[pNt->OptionalHeader.SizeOfImage]{};
	memcpy(fileBuffer, imageBuffer, pNt->OptionalHeader.SizeOfHeaders);
	fileBufferSize += pNt->OptionalHeader.SizeOfHeaders;
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	for (DWORD i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		memcpy(fileBuffer + pSection[i].PointerToRawData, imageBuffer + pSection[i].VirtualAddress, pSection[i].SizeOfRawData);
		fileBufferSize += pSection[i].SizeOfRawData;
	}
	return true;
}

int main()
{
	printf("Input file path>>");
	char fullPathName[MAX_PATH]{};
	gets_s(fullPathName, MAX_PATH);
	HANDLE hFile = CreateFileA(fullPathName, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
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
	//找到重定位表
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
					*dwNeedRelocAddr = *dwNeedRelocAddr - pNt->OptionalHeader.ImageBase + 0x800000;
					test++;
				}
			}
			//下一个重定位表块
			pRelocTabVa = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocTabVa + pRelocTabVa->SizeOfBlock);
		}
	}
	pNt->OptionalHeader.ImageBase = 0x800000;
	char* szFileBuffer = NULL;
	imageBufferTofileBuffer(imageBuffer, szFileBuffer);
	memcpy(szBuff, szFileBuffer, fileBufferSize);
	hFile = CreateFileA("1.exe", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("file not exists!\n");
		return 0;
	}
	DWORD dwWrite = 0;
	WriteFile(hFile, szBuff, fileBufferSize, &dwWrite, 0);
	CloseHandle(hFile);
	printf("test = %d\n", test);
	return 0;
}