#include <stdio.h>
#include <windows.h>

int main()
{
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

	char* szBuff = new char[fileSize + 0x1000] {};
	DWORD dwRead = 0;
	if (!ReadFile(hFile, szBuff, fileSize, &dwRead, 0))
	{
		printf("fail to read file!\n");
		return 0;
	}
	CloseHandle(hFile);
	PIMAGE_NT_HEADERS pNt = PIMAGE_NT_HEADERS(szBuff + ((PIMAGE_DOS_HEADER)szBuff)->e_lfanew);
	pNt->FileHeader.NumberOfSections++;
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_SECTION_HEADER pNewSection = pSection + pNt->FileHeader.NumberOfSections - 1;
	memcpy(pNewSection->Name, ".new", 4);
	DWORD differenceVal = pNt->OptionalHeader.FileAlignment - fileSize % pNt->OptionalHeader.FileAlignment;
	//char* newBuffer = new char[fileSize + differenceVal + 0x200]{};
	//memcpy(newBuffer, szBuff, fileSize);

	pNewSection->PointerToRawData = fileSize + differenceVal;
	pNewSection->SizeOfRawData = 0x200;
	pNewSection->VirtualAddress = (pNewSection - 1)->VirtualAddress + (pNewSection - 1)->SizeOfRawData;
	pNewSection->VirtualAddress += (pNt->OptionalHeader.SectionAlignment - pNewSection->VirtualAddress % pNt->OptionalHeader.SectionAlignment);
	pNewSection->Characteristics = 0xe00000e;
	pNt->OptionalHeader.SizeOfImage += 0x200;

	hFile = CreateFileA("addSection.exe", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0);
	DWORD dwWrite = 0;
	WriteFile(hFile, szBuff, fileSize + differenceVal + 0x200, &dwWrite, 0);
	CloseHandle(hFile);
	return 0;
}