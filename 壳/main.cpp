#include <windows.h>
#include <stdio.h>
#include <time.h>

#include "aplib.h"
#pragma comment(lib,"aPlib.lib")

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

DWORD rvaToFoa(IMAGE_NT_HEADERS* pNt, DWORD rva)
{
	IMAGE_SECTION_HEADER* pScn = (IMAGE_SECTION_HEADER*)IMAGE_FIRST_SECTION(pNt);
	DWORD dwScnCnt = pNt->FileHeader.NumberOfSections;
	for (DWORD i = 0; i < dwScnCnt; i++)
	{
		if (rva >= pScn[i].VirtualAddress && rva <= pScn[i].VirtualAddress + pScn[i].SizeOfRawData)
		{
			return rva - pScn[i].VirtualAddress + pScn[i].PointerToRawData;
		}
	}
	printf("������Χ�������ַ\n");
	return 0;
}
//��ȡFILEBUFFER
DWORD getFileBuffer(char*& fileBuffer)
{
	printf("Input file path>>");
	char fullPathName[MAX_PATH] = {};
	gets_s(fullPathName, MAX_PATH);
	//HANDLE hFile = CreateFileA("C:\\Users\\hhj-win10\\Desktop\\2.exe", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
	HANDLE hFile = CreateFileA(fullPathName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("file not exists!\n");
		CloseHandle(hFile);
		return 0;
	}
	DWORD fileSize = GetFileSize(hFile, 0);
	fileBuffer = new char[fileSize] {};
	DWORD dwRead = 0;
	if (!ReadFile(hFile, fileBuffer, fileSize, &dwRead, 0))
	{
		printf("fail to read file!\n");
		CloseHandle(hFile);
		return 0;
	}
	CloseHandle(hFile);
	return fileSize;
}
//��ȡDOSͷ
IMAGE_DOS_HEADER* getDosHeader(_In_  char* pBaseAddr) {
	return (IMAGE_DOS_HEADER *)pBaseAddr;
}

// ��ȡNTͷ
IMAGE_NT_HEADERS* getNtHeader(_In_  char* pBaseAddr) {
	return (IMAGE_NT_HEADERS*)(getDosHeader(pBaseAddr)->e_lfanew + (SIZE_T)pBaseAddr);
}

//��ȡ�ļ�ͷ
IMAGE_FILE_HEADER* getFileHeader(_In_  char* pBaseAddr) {
	return &getNtHeader(pBaseAddr)->FileHeader;
}

//��ȡ��չͷ
IMAGE_OPTIONAL_HEADER* getOptionHeader(_In_  char* pBaseAddr) {
	return &getNtHeader(pBaseAddr)->OptionalHeader;
}

// ��ȡָ�����ֵ�����ͷ
IMAGE_SECTION_HEADER* getSectionByName(_In_ char* pBaseAddr,
	_In_  const char* scnName)//��ȡָ�����ֵ�����
{
	// ��ȡ���θ�ʽ
	DWORD dwScnCount = getFileHeader(pBaseAddr)->NumberOfSections;
	// ��ȡ��һ������
	IMAGE_SECTION_HEADER* pScn = IMAGE_FIRST_SECTION(getNtHeader(pBaseAddr));
	char buff[10] = { 0 };
	// ��������
	for (DWORD i = 0; i < dwScnCount; ++i) {
		memcpy_s(buff, 8, (char*)pScn[i].Name, 8);
		// �ж��Ƿ�����ͬ������
		if (strcmp(buff, scnName) == 0)
			return pScn + i;
	}
	return nullptr;
}
// ��ȡ���һ������ͷ
IMAGE_SECTION_HEADER* getLastSection(_In_ char* pFileData)// ��ȡ���һ������
{
	// ��ȡ���θ���
	DWORD dwScnCount = getFileHeader(pFileData)->NumberOfSections;
	// ��ȡ��һ������
	IMAGE_SECTION_HEADER* pScn = IMAGE_FIRST_SECTION(getNtHeader(pFileData));
	// �õ����һ����Ч������
	return pScn + (dwScnCount - 1);
}
// ��������С

int fileBufferToImageBuffer(char*& fileBuffer, char*& imageBuffer)
{
	PIMAGE_NT_HEADERS pNt = PIMAGE_NT_HEADERS(fileBuffer + ((PIMAGE_DOS_HEADER)fileBuffer)->e_lfanew);
	if (pNt->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("invalid PE format!\n");
		return 0;
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
	return pNt->OptionalHeader.SizeOfImage;
}
int imageBufferTofileBuffer(char*& imageBuffer, char*& fileBuffer)
{
	DWORD fileBufferSize = 0;
	PIMAGE_NT_HEADERS pNt = getNtHeader(imageBuffer);
	if (pNt->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("invalid PE format!\n");
		return 0;
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
	return fileBufferSize;
}

int aligment(_In_ int size, _In_  int aliginment) {
	return (size) % (aliginment) == 0 ? (size) : ((size) / (aliginment)+1)* (aliginment);
}
DWORD acquireNewRelocTab(DWORD dllBase, char*& newTab, DWORD newVirtualAddr)
{
	PIMAGE_OPTIONAL_HEADER pOptionheader = getOptionHeader((char*)dllBase);
	PIMAGE_BASE_RELOCATION pRelocTabVA = (PIMAGE_BASE_RELOCATION)(pOptionheader->DataDirectory[5].VirtualAddress + dllBase);//DLL���ض�λ��VA
	PIMAGE_SECTION_HEADER pTextSectionHeader = (PIMAGE_SECTION_HEADER)getSectionByName((char*)dllBase, ".text");//DLL����ε�����ͷ
	PIMAGE_SECTION_HEADER pNextSectinHeader = pTextSectionHeader + 1;//DLL�������һ���ε�����ͷ
	DWORD virtualStart = pTextSectionHeader->VirtualAddress;//������Ҫ�������ʼ����ֹλ��
	DWORD virtualEnd = pNextSectinHeader->VirtualAddress;
	DWORD offset = 0;
	//��newTab������һƬ�ռ�
	newTab = new char[pOptionheader->DataDirectory[5].Size]{};
	while (pRelocTabVA->SizeOfBlock)
	{
		DWORD old = 0;
		//ֻ����text��
		if (pRelocTabVA->VirtualAddress >= virtualStart && pRelocTabVA->VirtualAddress < virtualEnd)
		{
			VirtualProtect((LPVOID)pRelocTabVA, 1, PAGE_EXECUTE_READWRITE, &old);
			pRelocTabVA->VirtualAddress = pRelocTabVA->VirtualAddress - virtualStart + newVirtualAddr;
			VirtualProtect((LPVOID)pRelocTabVA, 1, old, &old);
			memcpy(newTab + offset, pRelocTabVA, pRelocTabVA->SizeOfBlock);
			offset += pRelocTabVA->SizeOfBlock;
		}
		pRelocTabVA = PIMAGE_BASE_RELOCATION((DWORD)pRelocTabVA + pRelocTabVA->SizeOfBlock);
	}
	return offset + 8;//�ض�λ����ȫ0Ԫ�ؽ�β,
}
void fixRelocInfo(DWORD imageBase, DWORD newImageBase, DWORD newVirtualAddr)
{
	PIMAGE_NT_HEADERS pNt = getNtHeader((char*)imageBase);//dll��NTͷ
	PIMAGE_SECTION_HEADER pTextHeader = getSectionByName((char*)imageBase, ".text");//dll��text��ͷ��
	PIMAGE_SECTION_HEADER pNextHeader = pTextHeader + 1;
	DWORD nextVirAddr = pNextHeader->VirtualAddress;
	DWORD pRelocTabRva = pNt->OptionalHeader.DataDirectory[5].VirtualAddress;
	PIMAGE_OPTIONAL_HEADER pOption = getOptionHeader((char*)newImageBase);
	if (!pRelocTabRva)
	{
		printf("no data needs reloc!\n");
	}
	else
	{
		//�ض�λ��VA
		PIMAGE_BASE_RELOCATION pRelocTabVa = PIMAGE_BASE_RELOCATION(imageBase + pRelocTabRva);

		while (pRelocTabVa->SizeOfBlock)
		{
			//if (pRelocTabVa->VirtualAddress >= nextVirAddr)break;//ֻ�޸�����ε��ض�λ
			//ÿ��������Ҫ�ض�λ���ݵĸ���
			DWORD nNum = (pRelocTabVa->SizeOfBlock - 8) / 2;
			TypeOffset* typeOffset = (TypeOffset*)((DWORD)pRelocTabVa + 8);
			DWORD oldPro = 0;
			
			for (DWORD i = 0; i < nNum; i++)
			{
				if (typeOffset[i].type == 3)
				{
					DWORD* dwNeedRelocAddr = (DWORD*)(imageBase + pRelocTabVa->VirtualAddress + typeOffset[i].offset);
					VirtualProtect((LPVOID)dwNeedRelocAddr, 1, PAGE_EXECUTE_READWRITE, &oldPro);
					//�޸�
					*dwNeedRelocAddr = *dwNeedRelocAddr - imageBase - pTextHeader->VirtualAddress + newVirtualAddr + pOption->ImageBase;
					VirtualProtect((LPVOID)dwNeedRelocAddr, 1, oldPro, &oldPro);
				}
			}
			
			//��һ���ض�λ���
			pRelocTabVa = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocTabVa + pRelocTabVa->SizeOfBlock);
		}
	}
}

void saveToFile(char* fileBuffer, DWORD dwSize)
{
	HANDLE hFile = CreateFileA("new.exe", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("file not exists!\n");
		return;
	}
	DWORD dwWrite = 0;
	WriteFile(hFile, fileBuffer, dwSize, &dwWrite, 0);
	CloseHandle(hFile);
}
bool addNewSection(DWORD dllBase, DWORD fileBuffer, DWORD& fileBufferSize, char*& newFileBuffer)
{
	//1.��imageBuffer��������һƬ�ռ�,����������α�ı�ͷ��Ϣ
	PIMAGE_SECTION_HEADER pDllTextSecHeader = getSectionByName((char*)dllBase, ".text");
	//�´�С = ԭ�ļ����ļ������Ĵ�С + dllText�ε��ļ������С + dll�ض�λ���ļ������С
	DWORD newSize = aligment(fileBufferSize, getOptionHeader((char*)fileBuffer)->FileAlignment)
		+ pDllTextSecHeader->SizeOfRawData + 
		aligment(getOptionHeader((char*)dllBase)->DataDirectory[5].Size, getOptionHeader((char*)fileBuffer)->FileAlignment);
	newFileBuffer = new char[newSize] {};
	memcpy(newFileBuffer, (char*)fileBuffer, fileBufferSize);
	delete[] (char*)fileBuffer;
	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(newFileBuffer);
	pFileHeader->NumberOfSections++;//��������+1
	PIMAGE_SECTION_HEADER pLastSecHeader = getLastSection(newFileBuffer);//buffer�����һ������ͷ��
	PIMAGE_OPTIONAL_HEADER pOptionHeader = getOptionHeader(newFileBuffer);//buffer��option head
	DWORD calcPointerToRawData = aligment(fileBufferSize, pOptionHeader->FileAlignment);//����������PointerToRawData
	PIMAGE_SECTION_HEADER pPreSec = pLastSecHeader - 1;//�����ڶ�������ͷ��
	DWORD calcVirtualAddr = pPreSec->VirtualAddress + aligment(pPreSec->SizeOfRawData, pOptionHeader->SectionAlignment);//����������VirtualAddr
	pLastSecHeader->Characteristics = 0xe00000e0;//�������Կɶ���д��ִ��
	pLastSecHeader->Misc.VirtualSize = pDllTextSecHeader->Misc.VirtualSize;//δ�����С
	memcpy(pLastSecHeader->Name, ".15PB", 5);//������
	pLastSecHeader->SizeOfRawData = pDllTextSecHeader->SizeOfRawData;//�ļ������С
	pLastSecHeader->PointerToRawData = calcPointerToRawData;//pointerToRawData
	pLastSecHeader->VirtualAddress = calcVirtualAddr;//VirtualAddr
	//pOptionHeader->SizeOfImage = pDllTextSecHeader->SizeOfRawData + aligment(pOptionHeader->SizeOfImage,pOptionHeader->SectionAlignment);//�޸�sizeofImage
	//pOptionHeader->SizeOfImage += aligment(pDllTextSecHeader->SizeOfRawData, pOptionHeader->SectionAlignment);//�޸�sizeofImage
    //2.��Ŀ�����ı�Ҫ��Ϣ���浽�Ǵ���dll������ȫ�ֱ�����
	STUB_CONFIG_* stubCfg = (STUB_CONFIG_*)GetProcAddress((HMODULE)dllBase, "cfg");
	stubCfg->oep = pOptionHeader->AddressOfEntryPoint;
	//3.����dll���ض�λ���޸�text����Ϣ
	fixRelocInfo(dllBase, (DWORD)newFileBuffer, calcVirtualAddr);
	//4.��text�θ��Ƶ�newBuffer�����һ��������
	memcpy(newFileBuffer + pLastSecHeader->PointerToRawData, (char*)dllBase + pDllTextSecHeader->VirtualAddress, pDllTextSecHeader->SizeOfRawData);
	//------------------------------------------------------------------------------------------------------
	//�����ǽ�DLL���ֵ��ض�λ���������ӿǳ���
	//1.�޸�dll���ض�λ������,�õ�һ���µ��ض�λ��
	char* newRelocTab = NULL;
	DWORD newTabSize = acquireNewRelocTab(dllBase, newRelocTab, calcVirtualAddr);
	DWORD aligTabSize = aligment(newTabSize, pOptionHeader->FileAlignment);
	//2.Ȼ���Ƶ���buffer����
	memcpy(newFileBuffer + calcPointerToRawData + pDllTextSecHeader->SizeOfRawData, newRelocTab, newTabSize);
	//3.����Ŀ¼����ض�λָ��ָ������ض�λ��
	pOptionHeader->DataDirectory[5].VirtualAddress = calcVirtualAddr + pDllTextSecHeader->SizeOfRawData;
	pOptionHeader->DataDirectory[5].Size = newTabSize;
	//pOptionHeader->SizeOfImage += aligTabSize;//�޸�sizeofImage
	pLastSecHeader->SizeOfRawData += aligTabSize;//���ض�λ���������һ������
	pLastSecHeader->Misc.VirtualSize += newTabSize;
	//------------------------------------------------------------------------------------------------------
	//��DLL��TLS���������ӿǳ�����
	//------------------------------------------------------------------------------------------------------
	//1.��ȡDLL��TLS��RVA
	DWORD dllTlsRva = getOptionHeader((char*)dllBase)->DataDirectory[9].VirtualAddress;
	DWORD dllTlsSize = getOptionHeader((char*)dllBase)->DataDirectory[9].Size;
	//2.�������RVA��Ŀ������е�RVA
	DWORD targetRva = dllTlsRva - pDllTextSecHeader->VirtualAddress + pLastSecHeader->VirtualAddress;
	//3.��Ŀ���������Ŀ¼���TLSָ��ָ������
	pOptionHeader->DataDirectory[9].VirtualAddress = targetRva;
	pOptionHeader->DataDirectory[9].Size = dllTlsSize;
	//------------------------------------------------------------------------------------------------------
	//5.�޸�ԭʼOEPΪ�Ǵ����EP
	DWORD expEp = (DWORD)GetProcAddress((HMODULE)dllBase, "entry");
	expEp = expEp - dllBase - pDllTextSecHeader->VirtualAddress + pLastSecHeader->VirtualAddress;
	pOptionHeader->AddressOfEntryPoint = expEp;
	fileBufferSize = calcPointerToRawData + pDllTextSecHeader->SizeOfRawData + aligTabSize;
	pOptionHeader->SizeOfImage = pLastSecHeader->VirtualAddress + 
		aligment(pLastSecHeader->SizeOfRawData, pOptionHeader->SectionAlignment);//�޸�sizeofImage
	return true;
}
bool encrypt(HANDLE dllBase, char* fileBuffer)
{
	//1.��ȡDLL������Ϣ�ṹ��
	STUB_CONFIG_* stubConfig = (STUB_CONFIG_*)GetProcAddress((HMODULE)dllBase, "cfg");
	if (!stubConfig)
	{
		printf("fail to getProcAddr!\n");
		return false;
	}
	srand((unsigned)time(0));
	int key = rand() % 15 + 1;
	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(fileBuffer);//�ļ�ͷ
	PIMAGE_NT_HEADERS pNt = getNtHeader(fileBuffer);//NTͷ
	PIMAGE_SECTION_HEADER pSecHeader = IMAGE_FIRST_SECTION(pNt);//���α�ͷ
	PIMAGE_OPTIONAL_HEADER pOptinHeader = getOptionHeader(fileBuffer);//��ѡPEͷ

	//2.���ṹ����Ϣ
	//----------���ṹ����Ϣ-------------
	stubConfig->key = key;
	stubConfig->oep = pOptinHeader->AddressOfEntryPoint;
	stubConfig->peImageBase = pOptinHeader->ImageBase;
	stubConfig->iatRva = pOptinHeader->DataDirectory[1].VirtualAddress;
	stubConfig->iatSize = pOptinHeader->DataDirectory[1].Size;
	stubConfig->dataDirector_ImpTab = (DWORD)pOptinHeader - (DWORD)fileBuffer + 0x68;
	stubConfig->dataDirector_RVA = (DWORD)pOptinHeader->DataDirectory - (DWORD)fileBuffer;
	stubConfig->numOfEncrySection = pFileHeader->NumberOfSections;//��Դ������
	
	for (DWORD i = 0; i < pFileHeader->NumberOfSections; i++, pSecHeader++)
	{
		if (strcmp((char*)pSecHeader->Name, ".rsrc") == 0)//��Դ������
			continue;
		stubConfig->dataStartAndOverArry[i].startAddr = pSecHeader->VirtualAddress;
		stubConfig->dataStartAndOverArry[i].size = pSecHeader->SizeOfRawData;
	}
	PIMAGE_IMPORT_DESCRIPTOR pImpTab = PIMAGE_IMPORT_DESCRIPTOR(fileBuffer + rvaToFoa(pNt,pOptinHeader->DataDirectory[1].VirtualAddress));
	DWORD numOfLoadDll = 0;
	while (pImpTab->Name)
	{
		DWORD nameAddr = pImpTab->Name;
		DWORD* pIat = (DWORD*)pImpTab->FirstThunk;
		DWORD* pInt = (DWORD*)pImpTab->OriginalFirstThunk;
		stubConfig->impStartAndOverArry[numOfLoadDll].dllNameAddr = nameAddr;
		stubConfig->impStartAndOverArry[numOfLoadDll].iatAddr = (DWORD)pIat;
		stubConfig->impStartAndOverArry[numOfLoadDll].intAddr = (DWORD)pInt;
		DWORD numOfFunction = 0;
		pIat = (DWORD*)(fileBuffer + rvaToFoa(pNt, (DWORD)pIat));
		pInt = (DWORD*)(fileBuffer + rvaToFoa(pNt, (DWORD)pInt));
		for (; pInt[numOfFunction] != 0; numOfFunction++)
		{
			;
		}
		stubConfig->impStartAndOverArry[numOfLoadDll].numOfName = numOfFunction;
		numOfLoadDll++;
		pImpTab++;
	}
	stubConfig->numOfImportDll = numOfLoadDll;
	//----------���ṹ����Ϣ-------------
	//3.��������,xorһ��1~15�������
	pSecHeader = IMAGE_FIRST_SECTION(pNt);//����pSectionheader
	for (DWORD i = 0; i < pFileHeader->NumberOfSections; i++, pSecHeader++)//������������
	{
		//--------------------------------
		if (strcmp((char*)pSecHeader->Name, ".rsrc") == 0)//��Դ������
			continue;
		//--------------------------------
		for (DWORD j = 0; j < pSecHeader->SizeOfRawData; j++)
		{
			*(BYTE*)(pSecHeader->PointerToRawData + fileBuffer + j) ^= key;
			stubConfig->dataStartAndOverArry[i].isEncrypt = true;
		}
	}
	//�������Ŀ¼�������
	for (int i = 0; i < 16; i++)
	{
		stubConfig->dataDirectorInfoArry[i].virtualAddr = pOptinHeader->DataDirectory[i].VirtualAddress;
		stubConfig->dataDirectorInfoArry[i].size = pOptinHeader->DataDirectory[i].Size;
		pOptinHeader->DataDirectory[i] = {};
	}
	return true;
}
DWORD packSection(DWORD dllBase, char* fileBuffer, char*& newFileBuffer, DWORD fileSize)
{
	PIMAGE_NT_HEADERS pNt = getNtHeader(fileBuffer);
	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(fileBuffer);
	PIMAGE_OPTIONAL_HEADER pOptionHeader = getOptionHeader(fileBuffer);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNt);
	PACK_INFO_* pPackInfo = (PACK_INFO_*)GetProcAddress((HMODULE)dllBase, "pi");
	//��ȡ��Ҫѹ��������,�����Ǵ���α���,��ԭ�������һ������(����������Ϣ)
	WORD needHandleSection = pFileHeader->NumberOfSections;
	pPackInfo->numOfSection = needHandleSection;
	//����һ��newBuffer
	newFileBuffer = new char[fileSize] {};
	DWORD nTotalSize = pOptionHeader->SizeOfHeaders;
	//ѹ������
	for (WORD i = 0; i < needHandleSection; i++)
	{
		//1.������ļ������СΪ0,������.rsrc����,��ѹ��,�����俽������buffer����,�޸���pointerToRawData
		if (pSectionHeader->SizeOfRawData == 0)
		{
			pSectionHeader++;
			continue;
		}
		if (strcmp((char*)pSectionHeader->Name, ".rsrc") == 0)
		{
			memcpy(newFileBuffer + nTotalSize, fileBuffer + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData);
			pSectionHeader->PointerToRawData = nTotalSize;
			nTotalSize += pSectionHeader->SizeOfRawData;
			pSectionHeader++;
			continue;
		}
		//2.����������ѹ��
		//-----------------------------------------------
		int length = pSectionHeader->SizeOfRawData;//��ѹ�����ݵĴ�С
		
		/* allocate workmem and destination memory */
		char *workmem = new char[aP_workmem_size(length)]{};
		char *compressed = new char[aP_max_packed_size(length)]{};
		
		/* compress data[] to compressed[] */
		size_t outlength = aPsafe_pack(fileBuffer + pSectionHeader->PointerToRawData, compressed, length, workmem, NULL, NULL);//ѹ�����ʵ�ʴ�С
		//------------------------------------------------

		DWORD calAigment = aligment(outlength, pOptionHeader->FileAlignment);//����ѹ������ļ������С
		memcpy(newFileBuffer + nTotalSize, compressed, calAigment);

		//3.�޸ĸ�����pointerToData��sizeofRawData
		pSectionHeader->PointerToRawData = nTotalSize;
		pPackInfo->packSectionInfo[i].sizeOfRawData = pSectionHeader->SizeOfRawData;
		pSectionHeader->SizeOfRawData = calAigment;
		nTotalSize += calAigment;
		//4.�����Ϣ�ṹ��
		pPackInfo->packSectionInfo[i].isPacked = true;
		pPackInfo->packSectionInfo[i].originSize = length;
		pPackInfo->packSectionInfo[i].size = outlength;
		pPackInfo->packSectionInfo[i].startAddrRva = pSectionHeader->VirtualAddress;

		delete[] workmem;
		delete[] compressed;
		pSectionHeader++;
	}
	//5.����ͷ
	memcpy(newFileBuffer, fileBuffer, pOptionHeader->SizeOfHeaders);
	return nTotalSize;
}
int main()
{
	//1.��ȡĿ���ļ���fileBuffer
	char* fileBuffer = NULL;
	DWORD fileSize = 0;
	if (!(fileSize = getFileBuffer(fileBuffer)))return 0;//�ȵõ�fileBuffer
	//2.���ؿǴ���dll
	HANDLE dllBase = LoadLibraryExA("packDll.dll", 0, DONT_RESOLVE_DLL_REFERENCES);
	if (!dllBase)
	{
		printf("fail to load dllInfo!\n");
		return false;
	}
	//3.�����ļ�������Ҫ��Ϣ��֪�Ǵ���
	if (!encrypt(dllBase, fileBuffer))return 0;

	//4.ѹ���ļ�������Ҫ��Ϣ��֪�Ǵ���
	char* packBuffer = nullptr;
	DWORD finalSize_ = packSection((DWORD)dllBase, fileBuffer, packBuffer, fileSize);
	
	//5.��������
	char* psword = (char*)GetProcAddress((HMODULE)dllBase, "password");
	printf("SET PASSWORD>>");
	gets_s(psword, MAX_PATH);
	//------------------------------
	//����Ŀ�����֧���ض�λ
	//6.��Ŀ��PEӳ�����һ���µ�����
	char* newFileBuffer = NULL;
	if (!addNewSection((DWORD)dllBase, (DWORD)packBuffer, finalSize_, newFileBuffer))return 0;
	//------------------------------
	//7.��Ŀ��ӳ�����Ϊ�ļ�
	saveToFile(newFileBuffer, finalSize_);
	return 0;
}
