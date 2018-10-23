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
	printf("超出范围的虚拟地址\n");
	return 0;
}
//获取FILEBUFFER
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

// 获取指定名字的区段头
IMAGE_SECTION_HEADER* getSectionByName(_In_ char* pBaseAddr,
	_In_  const char* scnName)//获取指定名字的区段
{
	// 获取区段格式
	DWORD dwScnCount = getFileHeader(pBaseAddr)->NumberOfSections;
	// 获取第一个区段
	IMAGE_SECTION_HEADER* pScn = IMAGE_FIRST_SECTION(getNtHeader(pBaseAddr));
	char buff[10] = { 0 };
	// 遍历区段
	for (DWORD i = 0; i < dwScnCount; ++i) {
		memcpy_s(buff, 8, (char*)pScn[i].Name, 8);
		// 判断是否是相同的名字
		if (strcmp(buff, scnName) == 0)
			return pScn + i;
	}
	return nullptr;
}
// 获取最后一个区段头
IMAGE_SECTION_HEADER* getLastSection(_In_ char* pFileData)// 获取最后一个区段
{
	// 获取区段个数
	DWORD dwScnCount = getFileHeader(pFileData)->NumberOfSections;
	// 获取第一个区段
	IMAGE_SECTION_HEADER* pScn = IMAGE_FIRST_SECTION(getNtHeader(pFileData));
	// 得到最后一个有效的区段
	return pScn + (dwScnCount - 1);
}
// 计算对齐大小

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
	//区段头表地址
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
	PIMAGE_BASE_RELOCATION pRelocTabVA = (PIMAGE_BASE_RELOCATION)(pOptionheader->DataDirectory[5].VirtualAddress + dllBase);//DLL的重定位表VA
	PIMAGE_SECTION_HEADER pTextSectionHeader = (PIMAGE_SECTION_HEADER)getSectionByName((char*)dllBase, ".text");//DLL代码段的区段头
	PIMAGE_SECTION_HEADER pNextSectinHeader = pTextSectionHeader + 1;//DLL代码段下一个段的区段头
	DWORD virtualStart = pTextSectionHeader->VirtualAddress;//计算需要处理的起始和终止位置
	DWORD virtualEnd = pNextSectinHeader->VirtualAddress;
	DWORD offset = 0;
	//给newTab新申请一片空间
	newTab = new char[pOptionheader->DataDirectory[5].Size]{};
	while (pRelocTabVA->SizeOfBlock)
	{
		DWORD old = 0;
		//只处理text段
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
	return offset + 8;//重定位表以全0元素结尾,
}
void fixRelocInfo(DWORD imageBase, DWORD newImageBase, DWORD newVirtualAddr)
{
	PIMAGE_NT_HEADERS pNt = getNtHeader((char*)imageBase);//dll的NT头
	PIMAGE_SECTION_HEADER pTextHeader = getSectionByName((char*)imageBase, ".text");//dll的text段头表
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
		//重定位表VA
		PIMAGE_BASE_RELOCATION pRelocTabVa = PIMAGE_BASE_RELOCATION(imageBase + pRelocTabRva);

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
					DWORD* dwNeedRelocAddr = (DWORD*)(imageBase + pRelocTabVa->VirtualAddress + typeOffset[i].offset);
					VirtualProtect((LPVOID)dwNeedRelocAddr, 1, PAGE_EXECUTE_READWRITE, &oldPro);
					//修复
					*dwNeedRelocAddr = *dwNeedRelocAddr - imageBase - pTextHeader->VirtualAddress + newVirtualAddr + pOption->ImageBase;
					VirtualProtect((LPVOID)dwNeedRelocAddr, 1, oldPro, &oldPro);
				}
			}
			
			//下一个重定位表块
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
	//1.给imageBuffer重新申请一片空间,并填充新区段表的表头信息
	PIMAGE_SECTION_HEADER pDllTextSecHeader = getSectionByName((char*)dllBase, ".text");
	//新大小 = 原文件按文件对齐后的大小 + dllText段的文件对齐大小 + dll重定位表文件对齐大小
	DWORD newSize = aligment(fileBufferSize, getOptionHeader((char*)fileBuffer)->FileAlignment)
		+ pDllTextSecHeader->SizeOfRawData + 
		aligment(getOptionHeader((char*)dllBase)->DataDirectory[5].Size, getOptionHeader((char*)fileBuffer)->FileAlignment);
	newFileBuffer = new char[newSize] {};
	memcpy(newFileBuffer, (char*)fileBuffer, fileBufferSize);
	delete[] (char*)fileBuffer;
	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(newFileBuffer);
	pFileHeader->NumberOfSections++;//区段数量+1
	PIMAGE_SECTION_HEADER pLastSecHeader = getLastSection(newFileBuffer);//buffer的最后一个区段头表
	PIMAGE_OPTIONAL_HEADER pOptionHeader = getOptionHeader(newFileBuffer);//buffer的option head
	DWORD calcPointerToRawData = aligment(fileBufferSize, pOptionHeader->FileAlignment);//计算新区段PointerToRawData
	PIMAGE_SECTION_HEADER pPreSec = pLastSecHeader - 1;//倒数第二个区段头表
	DWORD calcVirtualAddr = pPreSec->VirtualAddress + aligment(pPreSec->SizeOfRawData, pOptionHeader->SectionAlignment);//计算新区段VirtualAddr
	pLastSecHeader->Characteristics = 0xe00000e0;//区段属性可读可写可执行
	pLastSecHeader->Misc.VirtualSize = pDllTextSecHeader->Misc.VirtualSize;//未对齐大小
	memcpy(pLastSecHeader->Name, ".15PB", 5);//区段名
	pLastSecHeader->SizeOfRawData = pDllTextSecHeader->SizeOfRawData;//文件对齐大小
	pLastSecHeader->PointerToRawData = calcPointerToRawData;//pointerToRawData
	pLastSecHeader->VirtualAddress = calcVirtualAddr;//VirtualAddr
	//pOptionHeader->SizeOfImage = pDllTextSecHeader->SizeOfRawData + aligment(pOptionHeader->SizeOfImage,pOptionHeader->SectionAlignment);//修改sizeofImage
	//pOptionHeader->SizeOfImage += aligment(pDllTextSecHeader->SizeOfRawData, pOptionHeader->SectionAlignment);//修改sizeofImage
    //2.将目标程序的必要信息保存到壳代码dll导出的全局变量中
	STUB_CONFIG_* stubCfg = (STUB_CONFIG_*)GetProcAddress((HMODULE)dllBase, "cfg");
	stubCfg->oep = pOptionHeader->AddressOfEntryPoint;
	//3.遍历dll的重定位表修复text段信息
	fixRelocInfo(dllBase, (DWORD)newFileBuffer, calcVirtualAddr);
	//4.将text段复制到newBuffer的最后一个区段里
	memcpy(newFileBuffer + pLastSecHeader->PointerToRawData, (char*)dllBase + pDllTextSecHeader->VirtualAddress, pDllTextSecHeader->SizeOfRawData);
	//------------------------------------------------------------------------------------------------------
	//这里是将DLL部分的重定位表拷贝到被加壳程序
	//1.修改dll的重定位表数据,得到一个新的重定位表
	char* newRelocTab = NULL;
	DWORD newTabSize = acquireNewRelocTab(dllBase, newRelocTab, calcVirtualAddr);
	DWORD aligTabSize = aligment(newTabSize, pOptionHeader->FileAlignment);
	//2.然后复制到新buffer里面
	memcpy(newFileBuffer + calcPointerToRawData + pDllTextSecHeader->SizeOfRawData, newRelocTab, newTabSize);
	//3.数据目录表的重定位指针指向构造的重定位表
	pOptionHeader->DataDirectory[5].VirtualAddress = calcVirtualAddr + pDllTextSecHeader->SizeOfRawData;
	pOptionHeader->DataDirectory[5].Size = newTabSize;
	//pOptionHeader->SizeOfImage += aligTabSize;//修改sizeofImage
	pLastSecHeader->SizeOfRawData += aligTabSize;//将重定位表融入最后一个区段
	pLastSecHeader->Misc.VirtualSize += newTabSize;
	//------------------------------------------------------------------------------------------------------
	//将DLL的TLS表拷贝到被加壳程序中
	//------------------------------------------------------------------------------------------------------
	//1.获取DLL的TLS表RVA
	DWORD dllTlsRva = getOptionHeader((char*)dllBase)->DataDirectory[9].VirtualAddress;
	DWORD dllTlsSize = getOptionHeader((char*)dllBase)->DataDirectory[9].Size;
	//2.计算这个RVA在目标程序中的RVA
	DWORD targetRva = dllTlsRva - pDllTextSecHeader->VirtualAddress + pLastSecHeader->VirtualAddress;
	//3.将目标程序数据目录表的TLS指针指向这里
	pOptionHeader->DataDirectory[9].VirtualAddress = targetRva;
	pOptionHeader->DataDirectory[9].Size = dllTlsSize;
	//------------------------------------------------------------------------------------------------------
	//5.修改原始OEP为壳代码的EP
	DWORD expEp = (DWORD)GetProcAddress((HMODULE)dllBase, "entry");
	expEp = expEp - dllBase - pDllTextSecHeader->VirtualAddress + pLastSecHeader->VirtualAddress;
	pOptionHeader->AddressOfEntryPoint = expEp;
	fileBufferSize = calcPointerToRawData + pDllTextSecHeader->SizeOfRawData + aligTabSize;
	pOptionHeader->SizeOfImage = pLastSecHeader->VirtualAddress + 
		aligment(pLastSecHeader->SizeOfRawData, pOptionHeader->SectionAlignment);//修改sizeofImage
	return true;
}
bool encrypt(HANDLE dllBase, char* fileBuffer)
{
	//1.获取DLL导出信息结构体
	STUB_CONFIG_* stubConfig = (STUB_CONFIG_*)GetProcAddress((HMODULE)dllBase, "cfg");
	if (!stubConfig)
	{
		printf("fail to getProcAddr!\n");
		return false;
	}
	srand((unsigned)time(0));
	int key = rand() % 15 + 1;
	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(fileBuffer);//文件头
	PIMAGE_NT_HEADERS pNt = getNtHeader(fileBuffer);//NT头
	PIMAGE_SECTION_HEADER pSecHeader = IMAGE_FIRST_SECTION(pNt);//区段表头
	PIMAGE_OPTIONAL_HEADER pOptinHeader = getOptionHeader(fileBuffer);//可选PE头

	//2.填充结构体信息
	//----------填充结构体信息-------------
	stubConfig->key = key;
	stubConfig->oep = pOptinHeader->AddressOfEntryPoint;
	stubConfig->peImageBase = pOptinHeader->ImageBase;
	stubConfig->iatRva = pOptinHeader->DataDirectory[1].VirtualAddress;
	stubConfig->iatSize = pOptinHeader->DataDirectory[1].Size;
	stubConfig->dataDirector_ImpTab = (DWORD)pOptinHeader - (DWORD)fileBuffer + 0x68;
	stubConfig->dataDirector_RVA = (DWORD)pOptinHeader->DataDirectory - (DWORD)fileBuffer;
	stubConfig->numOfEncrySection = pFileHeader->NumberOfSections;//资源表不加密
	
	for (DWORD i = 0; i < pFileHeader->NumberOfSections; i++, pSecHeader++)
	{
		if (strcmp((char*)pSecHeader->Name, ".rsrc") == 0)//资源表不加密
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
	//----------填充结构体信息-------------
	//3.加密区段,xor一个1~15的随机数
	pSecHeader = IMAGE_FIRST_SECTION(pNt);//重置pSectionheader
	for (DWORD i = 0; i < pFileHeader->NumberOfSections; i++, pSecHeader++)//加密区段数据
	{
		//--------------------------------
		if (strcmp((char*)pSecHeader->Name, ".rsrc") == 0)//资源表不加密
			continue;
		//--------------------------------
		for (DWORD j = 0; j < pSecHeader->SizeOfRawData; j++)
		{
			*(BYTE*)(pSecHeader->PointerToRawData + fileBuffer + j) ^= key;
			stubConfig->dataStartAndOverArry[i].isEncrypt = true;
		}
	}
	//清空数据目录表的内容
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
	//获取需要压缩的区段,除开壳代码段本身,和原来的最后一个区段(包含特殊信息)
	WORD needHandleSection = pFileHeader->NumberOfSections;
	pPackInfo->numOfSection = needHandleSection;
	//申请一个newBuffer
	newFileBuffer = new char[fileSize] {};
	DWORD nTotalSize = pOptionHeader->SizeOfHeaders;
	//压缩区段
	for (WORD i = 0; i < needHandleSection; i++)
	{
		//1.如果是文件对其大小为0,或者是.rsrc区段,则不压缩,并将其拷贝至新buffer里面,修改其pointerToRawData
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
		//2.其他区段则压缩
		//-----------------------------------------------
		int length = pSectionHeader->SizeOfRawData;//被压缩数据的大小
		
		/* allocate workmem and destination memory */
		char *workmem = new char[aP_workmem_size(length)]{};
		char *compressed = new char[aP_max_packed_size(length)]{};
		
		/* compress data[] to compressed[] */
		size_t outlength = aPsafe_pack(fileBuffer + pSectionHeader->PointerToRawData, compressed, length, workmem, NULL, NULL);//压缩后的实际大小
		//------------------------------------------------

		DWORD calAigment = aligment(outlength, pOptionHeader->FileAlignment);//计算压缩后的文件对齐大小
		memcpy(newFileBuffer + nTotalSize, compressed, calAigment);

		//3.修改该区段pointerToData和sizeofRawData
		pSectionHeader->PointerToRawData = nTotalSize;
		pPackInfo->packSectionInfo[i].sizeOfRawData = pSectionHeader->SizeOfRawData;
		pSectionHeader->SizeOfRawData = calAigment;
		nTotalSize += calAigment;
		//4.填充信息结构体
		pPackInfo->packSectionInfo[i].isPacked = true;
		pPackInfo->packSectionInfo[i].originSize = length;
		pPackInfo->packSectionInfo[i].size = outlength;
		pPackInfo->packSectionInfo[i].startAddrRva = pSectionHeader->VirtualAddress;

		delete[] workmem;
		delete[] compressed;
		pSectionHeader++;
	}
	//5.拷贝头
	memcpy(newFileBuffer, fileBuffer, pOptionHeader->SizeOfHeaders);
	return nTotalSize;
}
int main()
{
	//1.获取目标文件的fileBuffer
	char* fileBuffer = NULL;
	DWORD fileSize = 0;
	if (!(fileSize = getFileBuffer(fileBuffer)))return 0;//先得到fileBuffer
	//2.加载壳代码dll
	HANDLE dllBase = LoadLibraryExA("packDll.dll", 0, DONT_RESOLVE_DLL_REFERENCES);
	if (!dllBase)
	{
		printf("fail to load dllInfo!\n");
		return false;
	}
	//3.加密文件并将必要信息告知壳代码
	if (!encrypt(dllBase, fileBuffer))return 0;

	//4.压缩文件并将必要信息告知壳代码
	char* packBuffer = nullptr;
	DWORD finalSize_ = packSection((DWORD)dllBase, fileBuffer, packBuffer, fileSize);
	
	//5.设置密码
	char* psword = (char*)GetProcAddress((HMODULE)dllBase, "password");
	printf("SET PASSWORD>>");
	gets_s(psword, MAX_PATH);
	//------------------------------
	//测试目标程序支持重定位
	//6.向目标PE映像添加一个新的区段
	char* newFileBuffer = NULL;
	if (!addNewSection((DWORD)dllBase, (DWORD)packBuffer, finalSize_, newFileBuffer))return 0;
	//------------------------------
	//7.将目标映像另存为文件
	saveToFile(newFileBuffer, finalSize_);
	return 0;
}
