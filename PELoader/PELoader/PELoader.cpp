/*********************************************************************************************************
**
** 创   建   人: CSZQ
**
** 描        述: 进程替换
**
** 修 改 日 志:
**
**
**
**
**
*********************************************************************************************************/

#include <windows.h>

#include <iostream>
#include <filesystem>   //VS2019 修改配置文件才能支持 C++17 标准
#include <list>

#include "debug.h"

/*********************************************************************************************************
	结构体/类
*********************************************************************************************************/
typedef ULONG(WINAPI* PFNNtUnmapViewOfSection) (HANDLE ProcessHandle, PVOID BaseAddress);

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING;

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetList,
	MemorySectionName
}MEMORY_INFORMATION_CLASS;

typedef
NTSTATUS
(WINAPI* ZWQUERYVIRTUALMEMORY) (
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
	OUT PVOID MemoryInformation,
	IN SIZE_T MemoryInformationLength,
	OUT PSIZE_T ReturnLength OPTIONAL
	);
/*********************************************************************************************************
	全局变量
*********************************************************************************************************/
std::wstring injectFilePath = L"D:\\Project\\VS\\PELoader\\PELoader\\x64\\Debug\\InjectForPeLoader.exe";
std::wstring beInjectedFilePath = L"D:\\Project\\VS\\PELoader\\PELoader\\x64\\Debug\\BeInjected.exe";

PROCESS_INFORMATION gProcessInfo;										// 新进程信息

LPVOID pLocalRamBaseAddr = 0;											// 本进程中替换程序基址
PVOID pRemoteMemBaseAddr = 0;											// 远程进程中替换程序基址

_IMAGE_DOS_HEADER* pLocalRamDosHeader = 0;								// 本进程中 RAM 格式 DOS 头
_IMAGE_NT_HEADERS64* pLocalRamNtHeader = 0;								// 本进程中 RAM 格式 NT 头
LPVOID pLocalRamSectionTableBaseAddr = 0;								// 本进程中 RAM 格式 Section 表


std::list<_IMAGE_SECTION_HEADER> SectionHeadersInfo;
_IMAGE_SECTION_HEADER* pImportTableSection;

/*********************************************************************************************************
	函数
*********************************************************************************************************/
void printDebugInfo(CONTEXT context) {
	printf("[DEBUG]\r\n");
	printf("RIP = %p\r\n", (PVOID)context.Rip);
	printf("RCX = %p\r\n", (PVOID)context.Rcx);
	printf("RDX = %p\r\n", (PVOID)context.Rdx);
	printf("R8 = %p\r\n", (PVOID)context.R8);
	printf("R9 = %p\r\n", (PVOID)context.R9);
	printf("RAX = %p\r\n", (PVOID)context.Rax);
	printf("RBX = %p\r\n", (PVOID)context.Rbx);
	printf("RBP = %p\r\n", (PVOID)context.Rbp);
	printf("RSP = %p\r\n", (PVOID)context.Rsp);
	printf("RSI = %p\r\n", (PVOID)context.Rsi);
	printf("RDI = %p\r\n", (PVOID)context.Rdi);

	printf("[/DEBUG]\r\n");
}

/*********************************************************************************************************
	说明：
		RVA 转 RAM 地址
	参数：
		
	返回值：
		
*********************************************************************************************************/
ULONGLONG RVA2RAM (ULONGLONG pRva) {

	for (auto x : SectionHeadersInfo) {
		if (pRva > x.VirtualAddress && pRva - x.VirtualAddress < x.SizeOfRawData) {
			return pRva - x.VirtualAddress + x.PointerToRawData;
		}
	}

	return 0;
}

/*********************************************************************************************************
	说明：
		RVA 转本地二进制映射镜像文件虚拟地址
	参数：

	返回值：

*********************************************************************************************************/
ULONGLONG RVA2LocalVA (ULONGLONG pRva) {
	for (auto x : SectionHeadersInfo) {
		if (pRva > x.VirtualAddress && pRva - x.VirtualAddress < x.SizeOfRawData) {
			return pRva - x.VirtualAddress + x.PointerToRawData + (ULONGLONG)pLocalRamBaseAddr;
		}
	}

	return 0;
}

/*********************************************************************************************************
	说明：
		RAM 转 RVA 地址
	参数：
		
	返回值：
		
*********************************************************************************************************/
ULONGLONG RAM2RVA (ULONGLONG pRAM) {
	for (auto x : SectionHeadersInfo) {
		if (pRAM > x.PointerToRawData && pRAM - x.PointerToRawData < x.SizeOfRawData) {
			return pRAM - x.PointerToRawData + x.VirtualAddress;
		}
	}

	return 0;
}

/*********************************************************************************************************
	说明：
		RAM 转 RVA 地址
	参数：

	返回值：

*********************************************************************************************************/
ULONGLONG RAM2LocalVA(ULONGLONG pRAM) {
	return pRAM + (ULONGLONG)pLocalRamBaseAddr;
}

/*********************************************************************************************************
	说明：
		RAW 方式将程序映射到本进程
	参数：
		path    程序路径
	返回值：
		本进程中 RAM 形式程序基址
*********************************************************************************************************/
PVOID MapPE(std::wstring &path) {
	HANDLE hFile = CreateFile(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		if (ERROR_FILE_NOT_FOUND == GetLastError()) {
			std::cout << "File not exist" << std::endl;
		}
		std::cout << "[ERROR][CreateFile]" << GetLastError() << std::endl;
		return 0;
	}

	HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMap == NULL) {
		std::cout << "[ERROR][CreateFileMapping]" << GetLastError() << std::endl;
		return 0;
	}

	LPVOID pAddr = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
	if (pAddr == NULL) {
		std::cout << "[ERROR][MapViewOfFile]" << GetLastError() << std::endl;
		return 0;
	}

	return pAddr;
}

/*********************************************************************************************************
	说明：
		被替换进程创建
	参数：
		executeFile  文件路径及名称
		startUpInfo  没卵用
		processInfo  进程信息
	返回值：
		成功与否
*********************************************************************************************************/
BOOL StartProcess(std::wstring &executeFile, OUT STARTUPINFO &startUpInfo, OUT PROCESS_INFORMATION &processInfo) {
	startUpInfo.cb = sizeof(STARTUPINFO);

	/*
		//CreateProcess
		//CreateProcessinternal
		//ZwCreateUserProcess   
	*/

	return CreateProcessW(executeFile.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startUpInfo, &processInfo);
}

/*********************************************************************************************************
	说明：
		清理被替换进程的原始数据
	参数：
		ProcessHandle  被注入进程句柄
		BaseAddress    被注入进程的基址
	返回值：
		成功与否
*********************************************************************************************************/
BOOL CleanBeInjectedProcess (PVOID pBaseAddr, PROCESS_INFORMATION processInfo) {

	HMODULE hModule = GetModuleHandle(L"ntdll.dll");

	PFNNtUnmapViewOfSection NtUnmapViewOfSection = (PFNNtUnmapViewOfSection)GetProcAddress(hModule, "NtUnmapViewOfSection");
	if (NtUnmapViewOfSection == NULL) {
		std::cout << "[ERROR][GetProcAddress]NtUnmapViewOfSection" << GetLastError() << std::endl;
		return FALSE;
	}

	NtUnmapViewOfSection(processInfo.hProcess, pBaseAddr);

	return TRUE;
}




BOOL InitBasicInfoX86() {
	return TRUE;
}

BOOL InitBasicInfoX64() {
	pLocalRamSectionTableBaseAddr = (LPVOID)((ULONGLONG)pLocalRamNtHeader + sizeof(_IMAGE_NT_HEADERS64));

	DWORD pImportTableRva = pLocalRamNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	for (DWORD i = 0; i < pLocalRamNtHeader->OptionalHeader.NumberOfRvaAndSizes; i++) {
		PIMAGE_SECTION_HEADER pSectionHeader = ((PIMAGE_SECTION_HEADER)pLocalRamSectionTableBaseAddr + i);
		SectionHeadersInfo.push_back(*pSectionHeader);
	}

	for (auto x : SectionHeadersInfo) {
		if (pImportTableRva > x.VirtualAddress && pImportTableRva - x.VirtualAddress < x.SizeOfRawData) {

			pImportTableSection = &x;
			break;
		}
	}

	return TRUE;
}

BOOL InitBasicInfo() {
	/*
		1、内存映射到本进程，方便进行加载和重定位
	*/
	pLocalRamBaseAddr = MapPE(injectFilePath);
	if (pLocalRamBaseAddr == 0) {
		return -1;
	}

	/*
		基本信息初始化
	*/
	pLocalRamDosHeader = (_IMAGE_DOS_HEADER*)pLocalRamBaseAddr;
	pLocalRamNtHeader = (_IMAGE_NT_HEADERS64*)(pLocalRamDosHeader->e_lfanew + (char*)pLocalRamBaseAddr);

	/*
		判断进程类型 X64 or X86
	*/
	switch (pLocalRamNtHeader->FileHeader.SizeOfOptionalHeader) {
	case 0xe0:
		DBGPRINT("X86 process not support yet!\r\n");
		exit(-1);
		InitBasicInfoX86();
		break;
	case 0xf0:
		DBGPRINT("x64 process\r\n");
		InitBasicInfoX64();
		break;
	default:
		DBGPRINT("Unknown process\r\n");
	}

	return TRUE;
}

int main()
{
	std::cout << "Start" << std::endl;

	/*
		基本信息初始化
	*/
	InitBasicInfo();

	/*
		2、启动被注入进程，暂停模式启动被注入进程
	*/
	STARTUPINFO startUpInfo;

	ZeroMemory(&startUpInfo, sizeof(STARTUPINFO));

	if (!StartProcess(beInjectedFilePath, startUpInfo, gProcessInfo)) {
		std::cout << "[ERROR][StartProcess]" << GetLastError() << std::endl;
	}

	/*
		3、获取进程上下文，用于恢复的时候使用
	*/
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(gProcessInfo.hThread, &context)) {
		std::cout << "[ERROR][GetThreadContext]" << GetLastError() << std::endl;
		return -1;
	}
	printDebugInfo(context);

	/*
		4、获取进程基址，X64 PEB 基址在 RDX 中
	*/
	
	if (!ReadProcessMemory(gProcessInfo.hProcess, (LPCVOID)(context.Rdx + 0x10), &pRemoteMemBaseAddr, sizeof(PVOID), 0)) {
		std::cout << "[ERROR][ReadProcessMemory]" << GetLastError() << std::endl;
		return -1;
	}

	/*
		5、清理被注入进程，ummap掉被注入进程已加载的东西
	*/
	if (CleanBeInjectedProcess(pRemoteMemBaseAddr, gProcessInfo) == FALSE) {
		return -1;
	}

	/*
		6、申请新内存用于注入
	*/
	PVOID pNewRemoteMemBaseAddr = 0;


	pNewRemoteMemBaseAddr = VirtualAllocEx(gProcessInfo.hProcess,
		(LPVOID)pLocalRamNtHeader->OptionalHeader.ImageBase,
		pLocalRamNtHeader->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (!pNewRemoteMemBaseAddr) {
		std::cout << "[ERROR][VirtualAllocEx]" << GetLastError() << std::endl;
		return -1;
	}

	/*
		7、替换内容为指定 PE
	*/
	// 7.1 文件头
	WriteProcessMemory(gProcessInfo.hProcess, pNewRemoteMemBaseAddr, pLocalRamBaseAddr, pLocalRamNtHeader->OptionalHeader.SizeOfHeaders, NULL);

	// 7.2 section 写入
	for (DWORD i = 0; i < pLocalRamNtHeader->OptionalHeader.NumberOfRvaAndSizes; i++) {
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONGLONG)pLocalRamSectionTableBaseAddr + i * sizeof(IMAGE_SECTION_HEADER));

		WriteProcessMemory(gProcessInfo.hProcess,
			(LPVOID)((ULONGLONG)pNewRemoteMemBaseAddr + pSectionHeader->VirtualAddress),
			(LPCVOID)((ULONGLONG)pLocalRamBaseAddr + pSectionHeader->PointerToRawData),
			pSectionHeader->SizeOfRawData,
			NULL);
	}

	// 7.3 修正 PEB 中的基址
	WriteProcessMemory(gProcessInfo.hProcess, (LPVOID)(context.Rdx + 0x10), &pNewRemoteMemBaseAddr, sizeof(PVOID), NULL);

	/*
		8、如果分配的地址不是默认地址则需要重定位修复
	*/
	if (pNewRemoteMemBaseAddr != (PVOID)pLocalRamNtHeader->OptionalHeader.ImageBase) {
		//todo
	}

	/*
		9、修正执行点参数，X64入口点存放在 Rcx 
	*/
	context.Rcx = (ULONGLONG)pNewRemoteMemBaseAddr + pLocalRamNtHeader->OptionalHeader.AddressOfEntryPoint;
	SetThreadContext(gProcessInfo.hThread, &context);

	/*
		10、开始执行
	*/
	ResumeThread(gProcessInfo.hThread);

	std::cout << "End" << std::endl;

	return 0;
}

