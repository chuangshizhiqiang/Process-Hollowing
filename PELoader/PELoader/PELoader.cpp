// PELoader.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>


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

BOOL StartProcess(std::wstring &executeFile, OUT STARTUPINFO &startUpInfo, OUT PROCESS_INFORMATION &processInfo) {


	startUpInfo.cb = sizeof(STARTUPINFO);

	//CreateProcess
	//CreateProcessinternal
	//ZwCreateUserProcess
	return CreateProcess(executeFile.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startUpInfo, &processInfo);
}


typedef ULONG(WINAPI* PFNNtUnmapViewOfSection) (HANDLE ProcessHandle, PVOID BaseAddress);

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

int main()
{
	std::cout << "Start" << std::endl;

	std::wstring injectFilePath = L"D:\\Project\\VS\\PELoader\\PELoader\\x64\\Debug\\InjectForPeLoader.exe";
	std::wstring beInjectedFilePath = L"D:\\Project\\VS\\PELoader\\PELoader\\x64\\Debug\\BeInjected.exe";
	LPVOID pAddr = 0;

	/*
		1、内存映射到本进程，方便进行加载和重定位
	*/
	pAddr = MapPE(injectFilePath);
	if (pAddr == 0) {
		return -1;
	}

	/*
		2、启动被注入进程，暂停模式启动被注入进程
	*/
	STARTUPINFO startUpInfo;
	PROCESS_INFORMATION processInfo;

	ZeroMemory(&startUpInfo, sizeof(STARTUPINFO));

	if (!StartProcess(beInjectedFilePath, startUpInfo, processInfo)) {
		std::cout << "[ERROR][StartProcess]" << GetLastError() << std::endl;
	}

	/*
		3、获取进程上下文，用于恢复的时候使用
	*/
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(processInfo.hThread, &context)) {
		std::cout << "[ERROR][GetThreadContext]" << GetLastError() << std::endl;
		return -1;
	}

	/*
		4、获取进程基址，X64 PEB 基址在 RDX 中
	*/
	PVOID baseAddr = 0;
	if (!ReadProcessMemory(processInfo.hProcess, (LPCVOID)(context.Rdx + 0x10), &baseAddr, sizeof(PVOID), 0)) {
		std::cout << "[ERROR][ReadProcessMemory]" << GetLastError() << std::endl;
		return -1;
	}

	/*
		5、清理被注入进程，ummap掉被注入进程已加载的东西
	*/
	if (CleanBeInjectedProcess(baseAddr, processInfo) == FALSE) {
		return -1;
	}

	/*
		6、申请新内存用于注入
	*/
	PVOID newAddrBase = 0;
	_IMAGE_DOS_HEADER *pDosHeader = (_IMAGE_DOS_HEADER*)pAddr;
	_IMAGE_NT_HEADERS64* pNtHeader = (_IMAGE_NT_HEADERS64*)(pDosHeader->e_lfanew + (char*)pAddr);

	newAddrBase = VirtualAllocEx(processInfo.hProcess,
		(LPVOID)pNtHeader->OptionalHeader.ImageBase,
		pNtHeader->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (!newAddrBase) {
		std::cout << "[ERROR][VirtualAllocEx]" << GetLastError() << std::endl;
		return -1;
	}

	/*
		7、替换内容为指定 PE
	*/
	// 7.1 文件头
	WriteProcessMemory(processInfo.hProcess, newAddrBase, pAddr, pNtHeader->OptionalHeader.SizeOfHeaders, NULL);

	// 7.2 section 写入
	LPVOID pSectionBaseAddr = (LPVOID)((ULONGLONG)pNtHeader + sizeof(_IMAGE_NT_HEADERS64));
	for (int i = 0; i < pNtHeader->OptionalHeader.NumberOfRvaAndSizes; i++) {
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONGLONG)pSectionBaseAddr + i * sizeof(IMAGE_SECTION_HEADER));

		WriteProcessMemory(processInfo.hProcess,
			(LPVOID)((ULONGLONG)newAddrBase + pSectionHeader->VirtualAddress),
			(LPCVOID)((ULONGLONG)pAddr + pSectionHeader->PointerToRawData),
			pSectionHeader->SizeOfRawData,
			NULL);
	}

	// 7.3 修正 PEB 中的基址
	WriteProcessMemory(processInfo.hProcess, (LPVOID)(context.Rdx + 0x10), &newAddrBase, sizeof(PVOID), NULL);

	/*
		8、如果分配的地址不是默认地址且开启了地址随机化则需要重定位修复
	*/
	if (newAddrBase != (PVOID)pNtHeader->OptionalHeader.ImageBase) {
		//todo
	}

	/*
		9、修正执行点参数，X64入口点存放在 Rcx 
	*/
	context.Rcx = (ULONGLONG)newAddrBase + pNtHeader->OptionalHeader.AddressOfEntryPoint;
	SetThreadContext(processInfo.hThread, &context);

	/*
		10、开始执行
	*/
	ResumeThread(processInfo.hThread);

	std::cout << "End" << std::endl;

	return 0;
}

