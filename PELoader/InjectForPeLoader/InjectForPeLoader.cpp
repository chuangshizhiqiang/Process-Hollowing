// InjectForPeLoader.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>

__declspec(dllimport) void  test(void);

int main()
{
    std::cout << "Injected!!!!!\n";
	MessageBox(NULL, L"Hack", L"CSZQ", MB_OK);

	test();

	Sleep(3 * 0x1000);
	return 0;
}
