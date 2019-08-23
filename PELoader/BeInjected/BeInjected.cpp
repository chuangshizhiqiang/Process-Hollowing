// BeInjected.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>

int main()
{
    std::cout << "A Normal Day!\n";
	MessageBox(NULL, L"normal Day", L"AAA", MB_OK);
	Sleep(3 * 1000);
	return 0;
}
