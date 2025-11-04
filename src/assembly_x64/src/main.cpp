#include <iostream>
#include <Windows.h>

#if defined(_WIN64)
/// mycall x64汇编里的函数 调用
extern "C" UINT64 __stdcall mycall(); /// 函数的说明
extern "C" UINT64 __stdcall myadd1(); /// 函数的说明
#else
extern "C" UINT32 __stdcall mycall(); /// 函数的说明
extern "C" UINT32 __stdcall myadd1(); /// 函数的说明
#endif

int main()
{
#if defined(_WIN64)
    std::cout << "Running on x64 platform." << std::endl;
#else
    std::cout << "Running on x86 platform." << std::endl;
#endif
    printf("mycall返回值=%llX\r\n", (unsigned long long)mycall());
    printf("myadd1返回值=%llX\r\n", (unsigned long long)myadd1());

    getchar();
    return 0;
}
