#include <iostream>
#include <Windows.h>
int call00()
{
    printf("call00 无参数 call0_test  行号=%d\r\n", __LINE__);
    return 0x123;
}


int call01(int a)
{
    printf("call01 参数1=%d   行号=%d\r\n", a, __LINE__);
    return a + 2;
}
int call02(int a, int b)
{
    printf("call02 参数1=%d 参数2=%d 行号=%d\r\n", a, b, __LINE__);
    return a + b + 3;
}

int main()
{
    // HMODULE hDll = ::LoadLibrary(L"DBG_TOOL_x86_MFC_DLL.dll");

    //	MessageBoxA(0, 0, 0, 0);//ctrl+G 转到 MessageBoxA 下断
    printf("MessageBoxA=%p 行号=%d \r\n", MessageBoxA, __LINE__);
    int 计数 = 1;
    while (1)
    {
        printf("call00=%p call01=%p,call02=%p \n", call00, call01, call02);
        getchar();
        printf("计数=%d,行号=%d \r\n", 计数++, __LINE__);
    }
    return 1;
}
