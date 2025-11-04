#include <Windows.h>

#include <stdio.h>

/// call ret 外平栈 _cdecl add esp,?? 调用约定 _stdcall  ret 数字
int callret(int abc)
{
    int a = 1;
    int b = 2;
    int c = 3;
    return abc + a + b + c + 0x123456;
}

/// 为什么还是 ebp+8？
/// 因为函数调用机制没有变：
///
/// 调用者：push 0x111 （参数压栈）
///
/// call指令：压入返回地址
///
/// 函数序言：push ebp; mov ebp,esp
///
/// 这个标准流程决定了：
///
/// 第一个参数总是在 ebp+8 的位置
///
/// 编译器优化不影响参数的位置，只影响局部变量的处理


int main(int argc, char *argv[])
{
    printf("callret=%X\r\n", callret(0x111));
    // std::cout << "Hello World!\n";
    getchar();
    return 0;
}
