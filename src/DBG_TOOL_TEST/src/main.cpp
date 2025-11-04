#include <iostream>
static int vab        = 0; //静态变量
static int 静态变量v1 = 0; //定义静态变量

int 全局变量 = 123; //定义全局变量
int a, b, c;        //全局变量
#include <Windows.h>

int main()
{
    // MessageBoxA(0, 0, 0, 1);
    unsigned int 局部变量 = 0x12345678; //sub esp,???
    静态变量v1            = 0x111;
    全局变量              = 0x222;
    printf("静态变量v1=%d \r\n", 静态变量v1);
    printf("全局变量=%d \r\n", 全局变量);
    std::cout << "Hello World!\n";
}
