//
// 018-x64环境 常见的六种参数调用约定传递与平栈
//
#include <iostream>

//VS环境默认的调用约定
//add esp,参数数量*4
//add rsp,参数数量*8
int _cdecl call_cdecl(int a, int b, int a3, int a4, int a5, int a6)
{
    return a + b + a3 + a4 + a5 + a6;
}

//ret 参数数量*4  //x86   //ret 8
//ret 参数数量*8  //x64   //ret 10
int _stdcall call_std(int a, int b, int a3, int a4, int a5, int a6)
{
    return a + b + a3 + a4 + a5 + a6;
}
//快速
int _fastcall call_fast(int a, int b, int a3, int a4, int a5, int a6)
{
    return a + b + a3 + a4 + a5 + a6;
}
// thiscall 类成员函数独有
/*
int __thiscall call_vector(int a, int b)
{
	return a + b;
}
*/
// __vectorcall (/ Gv)
int __vectorcall call_vector(int a, int b, int a3, int a4, int a5, int a6)
{
    return a + b + a3 + a4 + a5 + a6;
}

//int __clrcall test()
//{
//	return 1;
//}

int abc(int a, int b, int c)
{
    printf("技能释放 a=%d,b=%d c=%d\r\n", a, b, c);
    return a + b + c;
}
int main()
{
    int a = 333;
    int b = 123;
    printf(" call_cdecl()=%X行号=%d\r\n", call_cdecl(0x11A, 0xA11, 3, 4, 5, 6), __LINE__);

    printf(" call_std()=%X行号=%d\r\n", call_std(0x11B, 0xB11, 3, 4, 5, 6), __LINE__);

    printf(" call_fast()=%X行号=%d\r\n", call_fast(0x11C, 0xC11, 3, 4, 5, 6), __LINE__);

    printf(" call_vector()=%X行号=%d\r\n", call_vector(0x11D, 0xD11, 3, 4, 5, 6), __LINE__);

    printf(" 释放技能 abc=%d\r\n", abc(0x123, 2, 6));
    getchar();
    return 1;
}
