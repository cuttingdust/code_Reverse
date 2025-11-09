#include <iostream>

//VS环境默认的调用约定
//add esp,参数数量*4
//add rsp,参数数量*8
int _cdecl call_cdecl(int a, int b)
{
    return a + b;
}

//ret 参数数量*4  //x86
//ret 参数数量*8  //x64
int _stdcall call_std(int a, int b)
{
    return a + b;
}
//快速
int _fastcall call_fast(int a, int b)
{
    return a + b;
}
// thiscall 类成员函数独有
/*
int __thiscall call_vector(int a, int b)
{
	return a + b;
}
*/
// __vectorcall (/ Gv)
int __vectorcall call_vector(int a, int b)
{
    return a + b;
}

int __vectorcall call_vector7(int a1, int a2, int a3, int a4, int a5, int a6, int a7)
{
    return 7;
    /// ret 14h /// 20 / 4 = 5;  5 + 2= 7
}

// int __clrcall test()
// {
//     return 1;
// }

int abc(int a, int b, int c)
{
    printf("技能释放 a=%d, b = %d, c=%d\n", a, b, c);
    return a + b + c;
}

int main()
{
    int a = 333;
    int b = 123;
    printf(" call_cdecl()=%d行号=%d\r\n", call_cdecl(0x111, 0x222), __LINE__);

    printf(" call_std()=%d行号=%d\r\n", call_std(0x11B, 0xB11), __LINE__);

    printf(" call_fast()=%d行号=%d\r\n", call_fast(0x11C, 0xC11), __LINE__);

    printf(" call_vector()=%d行号=%d\r\n", call_vector(0x11D, 0xD11), __LINE__);

    //////////////////////////////////////////////////////////////////


    printf(" call_vector7()=%d行号=%d\r\n", call_vector7(0x111, 0x222, 0x333, 0x444, 0x555, 0x666, 0x777), __LINE__);

    printf("释放技能 abc = %d\r\n", abc(0x123, 2, 6));
    getchar();
    return 1;
}
