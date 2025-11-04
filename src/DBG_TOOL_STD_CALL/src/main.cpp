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

// int __clrcall test()
// {
//     return 1;
// }
int main()
{
    int a = 333;
    int b = 123;
    printf(" call_cdecl()=%d行号=%d\r\n", call_cdecl(0x111, 0x222), __LINE__);

    printf(" call_std()=%d行号=%d\r\n", call_std(0x11B, 0xB11), __LINE__);

    printf(" call_fast()=%d行号=%d\r\n", call_fast(0x11C, 0xC11), __LINE__);

    printf(" call_vector()=%d行号=%d\r\n", call_vector(0x11D, 0xD11), __LINE__);

    return 1;
}
