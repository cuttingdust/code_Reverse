#include <iostream>

#include <limits.h>


/// 识记数值类型char   1个字节 8个二进制位 -128,127
/// 识记数值类型short
/// 识记数值类型int
/// 识记 sizeof 运算符
/// 了解数值类型char*与LPCTSTR
/// 了解无符号整数unsigned
/// 了解自定义函数 int myaddt(int a,int b)
/// %d //表示格式化带符号整数       //<4字节
/// %u //表示格式化无符号整数 >=0   //<4字节
/// %zd //格式化   >=0 size_t
/// %llu //格式化显示 8字节 无符号整数
/// sizeof运算符 返回值是size_t 占用空间8字节 %llu %zd


int main(int argc, char *argv[])
{
    char 变量名;  /// _abc123,abc,汉字
    char a, b, c; /// size_t
    /// char表示范围 -128,0,127 //256
    /// unsigned char 0..255    //256
    a = -123;
    b = 126;
    c = 33336;
    printf("char所占内存空间大小 =%llu BYTE %zd 字节,%zd 字节,%zd 字节\n", sizeof(变量名), sizeof(a), sizeof(b),
           sizeof(c));
    printf("a=%d,b=%d,c=%d \r\n", a, b, c);
    ///    //short(2字节) 0..65535 int 0..0..65535*65535
    short i = 0, j = 0, k = 0;
    i = 33336;
    k = -33336;
    printf("j=%d,k=%d \r\n", i, k);
    /// int(4字节)
    int a2, a3;
    a2 = 33336;
    a3 = -33336;
    printf("a2=%d,a3=%d \r\n", a2, a3);
    
    /// char short int的表示范围
    printf("char类型表示范围 %d至%d\r\n", SCHAR_MIN, SCHAR_MAX);
    printf("unsigned char类型表示范围 %u至%u\r\n", 0, UCHAR_MAX);
    /// short
    printf("short类型表示范围 %d至%d\r\n", SHRT_MIN, SHRT_MAX);
    printf("unsigned short类型表示范围 %u至%u\r\n", 0, USHRT_MAX);
    /// int  -21亿 +21亿
    printf("int类型表示范围 %d至%d\r\n", INT_MIN, INT_MAX);
    printf("unsigned int类型表示范围 %u至%u\r\n", 0, UINT_MAX);

    ///  暂停等待键盘输入
    getchar();
    return 1;
}
