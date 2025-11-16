#include <iostream>
int main()
{ ///&&
    printf("!(5 == 6 || 6 > 5) 等于=%d 行号=%d\r\n", !(5 == 6 || 6 > 5), __LINE__);

    if (!(5 == 6 || 6 > 5)) /// fasle || true  // 0 || 1
    {
        printf("条件表示式为真值 1 时会执行到这里 行号=%d\r\n", __LINE__);
        printf("条件表示式为真值 1 时会执行到这里 行号=%d\r\n", __LINE__);
    }
    else /// 条件不成立时执行下边
    {
        printf("条件表示式为假值 0 时会执行到这里 行号=%d\r\n", __LINE__);
        printf("条件表示式为假值 0 时会执行到这里 行号=%d\r\n", __LINE__);
    }
    int a = 0x111;
    int b = 0x222;
    if (a == b) ///  fasle || true  // 0 || 1
    {
        printf("条件表示式为真值 1 时会执行到这里 行号=%d\r\n", __LINE__);
        printf("条件表示式为真值 1 时会执行到这里 行号=%d\r\n", __LINE__);
    }
    else /// 条件不成立时执行下边
    {
        printf("条件表示式为假值 0 时会执行到这里 行号=%d\r\n", __LINE__);
        printf("条件表示式为假值 0 时会执行到这里 行号=%d\r\n", __LINE__);
    }
    return 1;
}
