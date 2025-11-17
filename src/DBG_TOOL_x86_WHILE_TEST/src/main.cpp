#include <iostream>

#include <stdio.h>

int main_while01()
{
    /* 局部变量定义 */
    int a = 10;

    /* while 循环执行 */
    /// SF(符号标志位)
    /// OF(溢出标志位)
    /// cmp a-20 从而影响到 符号标志位
    while (a < 20) /// SF=OF
    {
        printf("a 的值： %d  行号=%d \n", a, __LINE__);
        a++; /// a=a+1; add [esp+??],1// inc [esp+??]
    }

    return 0;
}

#include <stdio.h>

int main_do_while()
{
    /* 局部变量定义 */
    int a = 10;

    /* do 循环执行，在条件被测试之前至少执行一次 */
    do
    {
        printf("a 的值： %d 行号=%d \n ", a, __LINE__);
        a = a + 1;
    }
    while (a < 13); //
    printf("main 结束 行号=%d \n ", __LINE__);
    return 0;
}

#include <stdio.h>

int main_for()
{
    /* for 循环执行 */
    int a = 10;
    //for (; a < 20; ) 46行的代码 等价于 47行的代码
    while (a < 20)
    {
        printf("for循环测试:a 的值： %d 行号=%d \n ", a, __LINE__);
        a = a + 1;
    }

    return 0;
}

int main_for2()
{
    /* for 循环执行 */
    ;
    for (int a = 10 /*只执行一次*/; a < 20 /*判断语句*/; a = a + 1 /*增量语句*/)
    {
        printf("for循环测试:a 的值： %d 行号=%d \n ", a, __LINE__);
    }

    return 0;
}


int main_break()
{
    /* 局部变量定义 */
    int a = 1;

    /* while 循环执行 */
    while (a < 10)
    {
        if (a == 5)
        {
            /* 使用 break 语句终止循环 */
            break;
        }

        printf("for循环测试:a 的值： %d 行号=%d \n", a, __LINE__);
        a++;
    }

    return 0;
}

int main_continue()
{
    /* 局部变量定义 */
    int a = 0;

    /* while 循环执行 */
    while (a < 10) //0x0A=10
    {
        a++;
        if (a == 5)
        {
            /* 使用 continue 进入下一次循环 */
            continue;
        }
        printf("for循环测试:a 的值： %d 行号=%d \n", a, __LINE__);
    }

    return 0;
}

/// 新指定入口点
int main()
{
    printf("main start 行号=%d \n", __LINE__);
    main_continue();
    printf("main end   行号=%d \n", __LINE__);
    return 1;
}
