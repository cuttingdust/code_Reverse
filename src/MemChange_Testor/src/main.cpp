#include <stdio.h>
#include <windows.h>

/// 多个全局变量，便于测试
int    g_nNum     = 1000;
int    g_nCounter = 50;
double g_dValue   = 3.14159;

int main(void)
{
    int        i        = 198;
    int        j        = 9999;
    static int s_static = 8888;

    /// 显示编译平台信息
#ifdef _WIN64
    printf("=== x64 内存测试程序 ===\n");
#else
    printf("=== x86 内存测试程序 ===\n");
#endif

    printf("进程ID: %d\n", GetCurrentProcessId());
    printf("\n");
    printf("局部变量: i=%d, &i=%p\n", i, &i);
    printf("局部变量: j=%d, &j=%p\n", j, &j);
    printf("全局变量: g_nNum=%d, &g_nNum=%p\n", g_nNum, &g_nNum);
    printf("全局变量: g_nCounter=%d, &g_nCounter=%p\n", g_nCounter, &g_nCounter);
    printf("全局变量: g_dValue=%.5f, &g_dValue=%p\n", g_dValue, &g_dValue);
    printf("静态变量: s_static=%d, &s_static=%p\n", s_static, &s_static);
    printf("\n");

    int step = 0;
    while (true)
    {
        printf("[步骤%d] 当前值: i=%d, g_nNum=%d, g_nCounter=%d\n", step, i, g_nNum, g_nCounter);
        printf("按回车键继续（输入q退出）...");

        char input[10];
        if (fgets(input, sizeof(input), stdin))
        {
            if (input[0] == 'q' || input[0] == 'Q')
                break;
        }

        /// 改变变量值
        ++i;
        --g_nNum;
        ++g_nCounter;
        g_dValue += 0.1;
        step++;
    }

    return 0;
}
