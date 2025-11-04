#include <iostream>

#include <windows.h>

int  monitorCount      = 0;     /// 用于记录显示器数量
RECT secondMonitorRect = { 0 }; /// 存储第二个显示器的位置信息

BOOL CALLBACK MonitorEnumProc(HMONITOR hMonitor, HDC hdcMonitor, LPRECT lprcMonitor, LPARAM dwData)
{
    monitorCount++; /// 增加显示器计数
    if (monitorCount == 2)
    {                                     /// 只存储第二个显示器的信息
        secondMonitorRect = *lprcMonitor; /// 复制第二个显示器的矩形信息
    }
    return TRUE; /// 继续枚举下一个显示器
}

int main(int argc, char *argv[])
{
    // HWND 窗口句柄 = FindWindowA(NULL, "Everything"); /// (HWND)000000000AC11234
    HWND 窗口句柄 = FindWindowA("EVERYTHING", NULL);
    printf("窗口句柄=%p\r\n", 窗口句柄);

    // LPSTR 类名 = (LPSTR)malloc(256);
    // GetClassNameA(窗口句柄, 类名, 256);
    // printf("类名=%s\r\n", 类名);

    // SetWindowTextA(窗口句柄, "搜索中");
    // SetWindowTextA(窗口句柄, "搜索中123...");
    SetWindowTextA(窗口句柄, "文件搜索。。。");
    printf("sizeof(窗口句柄)=%zd字节\r\n", sizeof(窗口句柄)); //eax,rax


    EnumDisplayMonitors(NULL, NULL, MonitorEnumProc, 0);

    /// 如果有第二个显示器
    if (monitorCount > 1)
    {
        /// 移动窗口到第二个显示器的左上角
        SetWindowPos(窗口句柄, NULL, secondMonitorRect.left, secondMonitorRect.top, 0, 0,
                     SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        std::cout << "窗口已移动到副屏！" << std::endl;
    }
    else
    {
        std::cout << "未找到副屏！" << std::endl;
    }


    // /// 设置新的位置和大小
    // int x      = 500; /// 新的 x 坐标
    // int y      = 100; /// 新的 y 坐标
    int width  = 800; /// 新的宽度
    int height = 600; /// 新的高度

    /// 移动窗口
    {
        /// 移动位置
        // SetWindowPos(窗口句柄, NULL, secondMonitorRect.left + x, secondMonitorRect.top + y, width, height,
        //              SWP_NOZORDER | SWP_NOACTIVATE);
    }

    {
        /// 获取窗口的宽度和高度
        RECT windowRect;
        GetWindowRect(窗口句柄, &windowRect);
        int windowWidth  = windowRect.right - windowRect.left; /// 窗口宽度
        int windowHeight = windowRect.bottom - windowRect.top; /// 窗口高度

        /// 计算窗口的新位置，使其在副屏上居中
        int newX = secondMonitorRect.left + (secondMonitorRect.right - secondMonitorRect.left - windowWidth) / 2;
        int newY = secondMonitorRect.top + (secondMonitorRect.bottom - secondMonitorRect.top - windowHeight) / 2;

        // SetWindowPos(窗口句柄, NULL, newX, newY, width, height, SWP_NOZORDER | SWP_NOACTIVATE);
    }

    {
        /// 最大化窗口
        ShowWindow(窗口句柄, SW_SHOWMAXIMIZED);

        /// 可选：设置窗口为前台窗口
        SetForegroundWindow(窗口句柄);
    }

    getchar();

    return 0;
}
