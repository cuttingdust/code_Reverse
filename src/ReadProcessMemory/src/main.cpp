#include <iostream>

#include <windows.h>

/// 跨进程 读取目标地址  数据 每次读取4字节

unsigned int 读4字节(UINT_PTR 内存地址)
{
    // HWND h = FindWindowA("EVERYTHING", "Everything");
    // HWND h = FindWindowA(NULL, "计算器");
    HWND h = FindWindowA("MainWindow", "植物大战僵尸中文版");
    printf("窗口句柄 h=%p\r\n", h);

    DWORD pid, tid;
    printf("&pid=%p\r\n", &pid);
    /// int 和long是等价
    /// DWORD  等价于 unsigned long
    /// DWORD* 等价于 LPDWORD
    tid = GetWindowThreadProcessId(h, &pid); /// a&b
    printf("tid=%d pid=%d  16进制tid=%X 16进制pid=%X\r\n", tid, pid, tid, pid);

    /// 获取 进程 权限 句柄
    HANDLE 进程句柄 = OpenProcess(PROCESS_ALL_ACCESS, 0, pid); /// HWND
    printf("进程句柄=%p \r\n", 进程句柄);
    unsigned int 返回值 = 0;
    ReadProcessMemory(进程句柄, (LPCVOID)内存地址 /*要读取的地址*/, &返回值 /*存放数据的地址*/, 4, 0);
    printf("返回值=%X  返回值=%d 返回值=%u 行号=%d\r\n", 返回值, 返回值, 返回值, __LINE__); ///  GetLastError();
    return 返回值;
}

void 写4字节(UINT_PTR 内存地址)
{
    // HWND h = FindWindowA("EVERYTHING", "Everything");
    // HWND h = FindWindowA(NULL, "计算器");
    HWND h = FindWindowA("MainWindow", "植物大战僵尸中文版");
    printf("窗口句柄 h=%p\r\n", h);

    DWORD pid, tid;
    printf("&pid=%p\r\n", &pid);
    /// int 和long是等价
    /// DWORD  等价于 unsigned long
    /// DWORD* 等价于 LPDWORD
    tid = GetWindowThreadProcessId(h, &pid); /// a&b
    printf("tid=%d pid=%d  16进制tid=%X 16进制pid=%X\r\n", tid, pid, tid, pid);

    /// 获取 进程 权限 句柄
    HANDLE 进程句柄 = OpenProcess(PROCESS_ALL_ACCESS, 0, pid); /// HWND
    printf("进程句柄=%p \r\n", 进程句柄);

    /// 要写入的新值
    unsigned int 新值 = 1000; /// 替换为您要写入的值
    if (!WriteProcessMemory(进程句柄, (LPVOID)内存地址, &新值, sizeof(新值), nullptr))
    {
        printf("写入内存失败，错误代码=%lu, 行号=%d\r\n", GetLastError(), __LINE__);
    }
    else
    {
        printf("成功写入新值=%X  新值=%d  新值=%u, 行号=%d\r\n", 新值, 新值, 新值, __LINE__);
    }
}

unsigned int R4_bak(UINT_PTR 内存地址)
{
    //1 通过窗口标题或者类名 获取目标窗口句柄
    //2 通过窗口句柄获取进程的PID,TID
    HWND 窗口句柄 = FindWindowA("MainWindow", "植物大战僵尸中文版");
    printf("窗口句柄 h=%p  行号=%d\r\n", 窗口句柄, __LINE__);
    DWORD pid = 0, tid = 0;
    printf("&pid=%p\r\n", &pid);
    // int 和long是等价
    //DWORD  等价于 unsigned long
    //DWORD* 等价于 LPDWORD
    tid = GetWindowThreadProcessId(窗口句柄, &pid); // a&b
    printf("tid=%d pid=%d  16进制tid=%X 16进制pid=%X\r\n", tid, pid, tid, pid);
    //获取 进程 权限 句柄
    HANDLE 进程句柄 = OpenProcess(PROCESS_ALL_ACCESS, 0, pid); //HWND

    unsigned int 返回值 = 0;
    ReadProcessMemory(进程句柄, (LPCVOID)内存地址 /*要读取的地址*/, &返回值 /*存放数据的地址*/, 4, 0);
    printf("返回值=%X  返回值=%d 返回值=%u  行号=%d\r\n", 返回值, 返回值, 返回值, __LINE__); // GetLastError();
    return 返回值;
}

//unsigned
int R4(UINT_PTR 内存地址)
{
    unsigned int 返回值 = 0;
    if (HWND 窗口句柄 = FindWindowA("MainWindow", "植物大战僵尸中文版"))
    {
        DWORD pid = 0, tid = 0;
        tid = GetWindowThreadProcessId(窗口句柄, &pid);
        if (tid > 0)
        {
            if (HANDLE 进程句柄 = OpenProcess(PROCESS_ALL_ACCESS, 0, pid))
            {
                ReadProcessMemory(进程句柄, reinterpret_cast<LPCVOID>(内存地址 /*要读取的地址*/) /*要读取的地址*/,
                                  &返回值 /*存放数据的地址*/, 4, 0);
            }
        }
    }

    return 返回值;
}

int main(int argc, char *argv[])
{
    /// [[PlantsVsZombies.exe+2A9EC0]+768]+5560
    /// [[[6A9EC0]+768]+5560]
    // PlantsVsZombie.exe + 2A9EC0

    int 阳光值 = R4(R4(R4(0x6A9EC0) + 0x768) + 0x5560);
    printf("阳光值=%d 行号=%d\r\n", 阳光值, __LINE__);

    // [[[6A9EC0]+768]+5560]+111]+222]+333]+AAA]+BBB
    // int 阳光值=R4(R4(R4(R4(R4(R4(R4(R4(0x6A9EC0) + 0x768) + 0x5560)+111)+222)+333)+AAA)+BBB);

    getchar();
    return 0;
}
