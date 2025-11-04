#include <iostream>

#include <windows.h>

int main(int argc, char *argv[])
{
    // HWND h = FindWindowA("EVERYTHING", "Everything");
    HWND h = FindWindowA(NULL, "计算器");
    printf("窗口句柄 h=%p\r\n", h);

    DWORD pid, tid;
    printf("&pid=%p\r\n", &pid);
    /// int 和long是等价
    /// DWORD  等价于 unsigned long
    /// DWORD* 等价于 LPDWORD
    tid = GetWindowThreadProcessId(h, &pid); /// a&b
    printf("tid=%d pid=%d  16进制tid=%X 16进制pid=%X\r\n", tid, pid, tid, pid);

    return 0;
}
