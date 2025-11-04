#include <codecvt>
#include <iostream>

#include <windows.h>
#include <tlHelp32.h>
#include <tchar.h>
#include <float.h>


_In_opt_ constexpr LPCSTR lpClassName   = "Window";               ///< 窗口类名
_In_opt_ constexpr LPCSTR lpWindowName  = "Step 3";               ///< 窗口标题
_In_opt_ constexpr LPCSTR lpProcessName = "gtutorial-x86_64.exe"; ///< 进程名称
_In_opt_ constexpr LPCSTR lpMoudleName  = "gtutorial-x86_64.exe"; ///< 模块名称


/// \brief 将 LPCSTR 转换为 std::wstring
/// \param[in] lpStr
/// \return
std::wstring ConvertToWString(_In_opt_ const LPCSTR lpStr)
{
    /// 使用 std::wstring_convert 进行字符编码转换
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.from_bytes(lpStr);
}


/// \brief 将 LPCWSTR 转换为 std::string
/// \param[in] lpStr
/// \return 转换后的 std::string
std::string ConvertToString(_In_opt_ const LPCWSTR lpStr)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(lpStr);
}

/// \brief 获取指定进程的模块句柄
/// \param pid 进程ID
/// \param moduleName 模块名称
/// \return 模块句柄
UINT_PTR GetProcessModuleHandle(_In_opt_ DWORD pid, _In_opt_ const TCHAR* moduleName)
{
    MODULEENTRY32 moduleEntry;
    HANDLE        handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (handle == INVALID_HANDLE_VALUE)
    {
        return NULL;
    }

    ZeroMemory(&moduleEntry, sizeof(MODULEENTRY32));
    moduleEntry.dwSize = sizeof(MODULEENTRY32);

    if (!Module32First(handle, &moduleEntry))
    {
        CloseHandle(handle);
        return NULL;
    }

    do
    {
        if (_tcscmp(moduleEntry.szModule, moduleName) == 0)
        {
            CloseHandle(handle);
            return reinterpret_cast<UINT_PTR>(moduleEntry.hModule);
        }
    }
    while (Module32Next(handle, &moduleEntry));

    CloseHandle(handle);
    return NULL;
}

UINT_PTR GetMoudlueEntryAddress(_In_opt_ const LPCSTR processName)
{
    UINT_PTR result       = NULL;
    HANDLE   hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Failed to create process snapshot." << std::endl;
        return result;
    }

    PROCESSENTRY32 process = { sizeof(PROCESSENTRY32) };
    if (Process32First(hProcessSnap, &process))
    {
        do
        {
            std::wstring s_szExeFile  = process.szExeFile;
            std::wstring wProcessName = ConvertToWString(processName); /// 将传入的进程名转换为 std::wstring
            if (s_szExeFile == wProcessName)
            {
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process.th32ProcessID);
                if (hProcess)
                {
                    result = GetProcessModuleHandle(process.th32ProcessID, wProcessName.c_str());
                    if (result)
                    {
                        std::cout << processName << "的模块基地址：" << result << std::endl;
                    }
                    else
                    {
                        std::cerr << "Failed to get module handle." << std::endl;
                    }
                    CloseHandle(hProcess);
                }
                else
                {
                    std::cerr << "Failed to open process." << std::endl;
                }
            }
        }
        while (Process32Next(hProcessSnap, &process));
    }
    else
    {
        std::cerr << "Failed to retrieve process information." << std::endl;
    }

    CloseHandle(hProcessSnap);
    return result;
}
/// \brief 读取4字节数据
/// \param[in] address
/// \return
static UINT_PTR R4(_In_opt_ UINT_PTR address)
{
    unsigned int result = 0;

    /// Find the window handle based on class name and window name
    HWND handle = FindWindowA(lpClassName, lpWindowName);
    if (!handle) /// Check if the window handle is valid
    {
        printf("Window not found, ClassName=%s, WindowName=%s\r\n", lpClassName, lpWindowName);
        return 0;
    }

    DWORD pid = 0;
    DWORD tid = GetWindowThreadProcessId(handle, &pid);
    if (tid == 0) /// Check if the thread ID is valid
    {
        printf("Failed to get process ID, Error Code=%lu\r\n", GetLastError());
        return 0;
    }

    /// Open the process with necessary access rights
    HANDLE h_process = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (!h_process) /// Check if the process handle is valid
    {
        printf("Failed to open process, Error Code=%lu\r\n", GetLastError());
        return 0;
    }

    /// Read 4 bytes of memory from the specified address
    SIZE_T bytesRead;
    BOOL   readResult =
            ReadProcessMemory(h_process, reinterpret_cast<LPCVOID>(address), &result, sizeof(result), &bytesRead);

    if (!readResult || bytesRead != sizeof(result)) /// Check if reading was successful
    {
        printf("Failed to read memory, Error Code=%lu, Line Number=%d\r\n", GetLastError(), __LINE__);
        result = 0; /// Return 0 in case of failure
    }

    /// Close the process handle
    CloseHandle(h_process);
    return result; /// Return the value read from memory
}

/// \brief 读取4字节数据
/// \param[in] address
/// \return
static float RF4(_In_opt_ UINT_PTR address)
{
    float result = FLT_MIN;

    /// Find the window handle based on class name and window name
    HWND handle = FindWindowA(lpClassName, lpWindowName);
    if (!handle) /// Check if the window handle is valid
    {
        printf("Window not found, ClassName=%s, WindowName=%s\r\n", lpClassName, lpWindowName);
        return 0;
    }

    DWORD pid = 0;
    DWORD tid = GetWindowThreadProcessId(handle, &pid);
    if (tid == 0) /// Check if the thread ID is valid
    {
        printf("Failed to get process ID, Error Code=%lu\r\n", GetLastError());
        return 0;
    }

    /// Open the process with necessary access rights
    HANDLE h_process = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (!h_process) /// Check if the process handle is valid
    {
        printf("Failed to open process, Error Code=%lu\r\n", GetLastError());
        return 0;
    }

    /// Read 4 bytes of memory from the specified address
    SIZE_T bytesRead;
    BOOL   readResult =
            ReadProcessMemory(h_process, reinterpret_cast<LPCVOID>(address), &result, sizeof(result), &bytesRead);

    if (!readResult || bytesRead != sizeof(result)) /// Check if reading was successful
    {
        printf("Failed to read memory, Error Code=%lu, Line Number=%d\r\n", GetLastError(), __LINE__);
        result = 0; /// Return 0 in case of failure
    }

    /// Close the process handle
    CloseHandle(h_process);
    return result; /// Return the value read from memory
}

/// param[in]倒是方便 但是我更加喜欢 直接将输出放到返回值 C++ 的灵活是可控的 这样的可读性不比sal 差

/// \brief 写入4字节数据
/// \param[in] address
/// \param[in] val
/// \return
static BOOL W4(_In_opt_ UINT_PTR address, _In_opt_ DWORD val)
{
    HWND handle = FindWindowA(lpClassName, lpWindowName);
    if (!handle) ///  Check if the window handle is valid
    {
        printf("Window not found, ClassName=%s, WindowName=%s\r\n", lpClassName, lpWindowName);
        return false;
    }

    DWORD pid = 0;
    DWORD tid = GetWindowThreadProcessId(handle, &pid);
    if (tid == 0) ///  Check if the thread ID is valid
    {
        printf("Failed to get process ID, Error Code=%lu\r\n", GetLastError());
        return false;
    }

    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!processHandle) /// Check if the process handle is valid
    {
        printf("Failed to open process, Error Code=%lu\r\n", GetLastError());
        return false;
    }

    unsigned int newValue = val; /// Use the provided value
    SIZE_T       bytesWritten;
    BOOL writeResult = WriteProcessMemory(processHandle, reinterpret_cast<LPVOID>(address), &newValue, sizeof(newValue),
                                          &bytesWritten);

    if (!writeResult || bytesWritten != sizeof(newValue))
    {
        printf("Failed to write memory, Error Code=%lu, Line Number=%d\r\n", GetLastError(), __LINE__);
        CloseHandle(processHandle);
        return false;
    }

    CloseHandle(processHandle);
    return true;
}

static BOOL WF4(_In_opt_ UINT_PTR address, _In_opt_ FLOAT val)
{
    HWND handle = FindWindowA(lpClassName, lpWindowName);
    if (!handle) ///  Check if the window handle is valid
    {
        printf("Window not found, ClassName=%s, WindowName=%s\r\n", lpClassName, lpWindowName);
        return false;
    }

    DWORD pid = 0;
    DWORD tid = GetWindowThreadProcessId(handle, &pid);
    if (tid == 0) ///  Check if the thread ID is valid
    {
        printf("Failed to get process ID, Error Code=%lu\r\n", GetLastError());
        return false;
    }

    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!processHandle) /// Check if the process handle is valid
    {
        printf("Failed to open process, Error Code=%lu\r\n", GetLastError());
        return false;
    }

    float  newValue = val; /// Use the provided value
    SIZE_T bytesWritten;
    BOOL writeResult = WriteProcessMemory(processHandle, reinterpret_cast<LPVOID>(address), &newValue, sizeof(newValue),
                                          &bytesWritten);

    if (!writeResult || bytesWritten != sizeof(newValue))
    {
        printf("Failed to write memory, Error Code=%lu, Line Number=%d\r\n", GetLastError(), __LINE__);
        CloseHandle(processHandle);
        return false;
    }

    CloseHandle(processHandle);
    return true;
}


int main(int argc, char* argv[])
{
    /// [[["gtutorial-x86_64.exe"+3BED50] + 7C0] + 28] + 24 ///x
    /// [[["gtutorial-x86_64.exe" + 3BED50] + 7C0] + 28] + 28 ///y
    /// [["gtutorial-x86_64.exe" + 3BED50] + 7C0] + 88 /// 台阶
    /// 游戏教程第三关 直接破解


    /// 支持 std::string 或 std::wstring
    auto baseAddress = GetMoudlueEntryAddress(lpProcessName); /// 传入 const char*
    /// 如果需要使用 std::wstring，可以直接传入 wstring
    /// GetMoudlueEntryAddress(std::wstring(L"gtutorial-x86_64.exe"));
    printf("baseaddress = %p\n", baseAddress);
    auto greenStepAddress = R4(R4(baseAddress + 0x3BED50) + 0x7C0) + 0x88;
    auto greenSteps       = R4(greenStepAddress);
    printf("greenStepAddress = %p\n", greenStepAddress);
    printf("greenSteps = %d\n", greenSteps);

    auto xAddress = R4(R4(R4(baseAddress + 0x3BED50) + 0x7C0) + 0x28) + 0x24;
    auto x        = RF4(xAddress);
    printf("xAddress = %p\n", xAddress);
    printf("x = %f\n", x);

    std::cout << "==========================================" << std::endl;
    W4(greenStepAddress, 12);
    WF4(xAddress, 1.0f);

    printf("char所占空间=%d \r\n", sizeof(char));
    printf("short所占空间=%d \r\n", sizeof(short));
    printf("int所占空间=%d \r\n", sizeof(int));
    printf("long所占空间=%d \r\n", sizeof(long));

    printf("UINT_PTR所占空间=%d \r\n", sizeof(UINT_PTR));
    printf("LPVOID所占空间=%d \r\n", sizeof(LPVOID));

    printf("DWORD所占空间=%d \r\n", sizeof(DWORD));
    std::cout << "Hello World!\n";

    getchar();
    return 0;
}
