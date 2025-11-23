#include <Windows.h>
#include <TlHelp32.h>

#include <string>
#include <iostream>
#include <algorithm>
#include <vector>

/**
 * @brief 根据窗口标题获取进程PID（宽字符版本）
 * @param windowTitle 窗口标题
 * @return 进程PID，如果找不到返回0
 */
DWORD GetProcessPIDByWindowTitle(const std::wstring& windowTitle)
{
    if (windowTitle.empty())
    {
        std::wcerr << L"错误: 窗口标题不能为空" << std::endl;
        return 0;
    }

    HWND hWindow = ::FindWindow(nullptr, windowTitle.c_str());
    if (hWindow == nullptr)
    {
        DWORD errorCode = ::GetLastError();
        std::wcerr << L"错误: 找不到窗口 '" << windowTitle << L"', 错误代码: " << errorCode << std::endl;
        return 0;
    }

    DWORD processId = 0;
    DWORD threadId  = ::GetWindowThreadProcessId(hWindow, &processId);

    if (processId == 0)
    {
        std::wcerr << L"错误: 无法获取进程PID" << std::endl;
        return 0;
    }

    std::wcout << L"找到进程: " << windowTitle << L", PID: " << processId << L", 线程ID: " << threadId << std::endl;

    return processId;
}


/**
 * @brief 根据进程名称获取进程PID（宽字符版本）
 * @param processName 进程名称（如: L"notepad.exe"）
 * @return 进程PID，如果找不到返回0
 */
DWORD GetProcessPIDByName(const std::wstring& processName)
{
    if (processName.empty())
    {
        std::wcerr << L"错误: 进程名称不能为空" << std::endl;
        return 0;
    }

    HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"错误: 无法创建进程快照" << std::endl;
        return 0;
    }

    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    DWORD targetPid = 0;

    if (::Process32FirstW(hSnapshot, &processEntry))
    {
        do
        {
            if (_wcsicmp(processEntry.szExeFile, processName.c_str()) == 0)
            {
                targetPid = processEntry.th32ProcessID;
                std::wcout << L"找到进程: " << processName << L", PID: " << targetPid << std::endl;
                break;
            }
        }
        while (::Process32NextW(hSnapshot, &processEntry));
    }
    else
    {
        DWORD errorCode = ::GetLastError();
        std::wcerr << L"错误: 枚举进程失败，错误代码: " << errorCode << std::endl;
    }

    ::CloseHandle(hSnapshot);

    if (targetPid == 0)
    {
        std::wcerr << L"错误: 找不到进程 '" << processName << L"'" << std::endl;
    }

    return targetPid;
}


/**
 * @brief 根据窗口类名获取进程PID
 * @param className 窗口类名
 * @return 进程PID，如果找不到返回0
 */
DWORD GetProcessPIDByClassName(const std::wstring& className)
{
    if (className.empty())
    {
        std::wcerr << L"错误: 窗口类名不能为空" << std::endl;
        return 0;
    }

    HWND hWindow = ::FindWindow(className.c_str(), nullptr);
    if (hWindow == nullptr)
    {
        DWORD errorCode = ::GetLastError();
        std::wcerr << L"错误: 找不到类名为 '" << className << L"' 的窗口, 错误代码: " << errorCode << std::endl;
        return 0;
    }

    DWORD processId = 0;
    ::GetWindowThreadProcessId(hWindow, &processId);

    if (processId == 0)
    {
        std::wcerr << L"错误: 无法获取进程PID" << std::endl;
        return 0;
    }

    std::wcout << L"找到窗口类: " << className << L", PID: " << processId << std::endl;

    return processId;
}

///////////////////////////////////////////////////////////////////////////////////

/**
 * @brief 判断当前进程是32位还是64位
 */
bool IsProcess64Bit()
{
#if defined(_WIN64)
    return true; /// 编译为64位程序
#else
    /// 32位程序运行在64位系统上？
    BOOL isWow64 = FALSE;
    if (IsWow64Process(GetCurrentProcess(), &isWow64))
    {
        return isWow64; /// 如果是WOW64，说明系统是64位
    }
    return false;
#endif
}


/**
 * @brief 判断目标进程是32位还是64位
 */
bool IsTargetProcess64Bit(DWORD processId)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (hProcess == nullptr)
    {
        return false;
    }

    BOOL isWow64 = FALSE;
    bool is64Bit = false;

    if (IsWow64Process(hProcess, &isWow64))
    {
        /// 如果是WOW64进程，说明目标进程是32位运行在64位系统上
        /// 如果不是WOW64进程，在64位系统上就是64位进程
        is64Bit = !isWow64;
    }

    CloseHandle(hProcess);
    return is64Bit;
}


/**
 * @brief x86 架构地址分析
 */
void AnalyzeAddressX86(ULONG_PTR address, DWORD processId)
{
    std::wcout << L"  - x86地址分析:" << std::endl;

    /// x86 典型地址范围
    if (address == 0)
    {
        std::wcout << L"    * NULL指针" << std::endl;
    }
    else if (address < 0x10000)
    {
        std::wcout << L"    * 小整数参数: " << address;
        /// 常见的小整数含义
        if (address == 0)
            std::wcout << L" (NULL/FALSE)";
        else if (address == 1)
            std::wcout << L" (TRUE)";
        else if (address == 0xFFFFFFFF)
            std::wcout << L" (INVALID_HANDLE_VALUE/-1)";
        else if (address == 0xDEADBEEF)
            std::wcout << L" (调试标记)";
        else if (address == 0xBABABABA)
            std::wcout << L" (调试标记)";
        std::wcout << std::endl;
    }
    else if (address >= 0x00400000 && address <= 0x7FFFFFFF)
    {
        std::wcout << L"    * 用户模式地址空间" << std::endl;

        /// 常见的x86模块基址
        if (address >= 0x00400000 && address <= 0x10000000)
        {
            std::wcout << L"    * 可能为EXE/DLL代码段 (.text)" << std::endl;
        }
        else if (address >= 0x10000000 && address <= 0x70000000)
        {
            std::wcout << L"    * 可能为DLL模块基址" << std::endl;
        }
        else if (address >= 0x70000000 && address <= 0x7FFFFFFF)
        {
            std::wcout << L"    * 可能为系统DLL区域" << std::endl;
        }

        /// 检查对齐
        if ((address & 0xFFFF) == 0)
        {
            std::wcout << L"    * 64K对齐 - 可能为模块基址" << std::endl;
        }
    }
    else if (address >= 0x80000000 && address <= 0xFFFFFFFF)
    {
        std::wcout << L"    * 内核模式地址空间 (x86)" << std::endl;
        std::wcout << L"    * 警告: 用户模式无法访问" << std::endl;
    }
    else
    {
        std::wcout << L"    * 非标准地址范围" << std::endl;
    }
}

/**
 * @brief x64 架构地址分析
 */
void AnalyzeAddressX64(ULONG_PTR address, DWORD processId)
{
    std::wcout << L"  - x64地址分析:" << std::endl;

    /// x64 典型地址范围
    if (address == 0)
    {
        std::wcout << L"    * NULL指针" << std::endl;
    }
    else if (address < 0x10000)
    {
        std::wcout << L"    * 小整数参数: " << address;
        /// 常见的小整数含义
        if (address == 0)
            std::wcout << L" (NULL/FALSE)";
        else if (address == 1)
            std::wcout << L" (TRUE)";
        else if (address == 0xFFFFFFFF)
            std::wcout << L" (INVALID_HANDLE_VALUE/-1)";
        else if (address == 0xDEADBEEF)
            std::wcout << L" (调试标记)";
        else if (address == 0xBABABABA)
            std::wcout << L" (调试标记)";
        std::wcout << std::endl;
    }
    else if (address >= 0x0000000000010000 && address <= 0x000007FFFFFFFFFF)
    {
        std::wcout << L"    * 用户模式地址空间 (低128TB)" << std::endl;

        /// x64 典型的模块基址
        if (address >= 0x0000000100000000 && address <= 0x0000000500000000)
        {
            std::wcout << L"    * 可能为EXE/DLL代码段" << std::endl;
        }
        else if (address >= 0x0000000500000000 && address <= 0x000007FFFFFFFFFF)
        {
            std::wcout << L"    * 可能为堆/数据段" << std::endl;
        }

        /// 检查对齐
        if ((address & 0xFFFF) == 0)
        {
            std::wcout << L"    * 64K对齐 - 可能为模块基址" << std::endl;
        }
    }
    else if (address >= 0x0000080000000000 && address <= 0x00000FFFFFFFFFFF)
    {
        std::wcout << L"    * 用户模式地址空间 (高128TB)" << std::endl;
    }
    else if (address >= 0xFFFF080000000000 && address <= 0xFFFFFFFFFFFFFFFF)
    {
        std::wcout << L"    * 内核模式地址空间 (x64)" << std::endl;
        std::wcout << L"    * 警告: 用户模式无法访问" << std::endl;
    }
    else
    {
        std::wcout << L"    * 非标准地址范围" << std::endl;
    }

    /// x64 特定的特征检查
    if ((address & 0xFFFF000000000000) == 0x0000000000000000)
    {
        std::wcout << L"    * 规范地址格式" << std::endl;
    }
}


/**
 * @brief 详细打印参数信息（支持x86和x64）
 */
void PrintParameterDetails(LPVOID parameter, DWORD processId = 0)
{
    if (parameter == nullptr)
    {
        std::wcout << L"参数类型: 空指针" << std::endl;
        return;
    }

    ULONG_PTR paramValue    = reinterpret_cast<ULONG_PTR>(parameter);
    bool      isTarget64Bit = IsTargetProcess64Bit(processId);

    std::wcout << L"参数详细信息:" << std::endl;
    std::wcout << L"  - 指针地址: 0x" << std::hex << paramValue << std::dec << std::endl;
    std::wcout << L"  - 整数值: " << paramValue << std::endl;
    std::wcout << L"  - 目标进程架构: " << (isTarget64Bit ? L"x64" : L"x86") << std::endl;

    /// 根据架构进行不同的地址分析
    if (isTarget64Bit)
    {
        AnalyzeAddressX64(paramValue, processId);
    }
    else
    {
        AnalyzeAddressX86(paramValue, processId);
    }
}


/**
 * @brief 简化的参数信息打印（自动检测架构）
 */
void PrintParameterDetailsSimple(LPVOID parameter, DWORD processId = 0)
{
    if (parameter == nullptr)
    {
        std::wcout << L"参数: 空指针" << std::endl;
        return;
    }

    ULONG_PTR paramValue    = reinterpret_cast<ULONG_PTR>(parameter);
    bool      isTarget64Bit = IsTargetProcess64Bit(processId);

    std::wcout << L"参数: 0x" << std::hex << paramValue << std::dec << L" (" << paramValue << L")" << std::endl;
    std::wcout << L"目标架构: " << (isTarget64Bit ? L"x64" : L"x86") << std::endl;

    /// 基本类型推断
    if (paramValue == 0)
    {
        std::wcout << L"类型推断: NULL/0" << std::endl;
    }
    else if (paramValue == 1)
    {
        std::wcout << L"类型推断: TRUE/1" << std::endl;
    }
    else if (paramValue < 0x1000)
    {
        std::wcout << L"类型推断: 小整数参数" << std::endl;
    }
    else if (isTarget64Bit)
    {
        /// x64 地址推断
        if (paramValue >= 0x0000000100000000 && paramValue <= 0x000007FFFFFFFFFF)
        {
            std::wcout << L"类型推断: x64用户模式地址" << std::endl;
        }
    }
    else
    {
        /// x86 地址推断
        if (paramValue >= 0x00400000 && paramValue <= 0x7FFFFFFF)
        {
            std::wcout << L"类型推断: x86用户模式地址" << std::endl;
        }
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////


/**
 * @brief 在远程进程中创建线程执行指定函数
 * @param processId 目标进程ID
 * @param functionAddress 要执行的函数地址
 * @param parameter 传递给函数的参数
 * @param accessRights 进程访问权限
 * @return 成功返回true，失败返回false
 */
bool ExecuteRemoteThread(DWORD processId, LPVOID functionAddress, LPVOID parameter = nullptr,
                         DWORD accessRights = PROCESS_ALL_ACCESS)
{
    /// 参数验证
    if (processId == 0)
    {
        std::wcerr << L"错误: 无效的进程ID" << std::endl;
        return false;
    }

    if (functionAddress == nullptr)
    {
        std::wcerr << L"错误: 函数地址不能为空" << std::endl;
        return false;
    }

    /// 打印调用信息
    std::wcout << L"=== 远程线程调用信息 ===" << std::endl;
    std::wcout << L"目标进程PID: " << processId << std::endl;
    std::wcout << L"函数地址: 0x" << std::hex << functionAddress << std::dec << std::endl;
    std::wcout << L"参数: ";
    PrintParameterDetails(parameter, processId); /// 使用简化版本
    std::wcout << L"访问权限: 0x" << std::hex << accessRights << std::dec << std::endl;
    std::wcout << L"=========================" << std::endl;

    /// 打开目标进程
    HANDLE hProcess = ::OpenProcess(accessRights, FALSE, processId);
    if (hProcess == nullptr)
    {
        DWORD errorCode = ::GetLastError();
        std::wcerr << L"错误: 无法打开进程 PID=" << processId << L", 错误代码: " << errorCode << std::endl;
        return false;
    }

    std::wcout << L"成功打开目标进程句柄: 0x" << std::hex << hProcess << std::dec << std::endl;

    /// 在远程进程中创建线程
    HANDLE hRemoteThread = ::CreateRemoteThread(hProcess, /// 目标进程句柄
                                                nullptr,  /// 安全属性
                                                0,        /// 堆栈大小
                                                reinterpret_cast<LPTHREAD_START_ROUTINE>(functionAddress), /// 函数地址
                                                parameter,                                                 /// 参数
                                                0,                                                         /// 创建标志
                                                nullptr                                                    /// 线程ID
    );

    bool success = false;

    if (hRemoteThread != nullptr)
    {
        std::wcout << L"远程线程创建成功，线程句柄: 0x" << std::hex << hRemoteThread << std::dec << std::endl;

        /// 等待线程完成（可选）
        DWORD waitResult = ::WaitForSingleObject(hRemoteThread, 5000); /// 5秒超时
        if (waitResult == WAIT_OBJECT_0)
        {
            std::wcout << L"远程线程执行完成" << std::endl;
        }
        else if (waitResult == WAIT_TIMEOUT)
        {
            std::wcout << L"警告: 远程线程执行超时" << std::endl;
        }
        else if (waitResult == WAIT_FAILED)
        {
            DWORD errorCode = ::GetLastError();
            std::wcerr << L"错误: 等待远程线程失败，错误代码: " << errorCode << std::endl;
        }
        else
        {
            std::wcerr << L"错误: 等待远程线程返回未知状态: " << waitResult << std::endl;
        }

        ::CloseHandle(hRemoteThread);
        std::wcout << L"已关闭远程线程句柄" << std::endl;
        success = true;
    }
    else
    {
        DWORD errorCode = ::GetLastError();
        std::wcerr << L"错误: 创建远程线程失败，错误代码: " << errorCode << std::endl;

        /// 提供更详细的错误信息
        switch (errorCode)
        {
            case ERROR_ACCESS_DENIED:
                std::wcerr << L"详细: 访问被拒绝，可能权限不足" << std::endl;
                break;
            case ERROR_INVALID_HANDLE:
                std::wcerr << L"详细: 无效的进程句柄" << std::endl;
                break;
            case ERROR_NOT_ENOUGH_MEMORY:
                std::wcerr << L"详细: 内存不足" << std::endl;
                break;
            case ERROR_INVALID_PARAMETER:
                std::wcerr << L"详细: 参数无效" << std::endl;
                break;
            default:
                std::wcerr << L"详细: 未知错误" << std::endl;
                break;
        }
    }

    ::CloseHandle(hProcess);
    std::wcout << L"已关闭进程句柄" << std::endl;

    if (success)
    {
        std::wcout << L"远程线程调用操作成功完成" << std::endl;
    }
    else
    {
        std::wcerr << L"远程线程调用操作失败" << std::endl;
    }

    return success;
}


/**
 * @brief 安全的远程执行函数，使用最小权限
 * @param processId 目标进程ID
 * @param functionAddress 函数地址
 * @param parameter 参数
 * @return 成功返回true，失败返回false
 */
bool ExecuteRemoteThreadSafely(DWORD processId, LPVOID functionAddress, LPVOID parameter = nullptr)
{
    /// 使用最小必要权限
    DWORD accessRights = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
            PROCESS_VM_READ;

    return ExecuteRemoteThread(processId, functionAddress, parameter, accessRights);
}


/**
 * @brief 示例用法1：通过窗口标题注入
 */
void ExampleUsageByWindowTitle()
{
    const std::wstring windowTitle = LR"(DBG_TOOL_x64_REGISTER_TEST.exe)";

    DWORD pid = GetProcessPIDByWindowTitle(windowTitle);
    if (pid != 0)
    {
        /// 注意：这里的地址需要根据实际情况调整
        LPVOID targetFunction = reinterpret_cast<LPVOID>(0x00C91046);
        LPVOID parameter      = reinterpret_cast<LPVOID>(123);

        ExecuteRemoteThreadSafely(pid, targetFunction, parameter);
    }
}


/**
 * @brief 示例用法2：通过进程名称注入
 */
void ExampleUsageByProcessName()
{
    const std::wstring processName = L"DBG_TOOL_x64_REGISTER_TEST.exe";

    DWORD pid = GetProcessPIDByName(processName);
    if (pid != 0)
    {
        LPVOID targetFunction = reinterpret_cast<LPVOID>(0x00C91046);
        LPVOID parameter      = reinterpret_cast<LPVOID>(123);

        ExecuteRemoteThreadSafely(pid, targetFunction, parameter);
    }
}


/**
 * @brief 优化的回调调用函数
 */
void OptimizedCallbackCall()
{
    std::wcout << L"=== 开始远程线程注入 ===" << std::endl;

    DWORD pid = 0;

    /// 方法1：使用进程名称获取PID
    const std::wstring processName = L"DBG_TOOL_x64_REGISTER_TEST.exe";
    pid                            = GetProcessPIDByName(processName);

    /// 方法2：如果方法1失败，使用窗口标题
    if (pid == 0)
    {
        const std::wstring windowTitle = LR"(DBG_TOOL_x64_REGISTER_TEST.exe)";
        pid                            = GetProcessPIDByWindowTitle(windowTitle);
    }

    /// 方法3：如果方法2失败，使用硬编码PID（仅用于测试）
    if (pid == 0)
    {
        pid = 23000; /// 备用PID
        std::wcout << L"使用备用PID: " << pid << std::endl;
    }

    if (pid != 0)
    {
        // LPVOID functionAddress = reinterpret_cast<LPVOID>(0x00C91046); /// 目标函数地址 call00=00C91046
        LPVOID functionAddress = reinterpret_cast<LPVOID>(0x00C91299); /// 目标函数地址 call00=00C91299


        LPVOID parameter = reinterpret_cast<LPVOID>(123);

        if (ExecuteRemoteThreadSafely(pid, functionAddress, parameter))
        {
            std::wcout << L"远程线程注入成功完成" << std::endl;
        }
        else
        {
            std::wcerr << L"远程线程注入失败" << std::endl;
        }
    }
    else
    {
        std::wcerr << L"错误: 无法获取有效的进程PID" << std::endl;
    }
}


/**
 * @brief 枚举所有匹配的进程
 * @param processName 进程名称
 * @return 匹配的PID列表
 */
auto FindAllProcessesByName(const std::wstring& processName) -> std::vector<DWORD>
{
    std::vector<DWORD> pids;

    HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return pids;
    }

    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    if (::Process32FirstW(hSnapshot, &processEntry))
    {
        do
        {
            if (_wcsicmp(processEntry.szExeFile, processName.c_str()) == 0)
            {
                pids.push_back(processEntry.th32ProcessID);
            }
        }
        while (::Process32NextW(hSnapshot, &processEntry));
    }

    ::CloseHandle(hSnapshot);
    return pids;
}

int main()
{
    setlocale(LC_ALL, "chs");
    std::wcout << L"=== 远程线程注入示例 ===" << std::endl;

    /// 使用优化后的版本
    OptimizedCallbackCall();

    // 或者使用其他示例
    // ExampleUsageByWindowTitle();
    // ExampleUsageByProcessName();

    std::wcout << L"=== 程序执行完毕 ===" << std::endl;
    return 0;
}
