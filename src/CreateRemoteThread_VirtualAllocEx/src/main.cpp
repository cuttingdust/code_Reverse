#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <iostream>
#include <algorithm>
#include <iomanip>
#include <vector>
#include <memory>

///////////////////////////////////////////////////////////////////////////////////
/// 裸汇编函数定义
///////////////////////////////////////////////////////////////////////////////////

// __declspec(naked) void NakedAssemblyCode()
// {
//     _asm {
//         // 多参数函数调用
//         push 2 // 第二个参数
//         push 1 // 第一个参数
//         mov eax, 0x00081177 // 目标函数地址
//         call eax // 调用函数
//         add esp, 8 // 清理栈
//         mov eax, 0x12345678 // 设置返回值
//         ret
//     }
// }

/// 这种方式注入的时候 老是会 jmp 到开辟的其他地方

///////////////////////////////////////////////////////////////////////////////////
/// 内联汇编模板
///////////////////////////////////////////////////////////////////////////////////

class InlineAssemblyTemplate
{
public:
    /**
     * @brief 创建可定制的汇编代码
     */
    static std::vector<BYTE> CreateCustomAssembly(DWORD param1, DWORD param2, DWORD targetFunc)
    {
        /// 这是汇编代码的模板 //// __cdecl 约定
        std::vector<BYTE> code = {
            0x6A, 0x00,                   /// push param2 (占位符)
            0x6A, 0x00,                   /// push param1 (占位符)
            0xB8, 0x00, 0x00, 0x00, 0x00, /// mov eax, target (占位符)
            0xFF, 0xD0,                   /// call eax
            0x83, 0xC4, 0x08,             /// add esp, 8
            0xB8, 0x78, 0x56, 0x34, 0x12, /// mov eax, 0x12345678
            0xC3                          /// ret
        };

        /// 替换占位符
        code[1] = static_cast<BYTE>(param2);
        code[3] = static_cast<BYTE>(param1);

        /// 替换目标地址（小端序）
        code[5] = (targetFunc >> 0) & 0xFF;
        code[6] = (targetFunc >> 8) & 0xFF;
        code[7] = (targetFunc >> 16) & 0xFF;
        code[8] = (targetFunc >> 24) & 0xFF;

        return code;
    }

    /**
     * @brief 打印汇编代码和对应的机器码
     */
    static void PrintAssembly(const std::vector<BYTE>& code, DWORD param1, DWORD param2, DWORD targetFunc)
    {
        std::wcout << L"=== 生成的汇编代码 ===" << std::endl;
        std::wcout << L"参数1: " << param1 << L" (0x" << std::hex << param1 << L")" << std::endl;
        std::wcout << L"参数2: " << param2 << L" (0x" << std::hex << param2 << L")" << std::endl;
        std::wcout << L"目标函数地址: 0x" << std::hex << targetFunc << std::dec << std::endl;
        std::wcout << L"------------------------" << std::endl;

        // 先打印原始机器码用于调试
        std::wcout << L"原始机器码: ";
        for (size_t j = 0; j < code.size(); j++)
        {
            std::wcout << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<int>(code[j]) << L" ";
        }
        std::wcout << std::dec << std::endl;
        std::wcout << L"------------------------" << std::endl;

        // 逐条指令解析
        size_t i = 0;
        while (i < code.size())
        {
            std::wcout << L"地址 0x" << std::hex << std::setw(2) << std::setfill(L'0') << i << L": ";

            // 检查当前指令
            if (code[i] == 0x6A && i + 1 < code.size())
            {
                // push imm8
                std::wcout << L"push " << static_cast<int>(code[i + 1]) << L"  \t// 机器码: 6A " << std::hex
                           << std::setw(2) << static_cast<int>(code[i + 1]) << std::dec;
                i += 2;
            }
            else if (code[i] == 0xB8 && i + 4 < code.size())
            {
                // mov eax, imm32 - 正确的小端序解析
                DWORD value = code[i + 1] | (code[i + 2] << 8) | (code[i + 3] << 16) | (code[i + 4] << 24);
                std::wcout << L"mov eax, 0x" << std::hex << value << L"\t// 机器码: B8 " << std::hex << std::setw(2)
                           << static_cast<int>(code[i + 1]) << L" " << std::setw(2) << static_cast<int>(code[i + 2])
                           << L" " << std::setw(2) << static_cast<int>(code[i + 3]) << L" " << std::setw(2)
                           << static_cast<int>(code[i + 4]) << std::dec;
                i += 5;
            }
            else if (code[i] == 0xFF && i + 1 < code.size() && code[i + 1] == 0xD0)
            {
                // call eax
                std::wcout << L"call eax\t// 机器码: FF D0";
                i += 2;
            }
            else if (code[i] == 0x83 && i + 2 < code.size() && code[i + 1] == 0xC4)
            {
                // add esp, imm8
                std::wcout << L"add esp, " << static_cast<int>(code[i + 2]) << L"  \t// 机器码: 83 C4 " << std::hex
                           << std::setw(2) << static_cast<int>(code[i + 2]) << std::dec;
                i += 3;
            }
            else if (code[i] == 0xC3)
            {
                // ret
                std::wcout << L"ret\t\t// 机器码: C3";
                i += 1;
            }
            else
            {
                // 未知指令
                std::wcout << L"未知指令: 0x" << std::hex << std::setw(2) << static_cast<int>(code[i]) << std::dec;
                i += 1;
            }

            std::wcout << std::endl;
        }

        std::wcout << L"------------------------" << std::endl;
        std::wcout << L"总代码大小: " << code.size() << L" 字节" << std::endl;

        // 验证实际替换的值
        std::wcout << L"实际替换验证:" << std::endl;
        if (code.size() > 1)
            std::wcout << L"  push 参数2: " << static_cast<int>(code[1]) << " (0x" << std::hex
                       << static_cast<int>(code[1]) << ")" << std::dec << std::endl;
        if (code.size() > 3)
            std::wcout << L"  push 参数1: " << static_cast<int>(code[3]) << " (0x" << std::hex
                       << static_cast<int>(code[3]) << ")" << std::dec << std::endl;
        if (code.size() > 9)
        {
            DWORD actualAddr = code[6] | (code[7] << 8) | (code[8] << 16) | (code[9] << 24);
            std::wcout << L"  mov eax 地址: 0x" << std::hex << actualAddr << " (期望: 0x" << targetFunc << ")"
                       << std::dec << std::endl;
        }

        std::wcout << L"=========================" << std::endl;
    }

    /**
     * @brief 打印原始机器码（十六进制格式）
     */
    static void PrintMachineCode(const std::vector<BYTE>& code)
    {
        std::wcout << L"=== 机器码（十六进制）===" << std::endl;

        for (size_t i = 0; i < code.size(); i++)
        {
            if (i % 8 == 0)
            {
                if (i > 0)
                    std::wcout << std::endl;
                std::wcout << L"0x" << std::hex << std::setw(2) << std::setfill(L'0') << i << L": ";
            }
            std::wcout << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<int>(code[i]) << L" ";
        }
        std::wcout << std::dec << std::endl;
        std::wcout << L"=========================" << std::endl;
    }

    /**
     * @brief 创建并打印汇编代码（一体化函数）
     */
    static std::vector<BYTE> CreateAndPrintAssembly(DWORD param1, DWORD param2, DWORD targetFunc)
    {
        auto code = CreateCustomAssembly(param1, param2, targetFunc);
        PrintAssembly(code, param1, param2, targetFunc);
        PrintMachineCode(code);
        return code;
    }
};


//////////////////////////////////////////////////////////////////////////////////
/// 裸函数注入器
///////////////////////////////////////////////////////////////////////////////////

class DLLInjector
{
public:
    /**
     * @brief 直接注入裸函数到远程进程
     */
    static bool InjectDLL(DWORD processId, LPVOID nakedFunction)
    {
        auto shellcode = InlineAssemblyTemplate::CreateAndPrintAssembly(0x01, 0x02, (DWORD)nakedFunction);

        /// 打开目标进程
        HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!hProcess)
        {
            std::wcerr << L"无法打开进程: " << ::GetLastError() << std::endl;
            return false;
        }

        /// 分配可执行内存
        LPVOID remoteMem = ::VirtualAllocEx(hProcess, NULL, 20, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!remoteMem)
        {
            std::wcerr << L"无法分配远程内存: " << ::GetLastError() << std::endl;
            ::CloseHandle(hProcess);
            return false;
        }

        std::wcout << L"裸函数注入地址: 0x" << std::hex << remoteMem << std::dec << std::endl;

        /// 写入裸函数代码
        SIZE_T bytesWritten = 0;
        if (!::WriteProcessMemory(hProcess, remoteMem, shellcode.data(), shellcode.size(), &bytesWritten))
        {
            std::wcerr << L"无法写入裸函数代码: " << ::GetLastError() << std::endl;
            ::VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            ::CloseHandle(hProcess);
            return false;
        }

        std::wcout << L"成功写入 " << bytesWritten << L" 字节裸函数代码" << std::endl;

        /// 创建远程线程执行裸函数
        HANDLE hThread = ::CreateRemoteThread(hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteMem),
                                              NULL, 0, NULL);

        bool success = false;
        if (hThread)
        {
            std::wcout << L"远程线程创建成功，等待执行..." << std::endl;

            /// 等待线程完成
            DWORD waitResult = ::WaitForSingleObject(hThread, 5000);
            if (waitResult == WAIT_OBJECT_0)
            {
                std::wcout << L"裸函数执行完成" << std::endl;
                success = true;
            }
            else
            {
                std::wcerr << L"裸函数执行超时或失败: " << waitResult << std::endl;
            }

            ::CloseHandle(hThread);
        }
        else
        {
            std::wcerr << L"创建远程线程失败: " << ::GetLastError() << std::endl;
        }

        /// 清理
        ::VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        ::CloseHandle(hProcess);

        return success;
    }
};


namespace Constants
{
    const std::wstring TARGET_PROCESS_NAME = L"DBG_TOOL_x64_REGISTER_TEST.exe";
    const std::wstring TARGET_WINDOW_TITLE = LR"(DBG_TOOL_x64_REGISTER_TEST.exe)";
    const DWORD        FALLBACK_PID        = 23000;

    // 目标函数地址
    namespace FunctionAddresses
    {
        const LPVOID CALL_00 = reinterpret_cast<LPVOID>(0x00D71046);
        const LPVOID CALL_01 = reinterpret_cast<LPVOID>(0x00D71299);
        const LPVOID CALL_02 = reinterpret_cast<LPVOID>(0x00D71177);
    } // namespace FunctionAddresses
} // namespace Constants

///////////////////////////////////////////////////////////////////////////////////
/// 进程查找模块
///////////////////////////////////////////////////////////////////////////////////

class ProcessFinder
{
public:
    /**
     * @brief 根据窗口标题获取进程PID
     */
    static DWORD GetPIDByWindowTitle(const std::wstring& windowTitle)
    {
        if (windowTitle.empty())
        {
            LogError(L"窗口标题不能为空");
            return 0;
        }

        HWND hWindow = ::FindWindow(nullptr, windowTitle.c_str());
        if (!hWindow)
        {
            LogError(L"找不到窗口 '" + windowTitle + L"'", ::GetLastError());
            return 0;
        }

        DWORD processId = 0;
        DWORD threadId  = ::GetWindowThreadProcessId(hWindow, &processId);

        if (processId == 0)
        {
            LogError(L"无法获取进程PID");
            return 0;
        }

        LogInfo(L"找到进程: " + windowTitle + L", PID: " + std::to_wstring(processId) + L", 线程ID: " +
                std::to_wstring(threadId));
        return processId;
    }

    /**
     * @brief 根据进程名称获取进程PID
     */
    static DWORD GetPIDByName(const std::wstring& processName)
    {
        if (processName.empty())
        {
            LogError(L"进程名称不能为空");
            return 0;
        }

        std::unique_ptr<std::remove_pointer<HANDLE>::type, decltype(&::CloseHandle)> hSnapshot(
                ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), ::CloseHandle);

        if (!hSnapshot || hSnapshot.get() == INVALID_HANDLE_VALUE)
        {
            LogError(L"无法创建进程快照", ::GetLastError());
            return 0;
        }

        PROCESSENTRY32W processEntry = { sizeof(PROCESSENTRY32W) };
        DWORD           targetPid    = 0;

        if (::Process32FirstW(hSnapshot.get(), &processEntry))
        {
            do
            {
                if (_wcsicmp(processEntry.szExeFile, processName.c_str()) == 0)
                {
                    targetPid = processEntry.th32ProcessID;
                    LogInfo(L"找到进程: " + processName + L", PID: " + std::to_wstring(targetPid));
                    break;
                }
            }
            while (::Process32NextW(hSnapshot.get(), &processEntry));
        }
        else
        {
            LogError(L"枚举进程失败", ::GetLastError());
        }

        if (targetPid == 0)
        {
            LogError(L"找不到进程 '" + processName + L"'");
        }

        return targetPid;
    }

    /**
     * @brief 根据窗口类名获取进程PID
     */
    static DWORD GetPIDByClassName(const std::wstring& className)
    {
        if (className.empty())
        {
            LogError(L"窗口类名不能为空");
            return 0;
        }

        HWND hWindow = ::FindWindow(className.c_str(), nullptr);
        if (!hWindow)
        {
            LogError(L"找不到类名为 '" + className + L"' 的窗口", ::GetLastError());
            return 0;
        }

        DWORD processId = 0;
        ::GetWindowThreadProcessId(hWindow, &processId);

        if (processId == 0)
        {
            LogError(L"无法获取进程PID");
            return 0;
        }

        LogInfo(L"找到窗口类: " + className + L", PID: " + std::to_wstring(processId));
        return processId;
    }

    /**
     * @brief 获取目标进程PID（多种方法尝试）
     */
    static DWORD GetTargetPID()
    {
        // 方法1：使用进程名称
        DWORD pid = GetPIDByName(Constants::TARGET_PROCESS_NAME);

        // 方法2：如果方法1失败，使用窗口标题
        if (pid == 0)
        {
            pid = GetPIDByWindowTitle(Constants::TARGET_WINDOW_TITLE);
        }

        // 方法3：如果方法2失败，使用备用PID
        if (pid == 0)
        {
            pid = Constants::FALLBACK_PID;
            LogInfo(L"使用备用PID: " + std::to_wstring(pid));
        }

        return pid;
    }

private:
    static void LogInfo(const std::wstring& message)
    {
        std::wcout << L"[INFO] " << message << std::endl;
    }

    static void LogError(const std::wstring& message, DWORD errorCode = 0)
    {
        std::wcerr << L"[ERROR] " << message;
        if (errorCode != 0)
        {
            std::wcerr << L", 错误代码: " << errorCode;
        }
        std::wcerr << std::endl;
    }
};

///////////////////////////////////////////////////////////////////////////////////
/// 内存操作模块
///////////////////////////////////////////////////////////////////////////////////

class RemoteMemoryManager
{
public:
    /**
     * @brief 在远程进程中分配内存并写入数据
     */
    static LPVOID AllocateAndWrite(HANDLE hProcess, LPVOID localData, SIZE_T dataSize)
    {
        if (!hProcess || !localData || dataSize == 0)
        {
            LogError(L"无效的参数");
            return nullptr;
        }

        LPVOID remoteMemory = ::VirtualAllocEx(hProcess, nullptr, dataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteMemory)
        {
            LogError(L"无法在远程进程中分配内存", ::GetLastError());
            return nullptr;
        }

        SIZE_T bytesWritten = 0;
        if (!::WriteProcessMemory(hProcess, remoteMemory, localData, dataSize, &bytesWritten))
        {
            LogError(L"无法写入远程内存", ::GetLastError());
            ::VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
            return nullptr;
        }

        LogInfo(L"远程内存分配成功: 0x" + AddressToHexString(remoteMemory) + L", 大小: " + std::to_wstring(dataSize) +
                L" 字节");
        return remoteMemory;
    }

    /**
     * @brief 释放远程内存
     */
    static void Free(HANDLE hProcess, LPVOID remoteMemory)
    {
        if (hProcess && remoteMemory)
        {
            ::VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
            LogInfo(L"已释放远程内存: 0x" + AddressToHexString(remoteMemory));
        }
    }

private:
    static void LogInfo(const std::wstring& message)
    {
        std::wcout << L"[MEMORY] " << message << std::endl;
    }

    static void LogError(const std::wstring& message, DWORD errorCode = 0)
    {
        std::wcerr << L"[MEMORY ERROR] " << message;
        if (errorCode != 0)
        {
            std::wcerr << L", 错误代码: " << errorCode;
        }
        std::wcerr << std::endl;
    }

    static std::wstring AddressToHexString(LPVOID address)
    {
        wchar_t buffer[32];
        swprintf_s(buffer, L"%p", address);
        return buffer;
    }
};

///////////////////////////////////////////////////////////////////////////////////
/// 架构检测模块
///////////////////////////////////////////////////////////////////////////////////

class ArchitectureDetector
{
public:
    /**
     * @brief 判断当前进程是32位还是64位
     */
    static bool IsCurrentProcess64Bit()
    {
#if defined(_WIN64)
        return true;
#else
        BOOL isWow64 = FALSE;
        return (IsWow64Process(GetCurrentProcess(), &isWow64) && isWow64);
#endif
    }

    /**
     * @brief 判断目标进程是32位还是64位
     */
    static bool IsTargetProcess64Bit(DWORD processId)
    {
        std::unique_ptr<std::remove_pointer<HANDLE>::type, decltype(&::CloseHandle)> hProcess(
                ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId), ::CloseHandle);

        if (!hProcess)
            return false;

        BOOL isWow64 = FALSE;
        if (IsWow64Process(hProcess.get(), &isWow64))
        {
            return !isWow64; // 不是WOW64进程就是64位进程
        }

        return false;
    }
};

///////////////////////////////////////////////////////////////////////////////////
/// 地址分析模块
///////////////////////////////////////////////////////////////////////////////////

class AddressAnalyzer
{
public:
    struct AddressInfo
    {
        std::wstring type;
        std::wstring description;
        std::wstring additionalInfo;
    };

    /**
     * @brief 分析地址信息
     */
    static AddressInfo Analyze(ULONG_PTR address, DWORD processId = 0)
    {
        AddressInfo info;

        if (address == 0)
        {
            info.type        = L"NULL指针";
            info.description = L"空指针或零值";
            return info;
        }

        if (address < 0x10000)
        {
            info.type           = L"小整数参数";
            info.description    = L"数值: " + std::to_wstring(address);
            info.additionalInfo = GetSmallIntegerMeaning(address);
            return info;
        }

        bool isTarget64Bit = ArchitectureDetector::IsTargetProcess64Bit(processId);
        if (isTarget64Bit)
        {
            return AnalyzeX64(address);
        }
        else
        {
            return AnalyzeX86(address);
        }
    }

    /**
     * @brief 详细打印参数信息
     */
    static void PrintDetailedInfo(LPVOID parameter, DWORD processId = 0)
    {
        if (!parameter)
        {
            std::wcout << L"参数类型: 空指针" << std::endl;
            return;
        }

        ULONG_PTR paramValue = reinterpret_cast<ULONG_PTR>(parameter);
        auto      info       = Analyze(paramValue, processId);

        std::wcout << L"参数详细信息:" << std::endl;
        std::wcout << L"  - 指针地址: 0x" << std::hex << paramValue << std::dec << std::endl;
        std::wcout << L"  - 整数值: " << paramValue << std::endl;
        std::wcout << L"  - 类型: " << info.type << std::endl;
        std::wcout << L"  - 描述: " << info.description << std::endl;
        if (!info.additionalInfo.empty())
        {
            std::wcout << L"  - 附加信息: " << info.additionalInfo << std::endl;
        }
    }

    /**
     * @brief 简化参数信息打印
     */
    static void PrintSimpleInfo(LPVOID parameter, DWORD processId = 0)
    {
        if (!parameter)
        {
            std::wcout << L"参数: 空指针" << std::endl;
            return;
        }

        ULONG_PTR paramValue = reinterpret_cast<ULONG_PTR>(parameter);
        auto      info       = Analyze(paramValue, processId);

        std::wcout << L"参数: 0x" << std::hex << paramValue << std::dec << L" (" << paramValue << L") - " << info.type
                   << std::endl;
    }

private:
    static AddressInfo AnalyzeX86(ULONG_PTR address)
    {
        AddressInfo info;

        if (address >= 0x00400000 && address <= 0x7FFFFFFF)
        {
            info.type = L"x86用户模式地址";
            if (address >= 0x00400000 && address <= 0x10000000)
            {
                info.description = L"可能为EXE/DLL代码段 (.text)";
            }
            else if (address >= 0x10000000 && address <= 0x70000000)
            {
                info.description = L"可能为DLL模块基址";
            }
            else
            {
                info.description = L"用户模式地址空间";
            }

            if ((address & 0xFFFF) == 0)
            {
                info.additionalInfo = L"64K对齐 - 可能为模块基址";
            }
        }
        else if (address >= 0x80000000 && address <= 0xFFFFFFFF)
        {
            info.type        = L"x86内核模式地址";
            info.description = L"警告: 用户模式无法访问";
        }
        else
        {
            info.type        = L"非标准地址范围";
            info.description = L"未知的内存区域";
        }

        return info;
    }

    static AddressInfo AnalyzeX64(ULONG_PTR address)
    {
        AddressInfo info;

        if (address >= 0x0000000000010000 && address <= 0x000007FFFFFFFFFF)
        {
            info.type = L"x64用户模式地址";
            if (address >= 0x0000000100000000 && address <= 0x0000000500000000)
            {
                info.description = L"可能为EXE/DLL代码段";
            }
            else
            {
                info.description = L"用户模式地址空间 (低128TB)";
            }

            if ((address & 0xFFFF) == 0)
            {
                info.additionalInfo = L"64K对齐 - 可能为模块基址";
            }
        }
        else if (address >= 0xFFFF080000000000 && address <= 0xFFFFFFFFFFFFFFFF)
        {
            info.type        = L"x64内核模式地址";
            info.description = L"警告: 用户模式无法访问";
        }
        else
        {
            info.type        = L"非标准地址范围";
            info.description = L"未知的内存区域";
        }

        return info;
    }

    static std::wstring GetSmallIntegerMeaning(ULONG_PTR value)
    {
        switch (value)
        {
            case 0:
                return L"NULL/FALSE";
            case 1:
                return L"TRUE";
            case 0xFFFFFFFF:
                return L"INVALID_HANDLE_VALUE/-1";
            case 0xDEADBEEF:
                return L"调试标记";
            case 0xBABABABA:
                return L"调试标记";
            default:
                return L"";
        }
    }
};

///////////////////////////////////////////////////////////////////////////////////
/// 远程线程执行器
///////////////////////////////////////////////////////////////////////////////////

class RemoteThreadExecutor
{
public:
    // /**
    //  * @brief 在远程进程中创建线程执行指定函数
    //  */
    // static bool Execute(DWORD processId, LPVOID functionAddress, LPVOID parameter = nullptr,
    //                     DWORD accessRights = PROCESS_ALL_ACCESS)
    // {
    //     /// 参数验证
    //     if (processId == 0)
    //     {
    //         LogError(L"无效的进程ID");
    //         return false;
    //     }
    //
    //     if (!functionAddress)
    //     {
    //         LogError(L"函数地址不能为空");
    //         return false;
    //     }
    //
    //     /// 打印调用信息
    //     PrintExecutionInfo(processId, functionAddress, parameter, accessRights);
    //
    //     /// 打开目标进程
    //     std::unique_ptr<std::remove_pointer<HANDLE>::type, decltype(&::CloseHandle)> hProcess(
    //             ::OpenProcess(accessRights, FALSE, processId), ::CloseHandle);
    //
    //     if (!hProcess)
    //     {
    //         LogError(L"无法打开进程 PID=" + std::to_wstring(processId), ::GetLastError());
    //         return false;
    //     }
    //
    //     LogInfo(L"成功打开目标进程句柄: 0x" + AddressToHexString(hProcess.get()));
    //
    //     HANDLE hRemoteThread = NULL;
    //     {
    //         /// 创建远程线程
    //         hRemoteThread = ::CreateRemoteThread(hProcess.get(), nullptr, 0,
    //                                              reinterpret_cast<LPTHREAD_START_ROUTINE>(functionAddress), parameter,
    //                                              0, nullptr);
    //
    //         if (!hRemoteThread)
    //         {
    //             LogError(L"创建远程线程失败", ::GetLastError());
    //             return false;
    //         }
    //     }
    //
    //     /// 等待线程完成
    //     bool success = WaitForThreadCompletion(hRemoteThread);
    //
    //     ::CloseHandle(hRemoteThread);
    //     return success;
    // }

    //////////////////////////////////////////////////////////////////


    /**
     * @brief 在远程进程中创建线程执行指定函数
     */
    static bool Execute(DWORD processId, LPVOID functionAddress, LPVOID parameter = nullptr,
                        DWORD accessRights = PROCESS_ALL_ACCESS)
    {
        bool success = false;

        /// 使用裸函数注入
        if (DLLInjector::InjectDLL(processId, Constants::FunctionAddresses::CALL_02))
        {
            std::wcout << L"裸函数注入成功" << std::endl;
            success = true;
        }
        else
        {
            std::wcerr << L"裸函数注入失败" << std::endl;
        }

        return success;
    }


    static bool ExecuteSafely(DWORD processId, LPVOID functionAddress, LPVOID parameter = nullptr)
    {
        // DWORD accessRights = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
        //         PROCESS_VM_WRITE | PROCESS_VM_READ;

        DWORD accessRights = PROCESS_ALL_ACCESS;
        return Execute(processId, functionAddress, parameter, accessRights);
    }

private:
    static void PrintExecutionInfo(DWORD processId, LPVOID functionAddress, LPVOID parameter, DWORD accessRights)
    {
        std::wcout << L"=== 远程线程调用信息 ===" << std::endl;
        std::wcout << L"目标进程PID: " << processId << std::endl;
        std::wcout << L"函数地址: 0x" << std::hex << functionAddress << std::dec << std::endl;
        std::wcout << L"参数: ";
        AddressAnalyzer::PrintSimpleInfo(parameter, processId);
        std::wcout << L"访问权限: 0x" << std::hex << accessRights << std::dec << std::endl;
        std::wcout << L"=========================" << std::endl;
    }

    static bool WaitForThreadCompletion(HANDLE hThread)
    {
        LogInfo(L"远程线程创建成功，等待执行完成...");

        DWORD waitResult = ::WaitForSingleObject(hThread, 5000); // 5秒超时

        switch (waitResult)
        {
            case WAIT_OBJECT_0:
                LogInfo(L"远程线程执行完成");
                return true;
            case WAIT_TIMEOUT:
                LogWarning(L"远程线程执行超时");
                return false;
            case WAIT_FAILED:
                LogError(L"等待远程线程失败", ::GetLastError());
                return false;
            default:
                LogError(L"等待远程线程返回未知状态: " + std::to_wstring(waitResult));
                return false;
        }
    }

    static void LogInfo(const std::wstring& message)
    {
        std::wcout << L"[EXECUTOR] " << message << std::endl;
    }

    static void LogWarning(const std::wstring& message)
    {
        std::wcout << L"[EXECUTOR WARNING] " << message << std::endl;
    }

    static void LogError(const std::wstring& message, DWORD errorCode = 0)
    {
        std::wcerr << L"[EXECUTOR ERROR] " << message;
        if (errorCode != 0)
        {
            std::wcerr << L", 错误代码: " << errorCode;
        }
        std::wcerr << std::endl;
    }

    static std::wstring AddressToHexString(LPVOID address)
    {
        wchar_t buffer[32];
        swprintf_s(buffer, L"%p", address);
        return buffer;
    }
};

///////////////////////////////////////////////////////////////////////////////////
/// 主应用程序
///////////////////////////////////////////////////////////////////////////////////

class RemoteInjectorApp
{
public:
    void Run()
    {
        Initialize();

        std::wcout << L"=== 远程线程注入示例 ===" << std::endl;

        if (InjectToTargetProcess())
        {
            std::wcout << L"=== 注入操作完成 ===" << std::endl;
        }
        else
        {
            std::wcerr << L"=== 注入操作失败 ===" << std::endl;
        }
    }

private:
    void Initialize()
    {
        setlocale(LC_ALL, "chs");
    }

    bool InjectToTargetProcess()
    {
        DWORD pid = ProcessFinder::GetTargetPID();
        if (pid == 0)
        {
            std::wcerr << L"错误: 无法获取有效的进程PID" << std::endl;
            return false;
        }

        // 选择要调用的函数
        LPVOID targetFunction = Constants::FunctionAddresses::CALL_02;
        LPVOID parameter      = reinterpret_cast<LPVOID>(123);

        return RemoteThreadExecutor::ExecuteSafely(pid, targetFunction, parameter);
    }
};

///////////////////////////////////////////////////////////////////////////////////
/// 程序入口点
///////////////////////////////////////////////////////////////////////////////////

int main()
{
    RemoteInjectorApp app;
    app.Run();
    return 0;
}
