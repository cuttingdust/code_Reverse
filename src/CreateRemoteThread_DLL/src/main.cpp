#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h> // EnumProcessModules 和其他进程状态函数
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

        /// 先打印原始机器码用于调试
        std::wcout << L"原始机器码: ";
        for (size_t j = 0; j < code.size(); j++)
        {
            std::wcout << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<int>(code[j]) << L" ";
        }
        std::wcout << std::dec << std::endl;
        std::wcout << L"------------------------" << std::endl;

        /// 逐条指令解析
        size_t i = 0;
        while (i < code.size())
        {
            std::wcout << L"地址 0x" << std::hex << std::setw(2) << std::setfill(L'0') << i << L": ";

            /// 检查当前指令
            if (code[i] == 0x6A && i + 1 < code.size())
            {
                /// push imm8
                std::wcout << L"push " << static_cast<int>(code[i + 1]) << L"  \t// 机器码: 6A " << std::hex
                           << std::setw(2) << static_cast<int>(code[i + 1]) << std::dec;
                i += 2;
            }
            else if (code[i] == 0xB8 && i + 4 < code.size())
            {
                /// mov eax, imm32 - 正确的小端序解析
                DWORD value = code[i + 1] | (code[i + 2] << 8) | (code[i + 3] << 16) | (code[i + 4] << 24);
                std::wcout << L"mov eax, 0x" << std::hex << value << L"\t// 机器码: B8 " << std::hex << std::setw(2)
                           << static_cast<int>(code[i + 1]) << L" " << std::setw(2) << static_cast<int>(code[i + 2])
                           << L" " << std::setw(2) << static_cast<int>(code[i + 3]) << L" " << std::setw(2)
                           << static_cast<int>(code[i + 4]) << std::dec;
                i += 5;
            }
            else if (code[i] == 0xFF && i + 1 < code.size() && code[i + 1] == 0xD0)
            {
                /// call eax
                std::wcout << L"call eax\t// 机器码: FF D0";
                i += 2;
            }
            else if (code[i] == 0x83 && i + 2 < code.size() && code[i + 1] == 0xC4)
            {
                /// add esp, imm8
                std::wcout << L"add esp, " << static_cast<int>(code[i + 2]) << L"  \t// 机器码: 83 C4 " << std::hex
                           << std::setw(2) << static_cast<int>(code[i + 2]) << std::dec;
                i += 3;
            }
            else if (code[i] == 0xC3)
            {
                /// ret
                std::wcout << L"ret\t\t// 机器码: C3";
                i += 1;
            }
            else
            {
                /// 未知指令
                std::wcout << L"未知指令: 0x" << std::hex << std::setw(2) << static_cast<int>(code[i]) << std::dec;
                i += 1;
            }

            std::wcout << std::endl;
        }

        std::wcout << L"------------------------" << std::endl;
        std::wcout << L"总代码大小: " << code.size() << L" 字节" << std::endl;

        /// 验证实际替换的值
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
            return !isWow64; /// 不是WOW64进程就是64位进程
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

class RemoteFunctionCaller
{
public:
    /**
     * @brief 在远程进程中调用指定的DLL函数
     */
    static bool CallRemoteFunction(DWORD processId, const std::wstring& dllName, const std::string& functionName)
    {
        HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!hProcess)
        {
            std::wcerr << L"无法打开进程" << std::endl;
            return false;
        }

        bool success = false;

        // 1. 在远程进程中获取模块句柄
        HMODULE hRemoteModule = GetRemoteModuleHandle(hProcess, dllName);
        if (!hRemoteModule)
        {
            std::wcerr << L"DLL未在目标进程中加载: " << dllName << std::endl;
            ::CloseHandle(hProcess);
            return false;
        }

        std::wcout << L"找到远程模块: 0x" << std::hex << hRemoteModule << std::dec << std::endl;

        // 2. 计算函数在远程进程中的地址
        DWORD remoteFunctionAddr = CalculateRemoteFunctionAddress(hProcess, dllName, functionName, hRemoteModule);
        if (remoteFunctionAddr == 0)
        {
            std::wcerr << L"无法计算远程函数地址" << std::endl;
            ::CloseHandle(hProcess);
            return false;
        }

        std::wcout << L"远程函数地址: 0x" << std::hex << remoteFunctionAddr << std::dec << std::endl;

        // 3. 创建远程线程调用函数
        HANDLE hThread = ::CreateRemoteThread(
                hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteFunctionAddr), NULL, 0, NULL);
        if (hThread)
        {
            ::WaitForSingleObject(hThread, 10000);

            DWORD exitCode = 0;
            ::GetExitCodeThread(hThread, &exitCode);

            std::wcout << L"远程函数调用完成，返回值: 0x" << std::hex << exitCode << std::dec << std::endl;

            ::CloseHandle(hThread);
            success = true;
        }
        else
        {
            std::wcerr << L"创建远程线程失败: " << ::GetLastError() << std::endl;
        }

        ::CloseHandle(hProcess);
        return success;
    }

private:
    /**
     * @brief 获取远程进程中的模块句柄
     */
    static HMODULE GetRemoteModuleHandle(HANDLE hProcess, const std::wstring& moduleName)
    {
        HMODULE hModules[1024];
        DWORD   cbNeeded;

        if (::EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded))
        {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
            {
                wchar_t szModuleName[MAX_PATH];
                if (::GetModuleFileNameExW(hProcess, hModules[i], szModuleName, MAX_PATH))
                {
                    // 提取文件名
                    std::wstring fullPath(szModuleName);
                    size_t       lastSlash = fullPath.find_last_of(L"\\/");
                    std::wstring fileName =
                            (lastSlash != std::wstring::npos) ? fullPath.substr(lastSlash + 1) : fullPath;

                    if (_wcsicmp(fileName.c_str(), moduleName.c_str()) == 0)
                    {
                        return hModules[i];
                    }
                }
            }
        }

        return NULL;
    }

    /**
     * @brief 计算函数在远程进程中的地址
     */
    static DWORD CalculateRemoteFunctionAddress(HANDLE hProcess, const std::wstring& dllName,
                                                const std::string& functionName, HMODULE hRemoteModule)
    {
        // 1. 在当前进程加载相同的DLL
        HMODULE hLocalModule = ::LoadLibraryW(dllName.c_str());
        if (!hLocalModule)
        {
            std::wcerr << L"无法在本地加载DLL: " << dllName << std::endl;
            return 0;
        }

        // 2. 获取本地函数地址
        FARPROC localFunction = ::GetProcAddress(hLocalModule, functionName.c_str());
        if (!localFunction)
        {
            std::wcerr << L"找不到函数: " << functionName.c_str() << std::endl;
            ::FreeLibrary(hLocalModule);
            return 0;
        }

        // 3. 计算函数偏移量
        DWORD functionOffset = (DWORD)localFunction - (DWORD)hLocalModule;

        // 4. 计算远程函数地址
        DWORD remoteFunctionAddr = (DWORD)hRemoteModule + functionOffset;

        ::FreeLibrary(hLocalModule);

        return remoteFunctionAddr;
    }
};


//////////////////////////////////////////////////////////////////////////////////
/// DLL注入器
///////////////////////////////////////////////////////////////////////////////////

class ReflectiveDLLInjector
{
public:
    /**
     * @brief 执行反射DLL注入
     * @param processId 目标进程ID
     * @param dllPath DLL文件路径
     * @param customEntryPoint 自定义入口点（可选）
     * @return 是否成功
     */
    static bool ReflectiveInject(DWORD processId, const std::wstring& dllPath, DWORD customEntryPoint = 0)
    {
        // 1. 读取DLL文件到内存
        std::vector<BYTE> dllData = ReadFileToMemory(dllPath);
        if (dllData.empty())
        {
            return false;
        }

        // 2. 打开目标进程
        HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!hProcess)
        {
            return false;
        }

        // 3. 执行反射注入
        bool success = PerformReflectiveInjection(hProcess, dllData, customEntryPoint);

        ::CloseHandle(hProcess);
        return success;
    }

private:
    /**
     * @brief 读取文件到内存
     */
    static std::vector<BYTE> ReadFileToMemory(const std::wstring& filePath)
    {
        HANDLE hFile = ::CreateFile(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            return {};
        }

        DWORD             fileSize = ::GetFileSize(hFile, NULL);
        std::vector<BYTE> buffer(fileSize);

        DWORD bytesRead = 0;
        BOOL  success   = ::ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL);

        ::CloseHandle(hFile);

        return success ? buffer : std::vector<BYTE>();
    }

    /**
     * @brief 执行反射注入
     */
    static bool PerformReflectiveInjection(HANDLE hProcess, const std::vector<BYTE>& dllData, DWORD customEntryPoint)
    {
        // 1. 在远程进程分配内存（足够存放DLL数据）
        LPVOID remoteBase =
                ::VirtualAllocEx(hProcess, NULL, dllData.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteBase)
        {
            return false;
        }

        // 2. 写入DLL数据到远程内存
        SIZE_T bytesWritten = 0;
        if (!::WriteProcessMemory(hProcess, remoteBase, dllData.data(), dllData.size(), &bytesWritten))
        {
            ::VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
            return false;
        }

        // 3. 计算入口点地址
        DWORD entryPoint = CalculateEntryPoint(remoteBase, dllData, customEntryPoint);
        if (entryPoint == 0)
        {
            ::VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
            return false;
        }

        // 4. 创建远程线程执行入口点
        HANDLE hThread = ::CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)entryPoint,
                                              remoteBase, // 参数：DLL基址
                                              0, NULL);

        bool success = false;
        if (hThread)
        {
            // 等待线程完成初始化
            ::WaitForSingleObject(hThread, 10000);

            DWORD exitCode = 0;
            ::GetExitCodeThread(hThread, &exitCode);

            ::CloseHandle(hThread);
            success = (exitCode != 0);
        }

        // 注意：这里不释放内存，因为DLL需要在目标进程中持续存在
        return success;
    }

    /**
     * @brief 计算入口点地址
     */
    static DWORD CalculateEntryPoint(LPVOID remoteBase, const std::vector<BYTE>& dllData, DWORD customEntryPoint)
    {
        // 解析PE头
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dllData.data();
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return 0;
        }

        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pDosHeader + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        {
            return 0;
        }

        // 如果指定了自定义入口点，使用它
        if (customEntryPoint != 0)
        {
            return (DWORD)remoteBase + customEntryPoint;
        }

        // 否则使用标准的DLL入口点
        DWORD entryPointRVA = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
        return (DWORD)remoteBase + entryPointRVA;
    }
};


//////////////////////////////////////////////////////////////////
/// 通过路径

class DLLInjector
{
public:
    static bool InjectDLL(DWORD processId, const std::wstring& dllPath)
    {
        std::wcout << L"开始注入 DLL: " << dllPath << L" 到进程 PID=" << processId << std::endl;

        /// 验证DLL文件是否存在
        if (!ValidateDLLPath(dllPath))
        {
            return false;
        }

        /// 验证目标进程架构
        if (!ValidateProcessArchitecture(processId))
        {
            return false;
        }

        /// 执行注入
        return PerformInjection(processId, dllPath);
    }

private:
    static bool ValidateDLLPath(const std::wstring& dllPath)
    {
        DWORD attributes = ::GetFileAttributes(dllPath.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES)
        {
            std::wcerr << L"DLL文件不存在: " << dllPath << std::endl;
            return false;
        }

        if (attributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            std::wcerr << L"路径指向目录而不是文件: " << dllPath << std::endl;
            return false;
        }

        std::wcout << L"DLL文件验证成功" << std::endl;
        return true;
    }

    static bool ValidateProcessArchitecture(DWORD processId)
    {
        bool isTarget64Bit  = ArchitectureDetector::IsTargetProcess64Bit(processId);
        bool isCurrent64Bit = ArchitectureDetector::IsCurrentProcess64Bit();

        std::wcout << L"目标进程: " << (isTarget64Bit ? L"64位" : L"32位") << L", 当前进程: "
                   << (isCurrent64Bit ? L"64位" : L"32位") << std::endl;

        /// 32位进程不能注入64位进程
        if (!isCurrent64Bit && isTarget64Bit)
        {
            std::wcerr << L"错误: 32位进程不能注入64位进程" << std::endl;
            return false;
        }

        return true;
    }

    static bool PerformInjection(DWORD processId, const std::wstring& dllPath)
    {
        HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!hProcess)
        {
            DWORD error = ::GetLastError();
            std::wcerr << L"无法打开进程 (错误: " << error << L")" << std::endl;

            if (error == ERROR_ACCESS_DENIED)
            {
                std::wcerr << L"需要管理员权限" << std::endl;
            }
            return false;
        }

        /// 计算需要的缓冲区大小
        SIZE_T bufferSize = (dllPath.size() + 1) * sizeof(wchar_t);

        /// 分配内存
        LPVOID remoteMem = ::VirtualAllocEx(hProcess, NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteMem)
        {
            std::wcerr << L"无法分配远程内存: " << ::GetLastError() << std::endl;
            ::CloseHandle(hProcess);
            return false;
        }

        std::wcout << L"远程内存分配成功: 0x" << std::hex << remoteMem << std::dec << std::endl;

        /// 写入DLL路径
        SIZE_T bytesWritten = 0;
        BOOL   writeResult  = ::WriteProcessMemory(hProcess, remoteMem, dllPath.c_str(), bufferSize, &bytesWritten);

        if (!writeResult || bytesWritten != bufferSize)
        {
            std::wcerr << L"写入内存失败: " << ::GetLastError() << std::endl;
            ::VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            ::CloseHandle(hProcess);
            return false;
        }

        std::wcout << L"成功写入 " << bytesWritten << L" 字节到远程内存" << std::endl;

        /// 获取 LoadLibraryW 地址
        HMODULE                hKernel32 = ::GetModuleHandle(L"kernel32.dll");
        LPTHREAD_START_ROUTINE pLoadLibraryW =
                reinterpret_cast<LPTHREAD_START_ROUTINE>(::GetProcAddress(hKernel32, "LoadLibraryW"));

        if (!pLoadLibraryW)
        {
            std::wcerr << L"无法获取 LoadLibraryW 地址" << std::endl;
            ::VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            ::CloseHandle(hProcess);
            return false;
        }

        /// 创建远程线程
        HANDLE hThread = ::CreateRemoteThread(hProcess, NULL, 0, pLoadLibraryW, remoteMem, 0, NULL);
        bool   success = false;
        if (hThread)
        {
            std::wcout << L"远程线程创建成功，等待DLL加载..." << std::endl;

            DWORD waitResult = ::WaitForSingleObject(hThread, INFINITE); /// 10秒超时
            if (waitResult == WAIT_OBJECT_0)
            {
                DWORD exitCode = 0;
                if (GetExitCodeThread(hThread, &exitCode) && exitCode != 0)
                {
                    std::wcout << L"DLL注入成功! 模块句柄: 0x" << std::hex << exitCode << std::dec << std::endl;
                    success = true;
                }
                else
                {
                    std::wcerr << L"DLL加载失败，LoadLibrary返回NULL" << std::endl;
                }
            }
            CloseHandle(hThread);
        }
        else
        {
            DWORD error = ::GetLastError();
            std::wcerr << L"创建远程线程失败: " << error << std::endl;

            if (error == 5) // ERROR_ACCESS_DENIED
            {
                std::wcerr << L"提示: 可能需要以管理员身份运行" << std::endl;
            }
        }

        // 清理
        ::VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        ::CloseHandle(hProcess);

        return success;
    }
};

namespace Constants
{
    const std::wstring TARGET_PROCESS_NAME = L"DBG_TOOL_x64_REGISTER_TEST.exe";
    const std::wstring TARGET_WINDOW_TITLE = LR"(DBG_TOOL_x64_REGISTER_TEST.exe)";
    const std::wstring INJECT_DLL_PATH     = LR"(DBG_TOOL_x86_MFC_DLL.dll)";
    // const std::wstring INJECT_DLL_PATH = LR"(MFCLibrary.dll)";
    const DWORD FALLBACK_PID = 23000;

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
        std::wcout << L"=== 开始注入过程 ===" << std::endl;

        /// 获取当前目录
        wchar_t buffer[MAX_PATH] = { 0 };
        DWORD   result           = ::GetCurrentDirectory(MAX_PATH, buffer);
        if (result == 0 || result > MAX_PATH)
        {
            std::wcerr << L"获取当前目录失败: " << ::GetLastError() << std::endl;
            return false;
        }

        /// 构建完整DLL路径
        std::wstring dllPath = std::wstring(buffer) + L"\\" + Constants::INJECT_DLL_PATH;
        std::wcout << L"DLL路径: " << dllPath << std::endl;

        /// 检查文件是否存在
        DWORD fileAttr = ::GetFileAttributes(dllPath.c_str());
        if (fileAttr == INVALID_FILE_ATTRIBUTES)
        {
            std::wcerr << L"DLL文件不存在: " << dllPath << std::endl;
            return false;
        }
        std::wcout << L"DLL文件存在" << std::endl;

        /// 执行注入
        if (DLLInjector::InjectDLL(processId, dllPath))
        {
            std::wcout << L"DLL注入成功!" << std::endl;
            return true;
        }
        else
        {
            std::wcerr << L"DLL注入失败" << std::endl;
            return false;
        }

        // // 自定义入口点：
        // // 调用DLL中的自定义函数（而不是DllMain）
        // bool success = ReflectiveDLLInjector::ReflectiveInject(1234,             // 目标进程ID
        //                                                        L"C:\\MyDLL.dll", // DLL路径
        //                                                        0x1000            // 自定义函数在DLL中的偏移
        // );
        //
        // // 基本反射注入 - 调用DllMain
        // bool success = ReflectiveDLLInjector::ReflectiveInject(1234,             // 目标进程ID
        //                                                        L"C:\\MyDLL.dll", // DLL路径
        //                                                        0                 // 使用标准入口点(DllMain)
        // );

        // 2. 然后调用 test 函数
        // std::wcout << L"准备调用 test 函数..." << std::endl;
        //
        // bool functionCalled = RemoteFunctionCaller::CallRemoteFunction(processId, L"DBG_TOOL_x86_MFC_DLL.dll", "test");
        //
        // if (functionCalled)
        // {
        //     std::wcout << L"test 函数调用成功!" << std::endl;
        // }
        // else
        // {
        //     std::wcerr << L"test 函数调用失败!" << std::endl;
        // }

        // return functionCalled;
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

        /// 选择要调用的函数
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
