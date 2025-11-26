cmake_minimum_required(VERSION 3.12)

# 使用 vcpkg 工具链文件 Warning  工具连设置必须是在project 前面
set(CMAKE_TOOLCHAIN_FILE $ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake CACHE STRING "Vcpkg toolchain file")
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

project(XWindowsReserve)

# 查找 MASM 编译器
if(MSVC)
    enable_language(ASM_MASM)
endif()

set(CMAKE_INCLUDE_CURRENT_DIR ON)
# if(MSVC)
 # set(CMAKE_GENERATOR_PLATFORM x64)
# endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# C++23
# C++26. CMake 3.25 and later recognize 26 as a valid value, no version has support for any compiler.
set(CMAKE_CXX_STANDARD 23) 
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_BUILD_TYPE Debug)

# OpenMP
find_package(OpenMP)
message("OpenMP_FOUND = ${OpenMP_FOUND}")

if(OpenMP_FOUND)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
endif()

# MFC
find_package(MFC)
message("MFC_FOUND = ${MFC_FOUND}")

if(MFC_FOUND)
# 1: static MFC library, 2: shared MFC library
set(CMAKE_MFC_FLAG 2)
endif()

#==================================================================================#

message(STATUS "CMAKE_CXX_COMPILER = ${CMAKE_CXX_COMPILER}")

# 外部依赖项
set(DPS_INCLUDES)
set(DPS_TARGETS)
set(DPS_LIBRARYS)

# 资源文件

# #图标
set(RC_FILE)

# #qrc 文件
set(QRC_SOURCE_FILES)

# 忽略特定库
if(MSVC)
SET(CMAKE_EXE_LINKER_FLAGS /NODEFAULTLIB:"libcmt.lib;libc.lib")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(CommonTools)

###########################################
add_subdirectory(MessageBox)
add_subdirectory(sizeof_windows)
add_subdirectory(FindWindow)
add_subdirectory(GetWindowThreadProcess)
add_subdirectory(ReadProcessMemory)
add_subdirectory(ReadProcessMemory_basepointer)
add_subdirectory(WriteProcessMemory)
add_subdirectory(CreateRemoteThread)
add_subdirectory(CreateRemoteThread_VirtualAllocEx)
###########################################
if(CMAKE_GENERATOR_PLATFORM STREQUAL "x64")
add_subdirectory(assembly_x64)
elseif(CMAKE_GENERATOR_PLATFORM STREQUAL "Win32")
add_subdirectory(assembly)
endif()
add_subdirectory(DBG_TOOL_CALL_RET_TEST)
add_subdirectory(DBG_TOOL_VARIABLE_TYPE_TEST)
add_subdirectory(DBG_TOOL_x86_CALL_TEST)
add_subdirectory(DBG_TOOL_x64_CALL_TEST)
add_subdirectory(DBG_TOOL_x64_IF_TEST)
add_subdirectory(DBG_TOOL_x86_WHILE_TEST)
add_subdirectory(DBG_TOOL_x64_REGISTER_TEST) # 错误 注入器现在只能注入x86的
add_subdirectory(DBG_TOOL_x86_MFC_DLL)


# # 拷贝assert目录到输出目录
# set(ASSERT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/assert)
# file(COPY ${ASSERT_PATH} DESTINATION ${OUT_RUN_PATH})
