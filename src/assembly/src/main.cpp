#include <stdio.h>

/// 这种内嵌的 必须新建活动平台 Win32
int main(int argc, char *argv[])
{
    {
        int a = 1; /// 栈上分配空间 局部变量
        int b = 2;
        _asm
        {
                ;
                mov a, 123 /// a=123
        }
        printf("a = %d\n", a);

        __asm
        {
                ; mov eax,126h /// == 
                mov eax,126h /// 126h=0x126
                ; mov dword ptr [b],eax /// ==
                mov b,eax
        }
        printf("a=%d b=%x %x\r\n", a, b, 0xA126);

        __asm
        {
                ;
                mov eax, 0
                mov al, 0x44332211 /// al 是 eax 的低 8 位（即 eax 的最低字节）
                mov a, eax
        }
        printf("AL=%08X Line=%d\r\n", a, __LINE__);


        __asm
        {
                ;
                mov eax, 0
                mov ah, 0x112331FF /// ah 是 eax 的高 8 位（即 eax 的高字节）。
                mov a, eax /// 这里尝试将 0x112331FF 移动到 ah 中，但 ah 只能容纳 8 位（1 字节）
        }
        printf("AH=%08X Line=%d\r\n", a, __LINE__);

        __asm
        {
                ;
                mov eax, 0
                mov ax, 0x44332211 /// ax 是 eax 的低 16 位（即 eax 的最低 2 字节）。
                mov a, eax
        }
        printf("AX=%08X Line=%d\r\n", a, __LINE__);


        char  VAL, VAH;
        short VAX;
        __asm
        {
                ;
                mov eax, 0
                mov eax, 44332211h ///  0x11,0x22,0x33,0x44
                mov a, eax
                mov VAL, al
                mov VAH, ah
                mov VAX, ax
        }
        printf("EAX=%08X  AL=%08X AH=%08X AX=%08X Line=%d\r\n", a, VAL, VAH, VAX, __LINE__);
    }

    {
        int a = 1; /// 栈上分配空间 局部变量
        int b = 2;

        /// ADD加法指令
        /// SUB减法指令
        __asm
        {
                ;
                mov a,100
                ; mov dword ptr [ebp-14h],64h
                mov ebx,123
                ; ebx,7Bh
                add a,ebx /// a=a+ebx
                ; add dword ptr [ebp-14h],ebx
        }
        printf("ADD Result=%d Line=%d\r\n", a, __LINE__);

        __asm
        {
                mov a, 200
                ; mov         dword ptr [ebp-14h],0C8h
                mov ebx, 123
                ; mov         ebx,7Bh
                sub a, ebx /// a=a-ebx SUB sub
                ; sub         dword ptr [ebp-14h],ebx
        }
        printf("SUB Result=%d Line=%d\r\n", a, __LINE__);
    }

    getchar();
    return 0;
}
