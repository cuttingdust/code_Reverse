.386                           ; 指定 32 位模式
.model flat, stdcall
option casemap:none		       ; 指明大小写敏感
; ### x64 平台的时候注释掉

.code
	;需要在x64环境编译
	;分号表示注释
	;不能用//来注释


; 检查平台
ifdef _WIN64                 ; 如果是 64 位平台
    ; 64 位特定代码
    mycall proc
        mov rax, 1111122h   ; 64 位寄存器
        ret
    mycall endp

    myadd1 proc ;proc表示一个函数的开始{
		mov rax,12345678h
		ret ;return
	myadd1 endp ;endp表示一个函数的结束}

else      
    ; 否则是 32 位平台
    ; 32 位特定代码
    mycall proc
        mov eax, 1111122h   ; 32 位寄存器
        ret
    mycall endp

    myadd1 proc
        ;xor edx, edx             ; 清除 edx 寄存器
	    mov eax, 12345678h
		ret
	myadd1 endp 
endif

end