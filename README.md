# CTF Binary Exploitation

Some questions I did.

---

## EDU-CTF Final 2020 (01/2020)

### Impossible

- `abs()` bypass in C
- ROP

### nonono

- full protection
- index out-of-bound
- file stream overwrite

### EasyROP

- buffer overflow without leak
- ROP to orw

### BlueNote

- windows
- ROP to orw

### re-alloc

- use after free
- heap overlap
- GOT hijacking

## NCTU Secure Programming (12/2019)

### shellc0de

- length limit: 0x100
- filtered characters: `\x00` `\x05` `\x0F`
  -- no syscall (`\x0F\x05`)

### bof

- classic buffer overflow
- backdoor function provided

### how2orw

- amd64 shellcode
- seccomp: syscall limited to open, read, write

### Casino

- amd64 shellcode
- GOT hijacking

### Casino++

- NX
- GOT hijacking
- ret2libc

### ROP

- classic ROP
- buffer overflow
- NX, no canary

### ret2plt

- buffer overflow
- NX, no PIE

### ret2libc

- buffer overflow
- bypass ASLR

### EDU 2019 election

- ret2csu
- full protection

### UAF

- libc-2.23
- classic use after free

### Note

- libc-2.23
- full protection
- no overflow
- fast bin attack / double free
- one gadget

### Note++

- libc-2.23
- off-by-one null byte
- double free
- heap overlap

### T-Note

- libc-2.27
- Tcache: easier fast bin attack

## picoCTF 2019 (10/2019)

### handy-shellcode

- linux x86 shellcode
