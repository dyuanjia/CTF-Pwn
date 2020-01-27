# ROP

## Description:

> ROP~~~ :D

## Solution:

For this question, the binary is statically linked, therefore there are a lot of ROP gadgets available.

To find the address of ROP gadgets with filter:

```console
root@kali:~# ROPgadget --binary ./rop --only "pop|ret"
```

Using the gadgets, build a ROP chain to call `execve("/bin/sh", 0, 0)`.
