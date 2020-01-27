# how2orw

## Description:

> Shellcoding is fun :D

## Solution:

Do the following, either with assembly or pwntools:

1. open("/home/orw/flag")
2. read(fd, rsp, 0x50)
3. write(1, rsp, 0x50)
