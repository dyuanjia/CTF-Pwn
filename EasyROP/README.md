# EasyROP

## Description:

> ROP is tooooo ez~

## Solution:

Buffer overflow without leak.

Use `strcpy()` to copy libc gadget to bss.

`read_GOT+0x20 = int 0x80`: we can use `strcpy()` to partially overwrite this gadget to `int 0x80` and call arbitrary syscall.

`popal` is a very useful gadget.

Finally, use ROP chain to orw.

`FLAG{Congratulations!happy New Year!}`
