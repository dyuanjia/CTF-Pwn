# BlueNote

## Description:

> 不是有上 windows，那就出 windows pwn 啊。 by 非修課生

## Solution:

This is a menu question.

After creating 5 notes, we can show the 6th note, which can be used to leak canary, code address, kernel32 address and ntdll address.

Also, after creating 5 notes, we can edit the 6th note to overwrite return address.

Finally, use ROP chain to orw.

`FLAG{how2yuawn_how2win_dadada}`
