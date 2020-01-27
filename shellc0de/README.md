# shellc0de

## Description:

> Shellcoding is fun :D

## Solution:

First, I generate the shellcode using pwntools' shellcraft.

Since `\x00` `\x05` `\x0F` are being filtered, I encode these characters with pwntools' encoder.
