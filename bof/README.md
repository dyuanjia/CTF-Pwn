# bof

## Description:

> Buffer Overflow.

## Solution:

For this question, simply hijack the return address and jump to the provide backdoor function.

To get the address of that function:

```console
root@kali:~# objdump -d ./bof
```

However, when using the function address straight away, the program will crash with a segmentation fault at a [MOVAPS](http://c9x.me/x86/html/file_module_x86_id_180.html) instruction. This is because:

> When the source or destination operand is a memory operand, the operand must be aligned on a 16-byte boundary or a general-protection exception (#GP) is generated.

By overflowing the return address, the program will jump to another function without pushing its return address (8 bytes) onto the stack. This will cause stack misalignment. To bypass this, instead of jumping to the start of the function (`push rbp`), jump to the instruction after it.
