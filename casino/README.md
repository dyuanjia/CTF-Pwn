# Casino

## Description:

> Welcome to edu casino.

> Hacker don't need luck :P

## Solution:

Since this problem involves GOT hijacking, I need to first find a way to replace the GOT entry. This can be done by changing the number, where I can control the index of guess and its value. The index will point to the address of the GOT table, and the value will be the address of my shellcode.

Using gdb, the address of `puts@got.plt` is `0x602020`, and the address of guess is `0x6020d0`. The offset is then -43. Since the address is 8 bytes and int is 4 bytes, the address need 2 rounds to be completely replaced.

Next, I need to trigger the final puts call. Since the address of seed (`0x602100`) is right next to name (`0x6020f0`), it can be replaced as a predetermined number by overflowing name, and the resultant lottery numbers will be the same.

Finally, I need to inject my shellcode, and it can be placed at the name buffer. Its address is `0x6020f0`, but I need to pad it so that the start of the shellcode is after seed.

Once the final puts is called, RIP will be redirected to `0x602110` (6299888 in decimal), and spawn a shell.

`FLAG{0verf1ow_1n_ev3rywhere!}`
