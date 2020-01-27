# Casino++

## Description:

> Welcome to edu casino++ !

> I think it is still pwnable even if the NX protection was enabled.

> Pwn it again plz :P

## Solution:

Same as casino, I can control RIP by hijacking `puts@got`. This time, instead of pointing it to the address of name, I point it to `0x40095b` (the push instruction at the start of casino), so that I can continue running the program while keeping the **16-byte alignment**.

To open a shell, I first need to leak the address of `__libc_start_main()` so that I can calculate the base address. I noticed that the srand function will put the value of seed into RDI (first argument). Since I can control the value of seed by overflowing name, I can control RDI. By putting the address of `__libc_start_main()`'s GOT entry in seed, and changing `srand@got` to point to `printf@plt+6`, srand will resolve to printf, and gets called with the address of `__libc_start_main()` as the first argument. Its mapped address will be printed and I can then calculate the base address, and the address of system.

Next, I need to change `srand@got` again to point at the calculated system address. I also need to change seed to point at the string `/bin/sh` for system to work. I included the string `/bin/sh` in my initial overflow payload for name, at address `0x602110`.

Finally, after everything is changed properly, when the program reach srand, it will call `system("/bin/sh")`, and I can get the flag.

`FLAG{Y0u_pwned_me_ag4in!_Pwn1ng_n3v3r_di4_!}`
