# coolplayer

## Solution:

coolplayer.exe allows a .m3u file as input, so such a file can contain a shellcode payload to achieve buffer overflow.

After opening it in immunity debugger, I ran `!mona jmp -r esp`. The results are 2 `push esp; ret` instruction sets. However, the address of both of these, `0x004061da` and `0x0040e226`, have `\x00` in them. `\x00` will cause the payload to be truncated, so I can't use the `jmp esp` trick and append the shellcode after these eip address.

However, I realized that the ebx register contains the pointer to the start of my payload. Thus, I ran `!mona jmp -r ebx`, and got several addresses to call ebx. I put one of these addresses at the eip location, and put the shellcode at the beginning of the payload instead. This payload successfully caused the shellcode to execute.

The shellcode used here will simply open a message box.
