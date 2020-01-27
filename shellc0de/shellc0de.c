#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

void init()
{
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
}

int main()
{

    //init();

    char shellcode[0x100];
    memset(shellcode, 0xcc, sizeof(shellcode));

    puts("shellcode >");
    read(0, shellcode, 0x100);

    for (int i = 0; i < 0x100; ++i)
    {
        puts(i);
        printf("code: %s", shellcode[i]);
        if (shellcode[i] == ' 00' || shellcode[i] == ' 05' || shellcode[i] == ' 0f')
        {
            puts("Oops");
            _exit(-1);
        }
    }

    void (*hello)() = shellcode;

    hello();

    return 0;
}
