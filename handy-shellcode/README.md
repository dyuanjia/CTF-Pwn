# handy-shellcode

## Description:

> This program executes any shellcode that you give it. Can you spawn a shell and use that to read the flag.txt?

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFSIZE 148
#define FLAGSIZE 128

void vuln(char *buf){
  gets(buf);
  puts(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);

  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  char buf[BUFSIZE];

  puts("Enter your shellcode:");
  vuln(buf);

  puts("Thanks! Executing now...");

  ((void (*)())buf)();


  puts("Finishing Executing Shellcode. Exiting now...");

  return 0;
}

```

## Solution:

Using the shellcode:

```console
root@kali:~# (python exploit.py ; cat) | /problems/handy-shellcode_0/vuln
```

Without cat, the shell will have no input and simply exits.

`picoCTF{h4ndY_d4ndY_sh311c0d3_5843b402}`
