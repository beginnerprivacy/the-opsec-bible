---
search:
  exclude: true
---
# Sunshine CTF 2017 Prepared

## Downloading the binary file 
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/3/prep]
    → wget https://github.com/guyinatuxedo/nightmare/raw/master/modules/09-bad_seed/sunshinectf17_prepared/prepared
    --2021-03-07 13:57:41--  https://github.com/guyinatuxedo/nightmare/raw/master/modules/09-bad_seed/sunshinectf17_prepared/prepared
    Loaded CA certificate '/etc/ssl/certs/ca-certificates.crt'
    Resolving github.com (github.com)... 140.82.121.3
    Connecting to github.com (github.com)|140.82.121.3|:443... connected.
    HTTP request sent, awaiting response... 302 Found
    Location: https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/09-bad_seed/sunshinectf17_prepared/prepared [following]
    --2021-03-07 13:57:41--  https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/09-bad_seed/sunshinectf17_prepared/prepared
    Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.110.133, 185.199.111.133, ...
    Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 12888 (13K) [application/octet-stream]
    Saving to: ‘prepared’
    
    prepared                            100%[================================================================>]  12.59K  --.-KB/s    in 0.001s
    
    2021-03-07 13:57:42 (16.2 MB/s) - ‘prepared’ saved [12888/12888]
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/3/prep]
    → file prepared
    prepared: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=9cd9483ed0e7707d3addd2de44da60d2575652fb, not stripped
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/3/prep]
    → chmod +x prepared
    
    

` ![]()

## Solution 

So let's first run pwn checksec on the binary before executing it to see what it does:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/3/prep]
    → pwn checksec prepared
    [*] '/home/nothing/binexp/3/prep/prepared'
        Arch:     amd64-64-little
        RELRO:    Full RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      PIE enabled
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/3/prep]
    → ./prepared
    0 days without an incident.
    123
    Well that didn't take long.
    You should have used 63.
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/3/prep]
    → ./prepared
    0 days without an incident.
    63
    Well that didn't take long.
    You should have used 67.
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/3/prep]
    → ./prepared
    0 days without an incident.
    67
    Well that didn't take long.
    You should have used 24.
    
    

Here we see that this is a 64 bit binary with everything enabled (full relro, canary, nx and pie). It prompts us for input to make us guess a random number, let's take a look at it in ghidra: 

![](2.png)

And here we get the following code for the main function:
    
    
    undefined8 main(void)
    
    {
      int iVar1;
      time_t tVar2;
      FILE *__stream;
      char *pcVar3;
      long in_FS_OFFSET;
      uint local_464;
      char local_448 [64];
      char local_408 [512];
      char local_208 [504];
      long local_10;
      
      local_10 = *(long *)(in_FS_OFFSET + 0x28);
      tVar2 = time((time_t *)0x0);
      srand((uint)tVar2);
      local_464 = 0;
      while ((int)local_464 < 0x32) {
        iVar1 = rand();
        printf("%d days without an incident.\n",(ulong)local_464);
        sprintf(local_208,"%d",(ulong)(uint)(iVar1 % 100));
        __isoc99_scanf(" %10s",local_408);
        strtok(local_408,"\n");
        iVar1 = strcmp(local_208,local_408);
        if (iVar1 != 0) {
          puts("Well that didn\'t take long.");
          printf("You should have used %s.\n",local_208);
                        /* WARNING: Subroutine does not return */
          exit(0);
        }
        local_464 = local_464 + 1;
      }
      puts("How very unpredictable. Level Cleared");
      __stream = fopen("flag.txt","r");
      while( true ) {
        pcVar3 = fgets(local_448,0x32,__stream);
        if (pcVar3 == (char *)0x0) break;
        printf("%s",local_448);
      }
      if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                        /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return 0;
    }
    

Just like in the previous 2 challenges, time is declared as a seed with the srand function, and then it uses **rand** to generate values that are modded by 100 (value%100), and we have to guess it in a loop 50 times, So in order to guess the rand number 50 times in a row, this is based off of the seed, and since the seed is simply the current time, we can write a simple C program to get the seed and generate the numbers it expects: 
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/3/prep]
    → vim exploit.c
    
    
    
    
    ****#include <****stdio.h>
    #include <****stdlib.h>
    #include <****time.h>
    #include <****string.h>
    
    int main(void)    
    {
        int i, out;
        time_t var0 = time(NULL);
        srand(var0);
    
        for (i = 0; i < 50; i++)
        {
            out = rand() % 100;
            printf("%d\n", out);
        }
        
        return 0;
    }
    
    

Here we compile it with gcc:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/3/prep]
    → gcc exploit.c -o exploit
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/3/prep]
    → ./exploit
    83
    93
    92
    55
    70
    63
    4
    64
    54
    21
    87
    42
    77
    17
    74
    86
    57
    18
    72
    7
    52
    76
    46
    78
    81
    83
    19
    55
    20
    14
    21
    55
    59
    13
    10
    81
    76
    67
    46
    83
    88
    33
    77
    17
    2
    3
    4
    59
    21
    28
    
    

Now let's pipe it into the stdin of our binary:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/3/prep]
    → ./exploit | ./prepared
    0 days without an incident.
    1 days without an incident.
    2 days without an incident.
    3 days without an incident.
    4 days without an incident.
    5 days without an incident.
    6 days without an incident.
    7 days without an incident.
    8 days without an incident.
    9 days without an incident.
    10 days without an incident.
    11 days without an incident.
    12 days without an incident.
    13 days without an incident.
    14 days without an incident.
    15 days without an incident.
    16 days without an incident.
    17 days without an incident.
    18 days without an incident.
    19 days without an incident.
    20 days without an incident.
    21 days without an incident.
    22 days without an incident.
    23 days without an incident.
    24 days without an incident.
    25 days without an incident.
    26 days without an incident.
    27 days without an incident.
    28 days without an incident.
    29 days without an incident.
    30 days without an incident.
    31 days without an incident.
    32 days without an incident.
    33 days without an incident.
    34 days without an incident.
    35 days without an incident.
    36 days without an incident.
    37 days without an incident.
    38 days without an incident.
    39 days without an incident.
    40 days without an incident.
    41 days without an incident.
    42 days without an incident.
    43 days without an incident.
    44 days without an incident.
    45 days without an incident.
    46 days without an incident.
    47 days without an incident.
    48 days without an incident.
    49 days without an incident.
    How very unpredictable. Level Cleared
    [1]    2904178 done                              ./exploit |
           2904179 segmentation fault (core dumped)  ./prepared
    
    

And that's it! we have been able to guess the random number 50 times.

## Title 

text 
    
    
    

` ![]()

## Title 

text 
    
    
    

` ![]()

