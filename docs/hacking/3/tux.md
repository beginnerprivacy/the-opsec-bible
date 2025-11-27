---
search:
  exclude: true
---
# hsctf 2019 tux talk show

## Downloading the binary file 
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/3/tux]
    → wget https://github.com/guyinatuxedo/nightmare/raw/master/modules/09-bad_seed/hsctf19_tuxtalkshow/tuxtalkshow
    
    --2021-03-07 13:24:34--  https://github.com/guyinatuxedo/nightmare/raw/master/modules/09-bad_seed/hsctf19_tuxtalkshow/tuxtalkshow
    Loaded CA certificate '/etc/ssl/certs/ca-certificates.crt'
    Resolving github.com (github.com)... 140.82.121.3
    Connecting to github.com (github.com)|140.82.121.3|:443... connected.
    HTTP request sent, awaiting response... 302 Found
    Location: https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/09-bad_seed/hsctf19_tuxtalkshow/tuxtalkshow [following]
    --2021-03-07 13:24:35--  https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/09-bad_seed/hsctf19_tuxtalkshow/tuxtalkshow
    Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.110.133, 185.199.108.133, ...
    Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 21112 (21K) [application/octet-stream]
    Saving to: ‘tuxtalkshow’
    
    tuxtalkshow                         100%[================================================================>]  20.62K  --.-KB/s    in 0.003s
    
    2021-03-07 13:24:35 (5.81 MB/s) - ‘tuxtalkshow’ saved [21112/21112]
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/3/tux]
    → file tuxtalkshow
    tuxtalkshow: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=8c0d2b94392e01fecb4b54999cc8afe6fa99653d, for GNU/Linux 3.2.0, not stripped
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/3/tux]
    → chmod +x tuxtalkshow
    
    
    

` ![]()

## Solution 

First let's run pwn checksec on the binary file before executing it to see what it does:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/3/tux]
    → pwn checksec tuxtalkshow
    [*] '/home/nothing/binexp/3/tux/tuxtalkshow'
        Arch:     amd64-64-little
        RELRO:    Partial RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      PIE enabled
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/3/tux]
    → ./tuxtalkshow
    Welcome to Tux Talk Show 2019!!!
    Enter your lucky number: 13371337
    
    

So here we have a 64bit binary with PIE enabled. When we run it it prompts us for a number. So let's check it out from inside of ghidra:

![](1.png)

And here we get a gigantic main function:
    
    
    undefined8 main(void)
    
    {
      int iVar1;
      time_t tVar2;
      basic_ostream *pbVar3;
      long in_FS_OFFSET;
      int local_290;
      int local_28c;
      int local_288;
      int local_284;
      undefined4 local_280;
      undefined4 local_27c;
      undefined4 local_278;
      undefined4 local_274;
      undefined4 local_270;
      undefined4 local_26c;
      int local_268 [8];
      basic_string local_248 [32];
      basic_istream local_228 [520];
      long local_20;
      
      local_20 = *(long *)(in_FS_OFFSET + 0x28);
      std::basic_ifstream>::basic_ifstream((char *)local_228,0x1020b0);
      tVar2 = time((time_t *)0x0);
      srand((uint)tVar2);
                        /* try { // try from 0010127e to 001012c0 has its CatchHandler @ 00101493 */
      pbVar3 = std::operator<<((basic_ostream *)std::cout,"Welcome to Tux Talk Show 2019!!!");
      std::basic_ostream>::operator<<
                ((basic_ostream> *)pbVar3,
                 std::endl>);
      std::operator<<((basic_ostream *)std::cout,"Enter your lucky number: ");
      std::basic_istream>::operator>>
                ((basic_istream> *)std::cin,&local;_290);
      local_280 = 0x79;
      local_27c = 0x12c97f;
      local_278 = 0x135f0f8;
      local_274 = 0x74acbc6;
      local_270 = 0x56c614e;
      local_26c = 0xffffffe2;
      local_268[0] = 0x79;
      local_268[1] = 0x12c97f;
      local_268[2] = 0x135f0f8;
      local_268[3] = 0x74acbc6;
      local_268[4] = 0x56c614e;
      local_268[5] = 0xffffffe2;
      local_28c = 0;
      while (local_28c < 6) {
        iVar1 = rand();
        local_268[local_28c] = local_268[local_28c] - (iVar1 % 10 + -1);
        local_28c = local_28c + 1;
      }
      local_288 = 0;
      local_284 = 0;
      while (local_284 < 6) {
        local_288 = local_288 + local_268[local_284];
        local_284 = local_284 + 1;
      }
      if (local_288 == local_290) {
        std::__cxx11::basic_string,std::allocator>::basic_string();
                        /* try { // try from 00101419 to 00101448 has its CatchHandler @ 0010147f */
        std::operator>>(local_228,local_248);
        pbVar3 = std::operator<<((basic_ostream *)std::cout,local_248);
        std::basic_ostream>::operator<<
                  ((basic_ostream> *)pbVar3,
                   std::endl>);
        std::__cxx11::basic_string,std::allocator>::~basic_string
                  ((basic_string,std::allocator> *)local_248);
      }
      std::basic_ifstream>::~basic_ifstream
                ((basic_ifstream> *)local_228);
      if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                        /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return 0;
    }
    

Here we cansee that it starts off by scanning the contents of flag.txt and saves it into **local_228**. Then it initialized an integer array with size entries, although the decompilation only shows 4. So let's look at the assembly code:
    
    
            001012bc e8 8f fd        CALL       operator>>                                       undefined operator>>(basic_istre
                     ff ff
                                 } // end try from 0010127e to 001012c0
            001012c1 c7 85 88        MOV        dword ptr [RBP + local_280],0x79
                     fd ff ff 
                     79 00 00 00
            001012cb c7 85 8c        MOV        dword ptr [RBP + local_27c],0x12c97f
                     fd ff ff 
                     7f c9 12 00
            001012d5 c7 85 90        MOV        dword ptr [RBP + local_278],0x135f0f8
                     fd ff ff 
                     f8 f0 35 01
            001012df c7 85 94        MOV        dword ptr [RBP + local_274],0x74acbc6
                     fd ff ff 
                     c6 cb 4a 07
            001012e9 c7 85 98        MOV        dword ptr [RBP + local_270],0x56c614e
                     fd ff ff 
                     4e 61 6c 05
            001012f3 c7 85 9c        MOV        dword ptr [RBP + local_26c],0xffffffe2
                     fd ff ff 
                     e2 ff ff ff
    
    

We also see that it uses time as a seed. It performs an algorithm where it will generate random numbers by using time a sa seed to edit the values of array, and then it accumulate all of those values to end up with the number we are supposed to guess. Since the rand function is directly based off of the seed, and since the seed is the time, we know what the values the rand function will output, and thus end up with the following C program:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/3/tux]
    → vim exploit.c
    
    
    
    
    ****#include <****stdio.h>
    #include <****stdlib.h>
    #include <****stdint.h>
    #include <****time.h>
    
    int main()
    {
        int array[6];
        int i, output;
        uint32_t randVal, ans;
    
        srand(time(0)); 
    
    
        i = 0;
    
        array[0] = 0x79;
        array[1] = 0x12c97f;
        array[2] = 0x135f0f8;
        array[3] = 0x74acbc6;
        array[4] = 0x56c614e;
        array[5] = 0xffffffe2;
    
        while (i < 6)
        {
        	randVal = rand();
        	array[i] = array[i] - ((randVal % 10) - 1);
        	i += 1;
        }
    
        i = 0;
        output = 0;
    
        while (i < 6)
        {
        	output = output + array[i];
        	i += 1;
        }
    
    
        printf("%d\n", output);	
    }
    

Then we compile our C code:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/3/tux]
    → gcc exploit.c -o exploit
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/3/tux]
    → ./exploit
    
    

let's try it on the binary file:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/3/tux]
    → ./exploit
    234874834
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/3/tux]
    → ./exploit
    234874839
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/3/tux]
    → ./exploit
    234874828
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/3/tux]
    → ./exploit | ./tuxtalkshow
    Welcome to Tux Talk Show 2019!!!
    Enter your lucky number: flag{g0tt3m_boyz}
    
    

And that's it ! We have been able to print out the flag.

## Title 

text 
    
    
    

` ![]()

## Title 

text 
    
    
    

` ![]()

