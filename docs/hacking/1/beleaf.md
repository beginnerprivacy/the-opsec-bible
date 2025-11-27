---
search:
  exclude: true
---
# CSAW 2019 Beleaf

## Downloading the binary file 
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/1]
    → wget https://github.com/guyinatuxedo/nightmare/raw/master/modules/03-beginner_re/csaw19_beleaf/beleaf
    --2021-02-22 19:55:50--  https://github.com/guyinatuxedo/nightmare/raw/master/modules/03-beginner_re/csaw19_beleaf/beleaf
    Resolving github.com (github.com)... 140.82.121.4
    Connecting to github.com (github.com)|140.82.121.4|:443... connected.
    HTTP request sent, awaiting response... 302 Found
    Location: https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/03-beginner_re/csaw19_beleaf/beleaf [following]
    --2021-02-22 19:55:51--  https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/03-beginner_re/csaw19_beleaf/beleaf
    Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.108.133, 185.199.111.133, ...
    Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 7624 (7.4K) [application/octet-stream]
    Saving to: ‘beleaf’
    
    beleaf                                  100%[===============================================================================>]   7.45K  --.-KB/s    in 0.01s
    
    2021-02-22 19:55:51 (676 KB/s) - ‘beleaf’ saved [7624/7624]
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/1]
    → file beleaf
    beleaf: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6d305eed7c9bebbaa60b67403a6c6f2b36de3ca4, stripped
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/1]
    → chmod +x beleaf
    
    

` ![]()

## Solution 

Now, first things first, we are going to use pwntools' pwn tool to check the security of the binary file itself.
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/1]
    → pwn checksec beleaf
    [*] '/home/nothing/binexp/1/beleaf'
        Arch:     amd64-64-little
        RELRO:    Full RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      PIE enabled
    
    

So we are dealing with a 64bit binary, that scans the input of the user and then checks it, very much like the previous challenge we solved, [helithumper](heli.md). So we're going to import the file into ghidra, and take a look at the main function

![](6.png)

Here the main function is not called 'main' like in the previous challenge, to do so i had to look for the 'Enter the flag >>>" print statement which happened to be in the FUN_001008a1 function as you can see in the screenshot above. The code that ghidra gives us says that our text input is called 'local_98' and then later on the length of our text input is passed into sVar1
    
    
    undefined8 FUN_001008a1(void)
    
    {
      size_t sVar1;
      long lVar2;
      long in_FS_OFFSET;
      ulong local_b0;
      char local_98 [136];
      long local_10;
      
      local_10 = *(long *)(in_FS_OFFSET + 0x28);
      printf("Enter the flag\n>>> ");
      __isoc99_scanf(&DAT;_00100a78,local_98);
      sVar1 = strlen(local_98);
      if (sVar1 < 0x21) {
        puts("Incorrect!");
                        /* WARNING: Subroutine does not return */
        exit(1);
      }
      local_b0 = 0;
      while (local_b0 < sVar1) {
        lVar2 = FUN_001007fa((int)local_98[local_b0]);
        if (lVar2 != *(long *)(&DAT;_003014e0 + local_b0 * 8)) {
          puts("Incorrect!");
                        /* WARNING: Subroutine does not return */
          exit(1);
        }
        local_b0 = local_b0 + 1;
      }
      puts("Correct!");
      if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                        /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return 0;
    }
    

now let's look at what we need to get the 'correct' output, first of all if our input LENGTH (sVar1) is less than 0x21 or 33 bytes, we will get 'incorrect', so we need at least 33 characters:
    
    
      if (sVar1 < 0x21) {
        puts("Incorrect!");
                        /* WARNING: Subroutine does not return */
        exit(1);
    

Then we see that we enter a for loop (which is a while loop with a variable being incremented (here it is local_b0)) 
    
    
      while (local_b0 < sVar1) {
        lVar2 = FUN_001007fa((int)local_98[local_b0]);
        if (lVar2 != *(long *)(&DAT;_003014e0 + local_b0 * 8)) {
          puts("Incorrect!");
                        /* WARNING: Subroutine does not return */
          exit(1);
        }
        local_b0 = local_b0 + 1;
      }
      puts("Correct!");
    

in this for loop, each character of our text input (local_98 at the index 0,1,2,3 ... 32) gets passed into the 'FUN_001007fa' function the result of that function gets passed to the if statement as 'lVar2' to get checked against a certain '&DAT;_003014e0' which is basically an array, the if statement checks for the characters at offsets of 8. So let's double click it to see what it is: 
    
    
                                 DAT_003014e0                                    XREF[2]:     FUN_001008a1:0010096b(*), 
                                                                                              FUN_001008a1:00100972(R)  
            003014e0 01              ??         01h
    
            003014e1 00              ??         00h
            003014e2 00              ??         00h
            003014e3 00              ??         00h
            003014e4 00              ??         00h
            003014e5 00              ??         00h
            003014e6 00              ??         00h
            003014e7 00              ??         00h
            003014e8 09              ??         09h
    
            003014e9 00              ??         00h
            003014ea 00              ??         00h
            003014eb 00              ??         00h
            003014ec 00              ??         00h
            003014ed 00              ??         00h
            003014ee 00              ??         00h
            003014ef 00              ??         00h
            003014f0 11              ??         11h
    
            003014f1 00              ??         00h
            003014f2 00              ??         00h
            003014f3 00              ??         00h
            003014f4 00              ??         00h
            003014f5 00              ??         00h
            003014f6 00              ??         00h
            003014f7 00              ??         00h
            003014f8 27              ??         27h    '
    
            003014f9 00              ??         00h
            003014fa 00              ??         00h
            003014fb 00              ??         00h
            003014fc 00              ??         00h
            003014fd 00              ??         00h
            003014fe 00              ??         00h
            003014ff 00              ??         00h
            00301500 02              ??         02h
    
    

And here we see the bytes we need are at offsets of 8, so we have the following:
    
    
    0x1 0x9 0x11 0x27 0x2
    

Now let's take a look at the 'FUN_001007fa' function that checks each of our input text characters:

![](7.png)
    
    
    long FUN_001007fa(char param_1)
    
    {
      long local_10;
      
      local_10 = 0;
      while ((local_10 != -1 && ((int)param_1 != *(int *)(&DAT;_00301020 + local_10 * 4)))) {
        if ((int)param_1 < *(int *)(&DAT;_00301020 + local_10 * 4)) {
          local_10 = local_10 * 2 + 1;
        }
        else {
          if (*(int *)(&DAT;_00301020 + local_10 * 4) < (int)param_1) {
            local_10 = (local_10 + 1) * 2;
          }
        }
      }
      return local_10;
    }
    

in here, each character of our input text gets passed as the param_1 charcater, and then the function basically looks at the 'DAT_003014e0' array with offsets of 4, the function tries to find at which index our input text characters are in this array, so let's see what is in that 'DAT_003014e0' array 
    
    
                                 DAT_00301020                                    XREF[6]:     FUN_001007fa:00100820(*), 
                                                                                              FUN_001007fa:00100827(R), 
                                                                                              FUN_001007fa:00100844(*), 
                                                                                              FUN_001007fa:0010084b(R), 
                                                                                              FUN_001007fa:00100873(*), 
                                                                                              FUN_001007fa:0010087a(R)  
            00301020 77              ??         77h    w
    
            00301021 00              ??         00h
            00301022 00              ??         00h
            00301023 00              ??         00h
            00301024 66              ??         66h    f
    
            00301025 00              ??         00h
            00301026 00              ??         00h
            00301027 00              ??         00h
            00301028 7b              ??         7Bh    {
    
            00301029 00              ??         00h
            0030102a 00              ??         00h
            0030102b 00              ??         00h
            0030102c 5f              ??         5Fh    _
    
            0030102d 00              ??         00h
            0030102e 00              ??         00h
            0030102f 00              ??         00h
            00301030 6e              ??         6Eh    n
    
            00301031 00              ??         00h
            00301032 00              ??         00h
            00301033 00              ??         00h
            00301034 79              ??         79h    y
    
            00301035 00              ??         00h
            00301036 00              ??         00h
            00301037 00              ??         00h
            00301038 7d              ??         7Dh    }
    
            00301039 00              ??         00h
            0030103a 00              ??         00h
            0030103b 00              ??         00h
            0030103c ff              ??         FFh
            0030103d ff              ??         FFh
            0030103e ff              ??         FFh
            0030103f ff              ??         FFh
            00301040 62              ??         62h    b
    
            00301041 00              ??         00h
            00301042 00              ??         00h
            00301043 00              ??         00h
            00301044 6c              ??         6Ch    l
    
            00301045 00              ??         00h
            00301046 00              ??         00h
            00301047 00              ??         00h
            00301048 72              ??         72h    r
    
            00301049 00              ??         00h
            0030104a 00              ??         00h
            0030104b 00              ??         00h
            0030104c ff              ??         FFh
            0030104d ff              ??         FFh
            0030104e ff              ??         FFh
            0030104f ff              ??         FFh
            00301050 ff              ??         FFh
            00301051 ff              ??         FFh
            00301052 ff              ??         FFh
            00301053 ff              ??         FFh
            00301054 ff              ??         FFh
            00301055 ff              ??         FFh
            00301056 ff              ??         FFh
            00301057 ff              ??         FFh
            00301058 ff              ??         FFh
            00301059 ff              ??         FFh
            0030105a ff              ??         FFh
            0030105b ff              ??         FFh
            0030105c ff              ??         FFh
            0030105d ff              ??         FFh
            0030105e ff              ??         FFh
            0030105f ff              ??         FFh
            00301060 ff              ??         FFh
            00301061 ff              ??         FFh
            00301062 ff              ??         FFh
            00301063 ff              ??         FFh
            00301064 61              ??         61h    a
    
            00301065 00              ??         00h
            00301066 00              ??         00h
            00301067 00              ??         00h
            00301068 65              ??         65h    e
    
            00301069 00              ??         00h
            0030106a 00              ??         00h
            0030106b 00              ??         00h
            0030106c 69              ??         69h    i
    [...]
    
    

now when you look at the characters in this array, you can get the feeling that you might be able to type flag{something} with it, so let's follow what the code does with the 2 arrays we found:

we know that the start of the 1020array is 00301020. The character f will output 1 because **((0x00301024 - 0x00301020) / 4) = 1** so this is equal to 1. This 1 also corresponds to the 14e0 array from earlier: 
    
    
                                 DAT_003014e0                                    XREF[2]:     FUN_001008a1:0010096b(*), 
                                                                                              FUN_001008a1:00100972(R)  
            003014e0 01              ??         01h
    
            003014e1 00              ??         00h
            003014e2 00              ??         00h
            003014e3 00              ??         00h
            003014e4 00              ??         00h
            003014e5 00              ??         00h
            003014e6 00              ??         00h
            003014e7 00              ??         00h
            003014e8 09              ??         09h
    
            003014e9 00              ??         00h
            003014ea 00              ??         00h
            003014eb 00              ??         00h
            003014ec 00              ??         00h
            003014ed 00              ??         00h
            003014ee 00              ??         00h
            003014ef 00              ??         00h
            003014f0 11              ??         11h
    
            003014f1 00              ??         00h
            003014f2 00              ??         00h
            003014f3 00              ??         00h
            003014f4 00              ??         00h
            003014f5 00              ??         00h
            003014f6 00              ??         00h
            003014f7 00              ??         00h
            003014f8 27              ??         27h    '
    
            003014f9 00              ??         00h
            003014fa 00              ??         00h
            003014fb 00              ??         00h
            003014fc 00              ??         00h
            003014fd 00              ??         00h
            003014fe 00              ??         00h
            003014ff 00              ??         00h
            00301500 02              ??         02h
    
    [...]
    
    

and here you have to continue with the 0x9 value,**(0x00301020 + (4*9)) = 0x301044** this address corresponds to the l character 
    
    
    fl
    
    

11 is the third character **(0x00301020 + (4*11)) = 0x301064** this corresponds to the a character 
    
    
    fla
    

27 is the fourth character **(0x00301020 + (4*27)) = 0x3010bc** this corresponds to the g character
    
    
    flag
    

from here you keep going and you end up with the following:
    
    
    flag{we_beleaf_in_your_re_future}
    
    

so just run the binary with the flag to verify it is correct:
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/1]
    → ./beleaf
    Enter the flag
    >>> flag{we_beleaf_in_your_re_future}
    Correct!
    
    

## Title 

text 
    
    
    

` ![]()

## Title 

text 
    
    
    

` ![]()

