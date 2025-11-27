---
search:
  exclude: true
---
# Helithumper Reverse Engineering

## Downloading the binary file 
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/1]
    → wget https://github.com/guyinatuxedo/nightmare/raw/master/modules/03-beginner_re/helithumper_re/rev
    --2021-02-22 17:19:05--  https://github.com/guyinatuxedo/nightmare/raw/master/modules/03-beginner_re/helithumper_re/rev
    Resolving github.com (github.com)... 140.82.121.4
    Connecting to github.com (github.com)|140.82.121.4|:443... connected.
    HTTP request sent, awaiting response... 302 Found
    Location: https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/03-beginner_re/helithumper_re/rev [following]
    --2021-02-22 17:19:05--  https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/03-beginner_re/helithumper_re/rev
    Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.111.133, 185.199.108.133, ...
    Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 16704 (16K) [application/octet-stream]
    Saving to: ‘rev’
    
    rev                                     100%[===============================================================================>]  16.31K  --.-KB/s    in 0s
    
    2021-02-22 17:19:05 (37.3 MB/s) - ‘rev’ saved [16704/16704]
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/1]
    → file rev
    rev: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e4dbcb1281821db359d566c68fea7380aeb27378, for GNU/Linux 3.2.0, not stripped
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/1]
    → chmod +x rev
    
    

` ![]()

## Solution 

Run the binary 
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/1]
    → ./rev
    Welcome to the Salty Spitoon™, How tough are ya?
    very though
    Yeah right. Back to Weenie Hut Jr™ with ya
    

here the binary prints some text, then lets us input our text (here its 'very though') and then prints some text again. It is safe to assume that we will need to type the correct passphrase to get the correct output. So let's inspect the binary file from ghidra:

![](1.png) ![](2.png)

now from here we want to check out the main function of our binary file, so go into the symbol tree tab, into functions, into main, and we get the following code:

![](3.png)
    
    
    bool main(void)
    
    {
      int iVar1;
      void *pvVar2;
      
      pvVar2 = calloc(0x32,1);
      puts(&DAT;_00102008);
      __isoc99_scanf(&DAT;_0010203b,pvVar2);
      iVar1 = validate(pvVar2);
      if (iVar1 == 0) {
        puts(&DAT;_00102050);
      }
      else {
        puts("Right this way...");
      }
      return iVar1 == 0;
    }
    
    

now here we see something, first of all it does a scanf (to prompt for our input) and then moves our text into pvVar2, then, it calls a function called 'validate' and the result of that function gets put into iVar1 which determines if we get a correct answer or not. So let's inspect the 2 possibilities of the if statement:
    
    
    if (iVar1 == 0) {
        puts(&DAT;_00102050);
      }
      else {
        puts("Right this way...");
      }
    

From ghidra we see that this '&DAT;_00102050' is the string of characters we saw earlier:

![](5.png)

therefore, we do not want iVar1 to be equal to 0, we want iVar1 to be equal to 1

So the hint here is, what is being validated ? How is our input being validated ? we inspect the validate function which HAS TO return 1, if we want our iVar1 to be equal to 1:

![](4.png)

Which gives us the following code:
    
    
    undefined8 validate(char *param_1)
    
    {
      size_t sVar1;
      undefined8 uVar2;
      long in_FS_OFFSET;
      int local_50;
      int local_48 [4];
      undefined4 local_38;
      undefined4 local_34;
      undefined4 local_30;
      undefined4 local_2c;
      undefined4 local_28;
      undefined4 local_24;
      undefined4 local_20;
      undefined4 local_1c;
      undefined4 local_18;
      undefined4 local_14;
      long local_10;
      
      local_10 = *(long *)(in_FS_OFFSET + 0x28);
      local_48[0] = 0x66;
      local_48[1] = 0x6c;
      local_48[2] = 0x61;
      local_48[3] = 0x67;
      local_38 = 0x7b;
      local_34 = 0x48;
      local_30 = 0x75;
      local_2c = 0x43;
      local_28 = 0x66;
      local_24 = 0x5f;
      local_20 = 0x6c;
      local_1c = 0x41;
      local_18 = 0x62;
      local_14 = 0x7d;
      sVar1 = strlen(param_1);
      local_50 = 0;
      do {
        if ((int)sVar1 <= local_50) {
          uVar2 = 1;
    LAB_001012b7:
          if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                        /* WARNING: Subroutine does not return */
            __stack_chk_fail();
          }
          return uVar2;
        }
        if ((int)param_1[local_50] != local_48[local_50]) {
          uVar2 = 0;
          goto LAB_001012b7;
        }
        local_50 = local_50 + 1;
      } while( true );
    }
    

So first of all our input text gets passed into the validate function via the param_1 parameter. It enters a do{} while(); loop, with each iteration of that while loop, there is a value that gets incremented, the only return statements of that function are either return uVar2 or either not making the function return anything at all, instead going to the __stack_chk_fail() function. therefore the important value here is uVar2 
    
    
    int local_48 [4];
    
    [...]
    
      local_48[0] = 0x66;
      local_48[1] = 0x6c;
      local_48[2] = 0x61;
      local_48[3] = 0x67;
    
    [...]
    
    if ((int)param_1[local_50] != local_48[local_50]) {
          uVar2 = 0;
          goto LAB_001012b7;
        }
        local_50 = local_50 + 1;
    

Here we see that our each character of our input (param1) gets checked against the corresponding character of the local_48 string. Therefore we need to make sure our input matches the values inside of local_48's 0,1,2,3 characters. so we know we have to look at the following addresses: 
    
    
    0x66
    0x6c
    0x61
    0x67
    
    

From Ghidra, we see the following assembly code:
    
    
            00101205 c7 45 c0        MOV        dword ptr [RBP + local_48],0x66
                     66 00 00 00
            0010120c c7 45 c4        MOV        dword ptr [RBP + local_44],0x6c
                     6c 00 00 00
            00101213 c7 45 c8        MOV        dword ptr [RBP + local_40],0x61
                     61 00 00 00
            0010121a c7 45 cc        MOV        dword ptr [RBP + local_3c],0x67
                     67 00 00 00
    
    
    
    
            00101221 c7 45 d0        MOV        dword ptr [RBP + local_38],0x7b
                     7b 00 00 00
            00101228 c7 45 d4        MOV        dword ptr [RBP + local_34],0x48
                     48 00 00 00
            0010122f c7 45 d8        MOV        dword ptr [RBP + local_30],0x75
                     75 00 00 00
            00101236 c7 45 dc        MOV        dword ptr [RBP + local_2c],0x43
                     43 00 00 00
            0010123d c7 45 e0        MOV        dword ptr [RBP + local_28],0x66
                     66 00 00 00
            00101244 c7 45 e4        MOV        dword ptr [RBP + local_24],0x5f
                     5f 00 00 00
            0010124b c7 45 e8        MOV        dword ptr [RBP + local_20],0x6c
                     6c 00 00 00
            00101252 c7 45 ec        MOV        dword ptr [RBP + local_1c],0x41
                     41 00 00 00
            00101259 c7 45 f0        MOV        dword ptr [RBP + local_18],0x62
                     62 00 00 00
            00101260 c7 45 f4        MOV        dword ptr [RBP + local_14],0x7d
                     7d 00 00 00
    

Now from here we can get the list of specific bytes our input needs to be:
    
    
    0x66
    0x6c
    0x61
    0x67
    
    0x7b
    0x48
    0x75
    0x43
    0x66
    0x5f
    0x6c
    0x41
    0x62
    0x7d
    

Now let's move over to python:
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/1]
    → ls -lash
    total 788K
    4.0K drwxr-xr-x 2 nothing nothing 4.0K Feb 22 17:19 .
    4.0K drwxr-xr-x 4 nothing nothing 4.0K Feb 22 17:23 ..
     20K -rwxr-xr-x 1 nothing nothing  17K Feb 22 17:19 rev
    760K -rwxr-xr-x 1 nothing nothing 759K Feb 22 17:12 strings
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/1]
    → file rev
    rev: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e4dbcb1281821db359d566c68fea7380aeb27378, for GNU/Linux 3.2.0, not stripped
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/1]
    → python3
    Python 3.9.1+ (default, Feb  5 2021, 13:46:56)
    [GCC 10.2.1 20210110] on linux
    Type "help", "copyright", "credits" or "license" for more information.
    >>> x = [0x66, 0x6c, 0x61, 0x67, 0x7b, 0x48, 0x75, 0x43, 0x66, 0x5f, 0x6c, 0x41, 0x62, 0x7d]
    >>> input = ""
    >>> for i in x:
    ...     input += chr(i)
    ...
    >>> input
    'flag{HuCf_lAb}'
    

And here we see that the first 4 addresses were 'flag' the next 10 were '{HuCf_lAb}', this obviously was fairly easy

## Title 

text 
    
    
    

` ![]()

## Title 

text 
    
    
    

` ![]()

