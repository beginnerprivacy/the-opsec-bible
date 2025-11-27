---
search:
  exclude: true
---
# Binary Exploitation

## Downloading the binary file 
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/1]
    → wget https://github.com/guyinatuxedo/nightmare/raw/master/modules/03-beginner_re/pico18_strings/strings
    --2021-02-22 17:12:22--  https://github.com/guyinatuxedo/nightmare/raw/master/modules/03-beginner_re/pico18_strings/strings
    Resolving github.com (github.com)... 140.82.121.3
    Connecting to github.com (github.com)|140.82.121.3|:443... connected.
    HTTP request sent, awaiting response... 302 Found
    Location: https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/03-beginner_re/pico18_strings/strings [following]
    --2021-02-22 17:12:22--  https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/03-beginner_re/pico18_strings/strings
    Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.108.133, 185.199.109.133, ...
    Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 776368 (758K) [application/octet-stream]
    Saving to: ‘strings’
    
    strings                                                                         100%[=======================================================================================================================================================================================================>] 758.17K  --.-KB/s    in 0.1s
    
    2021-02-22 17:12:23 (5.86 MB/s) - ‘strings’ saved [776368/776368]
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/1]
    → file strings
    strings: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=e337b489c47492dd5dff90353eb227b4e7e69028, not stripped
    

` ![]()

## Solution 

The solution is fairly simple, first make the binary file executable, then run it: 
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/1]
    → chmod +x strings
    
    [ 192.168.100.126/24 ] [ /dev/pts/2 ] [~/binexp/1]
    → ./strings
    Have you ever used the 'strings' function? Check out the man pages!
    

Here we are hinted at using the strings function, so we will do so and use grep to try and see if the flag appears, generally the flag contains {flaghash} so we can use grep to find it :
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/binexp/1]
    → strings strings | grep {
    picoCTF{sTrIngS_sAVeS_Time_3f712a28}
    
    

And we're done!

![]()

## Title 

text 
    
    
    

` ![]()

## Title 

text 
    
    
    

` ![]()

