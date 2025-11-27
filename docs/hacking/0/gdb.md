---
search:
  exclude: true
---
# GDB + GEF

GDB, the GNU project debugger, allows you to see what is going on inside another program while it executes, or what said program was doing at the moment it crashed. GDB supports Ada, Assembly, C, C++, D, Frotan, Go, Objective-C, OpenCL, Modula-2, Pascal and Rust. For more information, click [here](https://www.gnu.org/software/gdb/).

However, GDB is very old school, so we will use GEF to enhance the usage of gdb, it is a set of commands for x86/64, ARM, MIPS,PowerPC and SPARC that provides additional features to GDB using the Python API to assist during the dynamic analysis and exploit development. For more information, click [here](https://github.com/hugsy/gef).

## Installation 

To install gdb you can find it in most repositories of popular linux distributions: 
    
    
    #Arch Linux:
    [ 192.168.0.18/24 ] [ /dev/pts/15 ] [~]
    → pacman -Ss gdb
    extra/gdb 10.1-4
        The GNU Debugger
    
    [ 192.168.0.18/24 ] [ /dev/pts/15 ] [~]
    → pacman -S gdb
    
    
    #Kali / Debian:
    [ 10.10.14.17/23 ] [ /dev/pts/3 ] [~]
    → apt search gdb
    gdb/kali-rolling,now 10.1-1.7 amd64 [installed]
      GNU Debugger
    
    [ 10.10.14.17/23 ] [ /dev/pts/3 ] [~]
    → apt install gdb -y
    

To install GEF we will follow the instructions from the main website:
    
    
    
    [ 10.10.14.17/23 ] [ /dev/pts/3 ] [~]
    → sh -c "$(wget http://gef.blah.cat/sh -O -)"
    --2021-02-21 16:20:00--  http://gef.blah.cat/sh
    Resolving gef.blah.cat (gef.blah.cat)... 40.121.232.30
    Connecting to gef.blah.cat (gef.blah.cat)|40.121.232.30|:80... connected.
    HTTP request sent, awaiting response... 301 Moved Permanently
    Location: https://github.com/hugsy/gef/raw/master/scripts/gef.sh [following]
    --2021-02-21 16:20:01--  https://github.com/hugsy/gef/raw/master/scripts/gef.sh
    Resolving github.com (github.com)... 140.82.121.4
    Connecting to github.com (github.com)|140.82.121.4|:443... connected.
    HTTP request sent, awaiting response... 302 Found
    Location: https://raw.githubusercontent.com/hugsy/gef/master/scripts/gef.sh [following]
    --2021-02-21 16:20:01--  https://raw.githubusercontent.com/hugsy/gef/master/scripts/gef.sh
    Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.109.133, 185.199.108.133, ...
    Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 565 [text/plain]
    Saving to: ‘STDOUT’
    
    -                                                                   100%[=================================================================================================================================================================>]     565  --.-KB/s    in 0s
    
    2021-02-21 16:20:01 (49.8 MB/s) - written to stdout [565/565]
    
    sh: 6: test: unexpected operator
    
    [ 10.10.14.17/23 ] [ /dev/pts/3 ] [~]
    → ls -lash ~/.gdbinit
    4.0K -rw-r--r-- 1 nothing nothing 58 Feb 21 16:20 /home/nothing/.gdbinit
    
    

Now when you try to launch gdb, you see that you are correctly launching gef:

![](1.png)

If you get any errors as you launch gdb - gef for the first time, just run the required pip install commands:

![](2.png)
    
    
    gef➤  q
    
    [ 10.10.14.17/23 ] [ /dev/pts/3 ] [~]
    → sudo apt install python3-pip -y
    
    [ 10.10.14.17/23 ] [ /dev/pts/3 ] [~]
    → pip3 install keystone-engine unicorn ropper
    Collecting keystone-engine
      Downloading keystone_engine-0.9.2-py2.py3-none-manylinux1_x86_64.whl (1.8 MB)
         |████████████████████████████████| 1.8 MB 2.3 MB/s
    Collecting unicorn
      Downloading unicorn-1.0.2-py2.py3-none-manylinux1_x86_64.whl (8.1 MB)
         |████████████████████████████████| 8.1 MB 6.3 MB/s
    Collecting ropper
      Downloading ropper-1.13.6.tar.gz (71 kB)
         |████████████████████████████████| 71 kB 2.2 MB/s
    Collecting filebytes>=0.10.0
      Downloading filebytes-0.10.2.tar.gz (20 kB)
    Building wheels for collected packages: ropper, filebytes
      Building wheel for ropper (setup.py) ... done
      Created wheel for ropper: filename=ropper-1.13.6-py3-none-any.whl size=99735 sha256=2f90a4e8a5b14f1c8c3abd0700b1e56ff8dbc7f3d165a5f69790c31cedd8948b
      Stored in directory: /home/nothing/.cache/pip/wheels/77/a4/5d/a4bc1b653bdcce30a17b5cdda8f19da11444bb8640d03ab678
      Building wheel for filebytes (setup.py) ... done
      Created wheel for filebytes: filename=filebytes-0.10.2-py3-none-any.whl size=27853 sha256=17cf4812a6b16ee7c92a4ba259326c61fbfab4cf3c05ace2cb627a0de892d27f
      Stored in directory: /home/nothing/.cache/pip/wheels/c2/51/58/98925d75705ee4df10da42a098d956183bb70661698fd07753
    Successfully built ropper filebytes
    Installing collected packages: keystone-engine, unicorn, filebytes, ropper
      WARNING: The script ropper is installed in '/home/nothing/.local/bin' which is not on PATH.
      Consider adding this directory to PATH or, if you prefer to suppress this warning, use --no-warn-script-location.
    Successfully installed filebytes-0.10.2 keystone-engine-0.9.2 ropper-1.13.6 unicorn-1.0.2
    
    
    

Once you're here, you're good to go

![](3.png)

## Title 

text 
    
    
    

` ![]()

## Title 

text 
    
    
    

` ![]()

## Title 

text 
    
    
    

` ![]()

