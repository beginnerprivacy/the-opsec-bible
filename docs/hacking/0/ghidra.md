---
search:
  exclude: true
---
# Ghidra 

Ghidra is a software reverse engineering (SRE) framework created and maintained by the National Security Agency Research Directorate. This framework includes a suite of full-featured, high-end software analysis tools that enable users to analyze compiled code on a variety of platforms including Windows, macOS, and Linux. Capabilities include disassembly, assembly, decompilation, graphing, and scripting, along with hundreds of other features. Ghidra supports a wide variety of processor instruction sets and executable formats and can be run in both user-interactive and automated modes.

## Installation

To install Ghidra, we will follow the instructions listed [here](https://www.ghidra-sre.org/InstallationGuide.html)

First install java: 
    
    
    [ 10.10.14.17/23 ] [ /dev/pts/3 ] [~]
    → sudo apt update -y ; sudo apt upgrade -y ; sudo apt install default-jdk -y
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~]
    → java -version
    openjdk version "11.0.10" 2021-01-19
    OpenJDK Runtime Environment (build 11.0.10+9-post-Debian-1)
    OpenJDK 64-Bit Server VM (build 11.0.10+9-post-Debian-1, mixed mode, sharing)
    
    

From here, just go to ghidra's main website to download the zip file: 

![](4.png)
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/Tools/ghidra]
    → wget https://www.ghidra-sre.org/ghidra_9.2.2_PUBLIC_20201229.zip
    --2021-02-21 23:10:29--  https://www.ghidra-sre.org/ghidra_9.2.2_PUBLIC_20201229.zip
    Resolving www.ghidra-sre.org (www.ghidra-sre.org)... 13.249.9.44, 13.249.9.83, 13.249.9.20, ...
    Connecting to www.ghidra-sre.org (www.ghidra-sre.org)|13.249.9.44|:443... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 317805407 (303M) [application/zip]
    Saving to: ‘ghidra_9.2.2_PUBLIC_20201229.zip’
    
    ghidra_9.2.2_PUBLIC_20201229.zip                                                100%[=======================================================================================================================================================================================================>] 303.08M  10.9MB/s    in 29s
    
    2021-02-21 23:10:58 (10.5 MB/s) - ‘ghidra_9.2.2_PUBLIC_20201229.zip’ saved [317805407/317805407]
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/Tools/ghidra]
    → unzip ghidra_9.2.2_PUBLIC_20201229.zip
    

Now from here, we need the ghidraRun binary to launch ghidra:
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/Tools/ghidra]
    → ls -l
    total 310368
    drwxr-xr-x 9 nothing nothing      4096 Dec 29 17:22 ghidra_9.2.2_PUBLIC
    -rw-r--r-- 1 nothing nothing 317805407 Jan 19 17:53 ghidra_9.2.2_PUBLIC_20201229.zip
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [~/Tools/ghidra]
    → cd ghidra_9.2.2_PUBLIC
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [Tools/ghidra/ghidra_9.2.2_PUBLIC]
    → ls
    docs  Extensions  Ghidra  ghidraRun  ghidraRun.bat  GPL  LICENSE  licenses  server  support
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [Tools/ghidra/ghidra_9.2.2_PUBLIC]
    → file ghidraRun
    ghidraRun: Bourne-Again shell script, ASCII text executable
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [Tools/ghidra/ghidra_9.2.2_PUBLIC]
    → cat ghidraRun
    #!/usr/bin/env bash
    
    #----------------------------------------
    # Ghidra launch
    #----------------------------------------
    
    # Maximum heap memory may be changed if default is inadequate. This will generally be up to 1/4 of
    # the physical memory available to the OS. Uncomment MAXMEM setting if non-default value is needed.
    #MAXMEM=2G
    
    # Resolve symbolic link if present and get the directory this script lives in.
    # NOTE: "readlink -f" is best but works on Linux only, "readlink" will only work if your PWD
    # contains the link you are calling (which is the best we can do on macOS), and the "echo" is the
    # fallback, which doesn't attempt to do anything with links.
    SCRIPT_FILE="$(readlink -f "$0" 2>/dev/null || readlink "$0" 2>/dev/null || echo "$0")"
    SCRIPT_DIR="${SCRIPT_FILE%/*}"
    
    # Launch Ghidra
    "${SCRIPT_DIR}"/support/launch.sh bg Ghidra "${MAXMEM}" "" ghidra.GhidraRun "$@"
    

To make it more convenient, i make a symlink to a folder in PATH:
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [Tools/ghidra/ghidra_9.2.2_PUBLIC]
    → echo $PATH
    /usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [Tools/ghidra/ghidra_9.2.2_PUBLIC]
    → sudo ln -s $(pwd)/ghidraRun /usr/bin/ghidra
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [Tools/ghidra/ghidra_9.2.2_PUBLIC]
    → ls -lash /usr/bin/ghidra
    0 lrwxrwxrwx 1 root root 56 Feb 21 23:19 /usr/bin/ghidra -> /home/nothing/Tools/ghidra/ghidra_9.2.2_PUBLIC/ghidraRun
    
    [ 192.168.100.126/24 ] [ /dev/pts/1 ] [Tools/ghidra/ghidra_9.2.2_PUBLIC]
    → which ghidra
    /usr/bin/ghidra
    
    

From here you can just type ghidra in your terminal or in dmenu or rofi or whatever you want, it will open up ghidra for you:

![](5.png)

Here you get a nice tutorial to let you know about ghidra's functionnalities, but you will want to create a new project and giving it a directory location:

![](6.png)

Just to test, we're going to copy a random binary locally and import it

![](7.png)
    
    
    [ 192.168.100.126/24 ] [ /dev/pts/3 ] [~/binexp]
    → cp /bin/lspci .
    
    [ 192.168.100.126/24 ] [ /dev/pts/3 ] [~/binexp]
    → ls -lash lspci
    92K -rwxr-xr-x 1 nothing nothing 92K Feb 21 23:27 lspci
    
    

` ![](8.png) ![](9.png) ![](10.png)

And there you have it! You now have an imported a binary file to disassemble.

![](11.png) ![]()

## Title 

text 
    
    
    

` ![]()

## Title 

text 
    
    
    

` ![]()

## Title 

text 
    
    
    

` ![]()

