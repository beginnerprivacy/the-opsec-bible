---
search:
  exclude: true
---
# Python Pwntools

Pwntools is a python ctf library designed for rapid exploit development. It helps us write exploits quickly, thanks to the functionnalities behind it. Pwntools has python2 and python3 versions, In this course we will use the python3 version since it is the most up to date.

## Installation 

The installation is fairly simple. Make sure you have python3 and python3-pip installed on your system, then run the following: 
    
    
    
    [ 10.10.14.17/23 ] [ /dev/pts/3 ] [~]
    → which python3 pip3
    /usr/bin/python3
    /usr/bin/pip3
    
    
    [ 10.10.14.17/23 ] [ /dev/pts/3 ] [~]
    → sudo pip3 install pwn
    [sudo] password for nothing:
    
    Collecting pwn
      Downloading pwn-1.0.tar.gz (1.1 kB)
    Collecting pwntools
      Downloading pwntools-4.3.1-py2.py3-none-any.whl (10.0 MB)
         |████████████████████████████████| 10.0 MB 12.3 MB/s
    Requirement already satisfied: six>=1.12.0 in /usr/lib/python3/dist-packages (from pwntools->pwn) (1.15.0)
    Requirement already satisfied: pyserial>=2.7 in /usr/lib/python3/dist-packages (from pwntools->pwn) (3.5b0)
    Requirement already satisfied: requests>=2.0 in /usr/lib/python3/dist-packages (from pwntools->pwn) (2.25.1)
    Requirement already satisfied: pygments>=2.0 in /usr/lib/python3/dist-packages (from pwntools->pwn) (2.7.1)
    Requirement already satisfied: intervaltree>=3.0 in /usr/lib/python3/dist-packages (from pwntools->pwn) (3.0.2)
    Requirement already satisfied: paramiko>=1.15.2 in /usr/lib/python3/dist-packages (from pwntools->pwn) (2.7.2)
    Requirement already satisfied: sortedcontainers in /usr/lib/python3/dist-packages (from pwntools->pwn) (2.1.0)
    Requirement already satisfied: python-dateutil in /usr/lib/python3/dist-packages (from pwntools->pwn) (2.8.1)
    Requirement already satisfied: packaging in /usr/lib/python3/dist-packages (from pwntools->pwn) (20.8)
    Requirement already satisfied: pysocks in /usr/lib/python3/dist-packages (from pwntools->pwn) (1.7.1)
    Collecting unicorn<1.0.2rc4,>=1.0.2rc1
      Downloading unicorn-1.0.2rc3-py2.py3-none-manylinux1_x86_64.whl (8.1 MB)
         |████████████████████████████████| 8.1 MB 4.2 MB/s
    Requirement already satisfied: mako>=1.0.0 in /usr/lib/python3/dist-packages (from pwntools->pwn) (1.1.3)
    Requirement already satisfied: pip>=6.0.8 in /usr/lib/python3/dist-packages (from pwntools->pwn) (20.1.1)
    Collecting ropgadget>=5.3
      Downloading ROPGadget-6.5-py3-none-any.whl (31 kB)
    Requirement already satisfied: capstone>=3.0.5rc2 in /usr/lib/python3/dist-packages (from pwntools->pwn) (4.0.2)
    Requirement already satisfied: pyelftools>=0.2.4 in /usr/lib/python3/dist-packages (from pwntools->pwn) (0.27)
    Requirement already satisfied: psutil>=3.3.0 in /usr/lib/python3/dist-packages (from pwntools->pwn) (5.7.3)
    Building wheels for collected packages: pwn
      Building wheel for pwn (setup.py) ... done
      Created wheel for pwn: filename=pwn-1.0-py3-none-any.whl size=1220 sha256=35c1e3da705801680c0b2d0b440b1da8836bc2b32b4343d4aa751ffcf26abf78
      Stored in directory: /root/.cache/pip/wheels/34/a6/82/682ac94b58ae2e949908f11392d778574372a6cedc78b4b0a5
    Successfully built pwn
    Installing collected packages: unicorn, ropgadget, pwntools, pwn
    Successfully installed pwn-1.0 pwntools-4.3.1 ropgadget-6.5 unicorn-1.0.2rc3
    
    

If you want the full documentation on pwntools, click [here](https://docs.pwntools.com/en/stable/).

![]()

## Title 

text 
    
    
    

` ![]()

## Title 

text 
    
    
    

` ![]()

## Title 

text 
    
    
    

` ![]()

