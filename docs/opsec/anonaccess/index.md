---
author: nihilist
date: 2024-05-02
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/111"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
tags:
  - Serverside Anonymity
---
# Remote anonymous access setup (SSH through Tor) 

```
TLDR: you can access VPSes anonymously, by routing the SSH connection through Tor
```

![](../context/anon_remote.png)

## **Initial Setup**

On your server, edit the torrc file like so:
    
    
    [ Datura ] [ /dev/pts/9 ] [~]
    → cat /etc/tor/torrc
    
    HiddenServiceDir /var/lib/tor/onions/daturab6drmkhyeia4ch5gvfc2f3wgo6bhjrv3pz6n7kxmvoznlkq4yd.onion/
    HiddenServicePort 22 127.0.0.1:22
    HiddenServicePort 80 127.0.0.1:4443
    	
    

Then just edit your local .ssh config to access it:
    
    
    [ mainpc ] [ /dev/pts/7 ] [~]
    → cat .ssh/config
    Host tortura
            User root
            hostname daturab6drmkhyeia4ch5gvfc2f3wgo6bhjrv3pz6n7kxmvoznlkq4yd.onion
            IdentityFile ~/.ssh/torified
    
    Host datura
            User root
            hostname 65.109.30.253
            IdentityFile ~/.ssh/torified
    	
    

Then connect to the host by forcing SSH to go through tor, thanks to torsocks:
    
    
    [ mainpc ] [ /dev/pts/5 ] [~]
    → systemctl restart tor@default
    
    [ mainpc ] [ /dev/pts/5 ] [~]
    → torsocks ssh tortura
    The authenticity of host 'daturab6drmkhyeia4ch5gvfc2f3wgo6bhjrv3pz6n7kxmvoznlkq4yd.onion (<****no hostip for proxy command>)' can't be established.
    ED25519 key fingerprint is SHA256:A0CFTeUixGoK96VenBQ7Z2U8kX5olDCqBvBNeJUfs6I.
    This host key is known by the following other names/addresses:
        ~/.ssh/known_hosts:144: [hashed name]
    Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
    Warning: Permanently added 'daturab6drmkhyeia4ch5gvfc2f3wgo6bhjrv3pz6n7kxmvoznlkq4yd.onion' (ED25519) to the list of known hosts.
    Enter passphrase for key '/home/nihilist/.ssh/torified':
    Linux Datura 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01) x86_64
    
    The programs included with the Debian GNU/Linux system are free software;
    the exact distribution terms for each program are described in the
    individual files in /usr/share/doc/*/copyright.
    
    Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
    permitted by applicable law.
    Last login: Thu May  2 14:47:23 2024 from 178.255.149.178

For instance, this is how you can access a server that is in an isolated LAN (such as in your home network), without requiring to port-forward anything.

But keep in mind that the latency is going to be higher due to the 6 hops circuit (since we're doing it via the .onion link, rather than connecting to the IP directly). The length of the circuit is due to requiring to use the rendez-vous mechanism, since we're using the .onion domain.

