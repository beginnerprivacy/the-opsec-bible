---
author: nihilist
date: 2025-01-05
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/294"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
tags:
    - Serverside Privacy
    - Self-Hosting
---
# Why should I self-host my own services? 

```
TLDR: to be able to achieve serverside-privacy
```


## **What is Self-Hosting ?**
    
    
    Self-hosting is the practice of running and maintaining a website or service using a private web server, instead of using a service outside of the administrator's own control. Self-hosting allows users to have more control over their data, privacy, and computing infrastructure
    	
    

In short, **Self-hosting is about running servers and services at your own home, rather than somewhere else.**

## **Do i have privacy when using remote services ?**

First of all, if you made sure that your laptop isn't running any closed-source software, then the privacy of what you do on that device is maintained, however you need to realize that **if you run a software (ex: google's onedrive), then the actual use of the service happens on a remote server, that is not controlled by you:**

![](1.png)

You don't control Google's servers, therefore everything you do on that service is permanently logged from THEIR end. Moreover, the ISP also logs where you connect to, so if you didn't use a [VPN](../vpn/index.md), then the ISP is also aware that you connected to google's servers. In short, **if you don't control the server the service operates on, then EVERYTHING that you do on that service is seen by the one running said service, which can cooperate with the adversary.**

![](3.png)

The same holds true if you intend to rent a remote VPS / dedicated server to run a service that you intend to control. Still here the server is not controlled by you, **therefore even if you run a FOSS service on that remote server, the adversary (the cloud service provider in this case) can still potentially see that you're running said service and what you're doing with it.** You don't control the server, therefore you can't hide what you do on that server without end to end encryption (e2ee).

![](../pgp/1.png)

As we have covered previously in our [PGP tutorial](../pgp/index.md), we cover an example of PGP messaging, where each party (bob and alice in this case) manually encrypt their messages, before sending it over untrusted messaging platforms such as Discord, or Whatsapp, or wherever else.

![](../pgp/2.png)

If you intend to have privacy on the serverside, especially when you don't control the remote server that runs the service you're using, then **End to End Encryption (E2EE) is a hard requirement** as it makes sure that the data is encrypted from your local device (where you have privacy, if you followed the FOSS-only software requirement), before being sent to the untrusted remote servers. **That way, the adversary can only see encrypted data, and they are unable to decrypt it.**

## **Self hosting and it's advantages**

![](2.png)

In practice, this can simply be a home server (which can just be an old desktop) that you decided to run some FOSS services on. If an adversary were to spy on it, said adversary would either require to use a closed-source software that you installed on the server (which obviously should NOT happen if you follow the FOSS software requirement), or they would have to literally bust down your door, and get physical access to the server to be able to do something about it. 

**_TLDR:_ the requirement for server-side privacy is either to use end to end encryption (e2ee), or to use a server that can only be physically accessed by you alone.**

If you want some examples on what services you can self-host, you can check out our archived [self-hosting tutorials](../../selfhosting/0_lainradio/index.md)

