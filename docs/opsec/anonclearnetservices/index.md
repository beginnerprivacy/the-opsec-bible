---
author: nihilist
date: 2024-08-06
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/105"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
tags:
  - Serverside Anonymity
  - Clearnet Services
---
# Where to Host Anonymous Clearnet Services ? 

```
TLDR: you can host clearnet services remotely as long as you do everything through Tor, or self-hosting them by routing the traffic through Tor to a remote VPS
```

![](../context/anon_remote.png)

![](0.png)

In this tutorial, we're going to explain how you can have anonymous clearnet services, which can either be remotely or self-hosted. 

## **Hosting an Anonymous Remote Clearnet Service**

The first way to have an anonymous clearnet service is remotely, where you go through a non-KYC cloud provider and a non-KYC domain provider in order to obtain a remote VPS and domain anonymously (using Tor and Monero).

![](1.png)

The idea here is that you always keep Tor between you and the services, so that it remains impossible to prove that you are the owner of said service, from the acquisition of the services to their actual use (forcing SSH to go through Tor).

## **Self-Hosting an Anonymous Clearnet Service**

The second way to have an anonymous clearnet service is by self-hosting it. Like above, you also need to get yourself a VPS and a domain anonymously, using non-KYC providers/resellers. The VPS must have OpenVPN installed on it.

Then you need to have a home server running a local service (let's say with ports 80 and 443).

That same local home server must connect to the OpenVPN server, but you must force the VPN connection to go through Tor to avoid revealing your home IP to the cloud provider.

From there, you will be able to port-forward the ports from your local service to the VPS while maintaining your anonymity. 

And of course, if your ISP doesn't allow Tor traffic, we can always hide it using a trusted VPN, like MullvadVPN.

![](2.png)

Note that such a setup is to be done only when you want to have your server data at home (for example, [self-hosting a mail server while maintaining anonymity](../mailprivate/index.md)). If this is not a concern, then you should just host the service remotely as seen above.
