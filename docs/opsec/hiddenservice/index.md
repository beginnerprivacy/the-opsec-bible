---
author: nihilist
date: 2024-08-06
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/105"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
tags:
  - Serverside Anonymity
---
# Where to host Anonymous Hidden Services ? 

```
TLDR: either host them on VPSes, baremetal servers or on your homeserver.
```

In this tutorial we're going to look at where exactly you can host Hidden Services Anonymously.

## **Hosting a Hidden Service Remotely**

![](../context/anon_remote.png)

One way to host a Hidden Service is remotely. You anonymously rent a VPS to a non-KYC cloud provider (using Tor and Monero), and use it anonymously (using SSH through Tor), to host a Tor Hidden Service. 

![](1.png)

The main advantage here is that if anything goes wrong (if you try to run a sensitive service there), you are safe from any repercussions, as the cloud provider can't know that it was you who bought and used the VPS.

The strategy here is that whatever service you try to run, you run it as far away from your home as possible. So that if one day the location of the hidden service gets found out (as tor traffic sometimes get deanonymized, when the tor circuits go through nodes that all belong to the adversary), your home IP address doesn't get revealed.

_Sidenote:_ know that if you try to run a sensitive service, you are literally abusing the goodwill of non-KYC cloud providers, that are willing to go the extra mile to provide anonymity for you. So please don't bite the hand that feeds you, don't run sensitive services on VPSes, as the non-KYC cloud resellers are the ones that will have to deal with the consequences afterward.

The main drawback however, is that you are not in physical control of the server that you are using, therefore if the cloud provider has implemented extensive spying mechanisms, they will immediately find out that it is this VPS that is running said hidden service.

_TLDR:_ it's safer in case if anything goes wrong, but you don't have physical control over the service.

## **Self-Hosting a Hidden Service**

![](../context/anon_self.png)

Another way to host a Hidden Service is locally, you Self-host it. You are running a server at home (which could be your previous PC), to run the hidden service. And if the ISP doesn't allow Tor traffic, you use a VPN to hide the Tor traffic.

![](2.png)

The main advantage here is that you have complete control over the server, if an adversary has to get his hands on the server, he has to bust down your door and find it.

The strategy here is "I use secure technology, come at me!", Which brings us to the main disadvantage however: if the technology fails you along the way for example the adversary uses a Tor 0day on you, and finds out that the hidden service is at your home IP address, then there is no way you can deny that you are the administrator of said service. In that case, using a trusted VPN that regularly deletes logs like mullvadVPN, to hide the Tor traffic, might be a lifesaver. 

![](0.png)

There may be other attacks to figure out if you are the owner of said hidden service, like temporarily shutting down the power, or the internet connection, to see if the hidden service goes down or not.

_TLDR:_ you have physical control over the server, but if anything goes wrong, the service is at your house. No possibility to deny that you are the administrator!

