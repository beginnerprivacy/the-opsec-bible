---
author: nihilist
date: 2025-08-25
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/71"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
tags:
  - Core Tutorial
  - OPSEC Concepts
---
# Internet Usage Segmentation Setup

```
TLDR: 
- Windows VM for public use, 
- Kicksecure VM for private use,
- Whonix VM for anonymous use, 
- Whonix VM in a veracrypt hidden volume for sensitive use.
- Public / Private / Anonymous profiles separation on your grapheneOS phone, with duress password for sensitive use
```

In this tutorial we're going to cover how to properly segment your internet usage. This is the most common opsec practice that you should always use. We're going to base ourselves off from the pyramid of internet use that we have seen [previously](../opsec4levels/index.md), to be able to replicate each of the 4 OPSEC levels into our current setup:

![](../opsec4levels/0.3.png)

Additionally, remember that our recommendations are **EXCLUSIVELY** for personal devices. Do not use work devices from your employment for personal uses, and vice versa. **Personal devices = Level 0-3** OpSec levels. **Work devices = Level 0** public use and nothing else.


## **Different Internet Usage**

The most common OPSEC mistake out there is the lack of internet usage segmentation. Most people don't have this reflex when they first discover Anonymity and Privacy online. Thing is, **it is not possible to be fully anonymous for everything that you do online** , there will always be some service that is vital to you, which you will need to access with your real world identity (for example, to access your bank account, or some insurance website, etc). However it is definitely possible to implement proper internet usage segmentation:

In this case we're going to differentiate 4 types of Internet usage:

![](2.png)

_Internet Uses:_

  1. _Public use_ : What you do is public knowledge

  2. _Private use_ : What you do is NOT publicly known

  3. _Anonymous use_ : What you do is meant to be done without revealing your identity

  4. _Sensitive use_ : What you do is meant to remain secret at all cost, only to be known by you




With each different Internet usage, we have different requirements:

![](3.png)

_Requirements:_

  1. _Public use_ : No requirement ; you can use closed source software (meaning it's all public), using your IRL identity

  2. _Private use_ : only open source software, + you use a pseudonym instead of your IRL identity

  3. _Anonymous use_ : open source, using a random, meaningless identity not sensitive

  4. _Sensitive use_ : open source, using an other random meaningless identity, **AND if the adversary seizes the device, they musn't be able to prove the existance of the Sensitive VM**




Now with this we identified the 4 most typical internet use cases, and their requirements.

## **Identity Management**

As we said previously, segmentation is required for each internet use. This extends to the Identity you use online. For example you cannot use your real name when trying to use the internet anonymously. So you need a different identity for each use case: 

![](4.png)

_Different Identities:_

  1. _Public Identity_ : **Linus Torvalds** (used on websites that ask for your identity) 

  2. _Private Identity_ : **Nihilist** (used on websites that may KYC, but pseudonym is preferred)

  3. _Anonymous Identity_ : **ZacharyJr** (used on anonymous websites, non-sensitive use)

  4. _Sensitive Identity_ : **Dread Pirate Roberts** (used on anonymous websites, sensitive use)




The important thing here is that you must make sure that each identity have nothing in common, **it must always remain impossible for and adversary to be able to link those identities together.**

## **Multiple Virtual Machines (VMs)**

To help you implement your internet usage segmentation, you can use VMs to make sure the segmentation is present inside the system:

![](5.png)

_Virtual Machines:_

  1. _Public use_ : No requirement ; you can use a windows VM for all closed source software and KYC use

  2. _Private use_ : you can use a Debian VM, with only open source software (ex: [SimpleX chat](../privatesimplex/index.md))

  3. _Anonymous use_ : you can use Whonix VMs (it forces every connection to go through Tor)

  4. _Sensitive use_ : You can use Whonix VMs, but they need to be inside a [Veracrypt hidden volume](../veracrypt/index.md)

_Sidenote:_ [QubesOS](../../selfhosting/qubesos/index.md) is based off the same segmentation principle, that every use must remain isolated (or compartmentalized) into VMs, for specific uses. It also uses Linux and Whonix VMs, while using the Xen hypervisor instead of libvirtd QEMU/KVM, but the concept remains the same. 


## **Multiple GrapheneOS Profiles**

You can also accomplish segmentation on your GrapheneOS device by the use of [User Profiles](https://grapheneos.org/features#improved-user-profiles).

![](./graphene-segmentation.png)

_Graphene OS Profiles:_

  1. _Public profile_ : No requirement ; you can use this all closed source software and KYC use for your Public Identity

  2. _Private profile_ : you can use with only open source software (ex: [SimpleX chat](../privatesimplex/index.md)) and be sure you're at least [using a VPN](../vpn/index.md#opsec-recommendations-1).

  3. _Anonymous profile_ : you can only use FOSS software and route everything through Tor (using [InviZible Pro](http://fdroidorg6cooksyluodepej4erfctzk7rrjpjbbr6wx24jh3lqyfwyd.onion/en/packages/pan.alexander.tordnscrypt.stable/) or [Orbot](https://orbot.app))

  4. _Sensitive usage_ : As Graphene does not have Hidden Profile or something akin to a Veracrypt Hidden Volume. Sensitive Use activities are limited to having SimpleX Chat with a [hidden chat profile](http://isdb4l77sjqoy2qq7ipum6x3at6hyn3jmxfx4zdhc72ufbmuq4ilwkqd.onion/blog/20230328-simplex-chat-v4-6-hidden-profiles.html), as well as the use of the [GrapheneOS Duress Password/PIN](../duresspin/index.md).


Something very important to remember, since we are talking about internet usage, is that firstly, when you install a VPN one user profile, this VPN does NOT carry over to another user profile

However, this is also true for [Work Profiles](https://discuss.grapheneos.org/d/1014-work-profiles) and [Private Spaces](https://discuss.grapheneos.org/d/16670-private-space-on-android-15-grapheneos), which live inside of User Profiles. So for example, if you install Mullvad VPN inside of the standard space (sometimes called "Personal" or "Owner" profile) of the user profile, and then you browse the web with Firefox that is installed on the Work Profile or in the Private Space, those connections will NOT route through the Mullvad VPN, because they have their own dedicated VPN slots.

![](./profile-internet-traffic.png)

## **Internet Usage Segmentation Recap**

Now with this setup, one can segment their Internet use with a system implementation (VMs) along with the associated Identities for each usecase.

![](6.png)

And the same with Graphene OS profiles:

![](./graphene-segment-identities-recap.png)

For further details on how to dissect your OPSEC, check out this tutorial [here](../opsec/index.md), because using the right technologies is only the first half of the work, you also need to have the correct behavior while using them.

