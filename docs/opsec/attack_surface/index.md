---
author: odysseus
date: 2025-07-21
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/363"
xmr: 83tvixnZaL5SbN8fWiPAAje4mvdZnfrJUM5H1pnbLTZmT1d6eGC1qCp7aFB7jUpt3wECm33L9quvkAVtJH4GDvYmEuoPgrr
tags:
  - Opsec Concepts
---

# What is my Attack Surface ?

```
TLDR: Your attack surface is a target for the adversary throw darts at. 
- Privacy is about making the target small,
- Anonymity is about hiding the target amongst as many other targets as possible, 
- Deniability is about making it impossible for the adversary to prove that there is a target.
```

Now we will discuss the concept of "Attack Surface," its significance, and strategies to minimize it.

## What Law Enforcement needs to arrest you.

Imagine a scenario where you teach your friend how to use Monero, and we are in a future where this action is deemed illegal. What does law enforcement need to arrest you for this?

First, they must be aware that the action occurred, and then they need to identify the individual responsible in order to make an arrest.

To obtain this information, law enforcement monitors all activities, ensuring they can detect any undesirable actions. However, merely observing events is insufficient. They also mandate identification through methods like [KYC (Know Your Customer)](https://en.wikipedia.org/wiki/Know_your_customer) to connect individuals' identities with their monitored actions.

![](../governments/3.png)


## What does Attack Surface mean?

Imagine a dart game. You are the target, and law enforcement is throwing darts at you. If you have a big attack surface, it will be easy for law enforcement to hit you. To prevent that, you want to make it as hard as possible for law enforcement to hit you. So, the attack surface is a way of measuring how easy it is for law enforcement or any adversary to get you.

Now, there are different ways of making it harder for any adversary, like law enforcement, to hit you while still being able to tell your friends how to use Monero.

### Privacy

We use [privacy](../privacy/index.md) to make our target as small as possible by hiding our actions from law enforcement, making it harder to surveil and see everything going on.

This means that instead of Twitter, Facebook, or any other public place where everyone, including your adversary (for example, law enforcement), can see what's happening, you would go to something like SimpleX, where you are safe from anyone surveilling you.

![](1.png)

### Anonymity

We use [anonymity](../anonymityexplained/index.md) to hide our target in between other targets, making it harder for law enforcement to know who is who.

This means that instead of Telegram, Signal, or any other place that requires you to give up personal information, helping your adversary (for example, law enforcement) to identify you, you would use SimpleX with Incognito profiles.

![](2.png)

### Deniability

We use [deniability](../deniability/index.md) to deny the existence of the target altogether. Law enforcement can't hit a target that doesn't exist.

This means that instead of using normal SimpleX chats, you use Incognito profiles and enable disappearing messages so you can deny they ever existed.

![](3.png)

## Clearnet vs Darknet

When trying to make it harder for law enforcement to hit you, things like deciding between the clearnet and the darknet are important. Law enforcement loves the clearnet because it can surveil and identify everyone in it. On the other hand, it's harder to see what's going on in the darknet, so the target gets smaller. All the darknet users also pretty much look the same; therefore, hiding the target among other targets makes it hard for law enforcement to identify someone. Smart people who read the OPSEC Bible, like you, also know how to use the darknet to deny the existence of the target. All of this makes law enforcement hate the darknet and its superiority over the clearnet, where they can clearly see what is being done and by whom.

For example, if you want to host a website on the clearnet, you have to [pay for a domain](../anondomain/index.md) and for [server hosting](../anonymousremoteserver/index.md). An adversary like law enforcement could still decide to take it down in various ways. Law enforcement could tell your server provider to shut it down, go and shut it down themselves, or directly take the domain away from you.

When [hosting a website on the darknet](../torwebsite/index.md), you don't have to pay for hosting or a domain, and law enforcement cannot take it down since they don't know where the server is.

![](../clearnetvsdarknet/3.png)


## How attack surface applies to software

Imagine a PC with no software installed. The attack surface would be minimal since there is essentially nothing to exploit. Now, consider installing an application that contains 100 lines of code. The attack surface increases because there could be a vulnerability in the code; however, since it is only 100 lines, you could review it to ensure everything is functioning correctly. 

After installing the first application, if you then install another one with 1,000 lines of code, followed by one with 10,000 lines, your attack surface expands significantly. This is due to the numerous potential vulnerabilities in the code, and it becomes impractical to thoroughly review extensive lines of code to understand everything. This illustrates why bloated software is detrimental.

This example demonstrates how the quantity of software, particularly bloated software, impacts the attack surface. However, most individuals do not stop there. Many people use software that is not free (as in freedom). What implications does this have for their attack surface? Utilizing non-free software is one of the most detrimental actions a person can take regarding their attack surface. This is because, as you use such software, your attack surface could already be compromised, potentially expanding to a point where it is highly vulnerable, or it may remain unchanged. Since you cannot inspect or modify the code, you must assume that it is malware, and no one would willingly install malware on their PC.

Given this understanding, it is advisable to use only non-bloated, free (as in freedom) software. Therefore, if you are still using malware like Windows, macOS, Android, iOS, or others, you should consult our guides on [how to install GNU/Linux](../linux/index.md) for your computer and [GrapheneOS](../graphene/index.md) for your phone.

![](4.png)
