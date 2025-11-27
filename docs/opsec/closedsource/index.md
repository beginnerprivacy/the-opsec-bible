---
author: nihilist
date: 2024-04-29
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/261"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
tags:
    - Privacy Explained
---
# Why can't I trust closed source software for Privacy? 

```
TLDR: if the software is closed-source you cannot ever be 100% sure that you've successfully removed all spyware from it (ex: Windows / Macos). That's why you must replace all closed-source software with FOSS alternatives instead (ex: Linux).
```

"Hey, I just wrote this code, I compiled it, it gave me this .exe file, run it on your computer!

What? You want the source code? Hell no, just trust me bro!"

Or in other words, why can't I trust an adversary to not look at me when i install one of his cameras in my bedroom?



## **What is closed source software?**

To briefly explain, any software out there was first written (a developer wrote some source code, for example in the Go language), it was then compiled, and then the compilation produced a binary file (for example it became a .exe file on windows)

![](1.png)

The catch here is that when you try to reverse-engineer binary files, it's going to be very hard to figure out what the original source code was. This practice is called [Reverse Engineering](https://blog.nowhere.moe/binexp.html), a niche in cybersecurity, where someone tries to figure out what the original sourcecode was intended to be, with only the binary to work with.

One thing is for sure: you can't arrive at the original sourcecode from just the binary. It's mostly guess work.

Most software companies (which can be corporations) out there are greedy, they work hard to produce software, and they hate to have any competition. Hence they want keep their software sourcecode private, to make it as hard as possible to others to arrive at the same level of functionality. That is exactly why closed source software is used by most people. 

The most popular example out there is Windows, they would definitely not like their sourcecode to be leaked/reversed like it with [Apple's IOS](https://www.theverge.com/2018/2/8/16992626/apple-github-dmca-request-ios-iboot-source-code).

## **Privacy Is not a Spectrum**

Like we have explained [previously](../privacy/index.md), privacy is binary, you are either being watched, or you are not being watched.

![](6.png)

[Whoever tries to tell you that "Privacy is a spectrum"](https://discuss.privacyguides.net/t/should-privacy-guides-require-open-source-source-first-or-source-available-as-a-criteria-for-all-tools/22684/83) are just trying to justify that you should leave at least some closed source software on your computer if you don't feel like it, in the name of convenience.

**No you should not, you either have privacy or you don't.** You definitely do not have privacy when there are 100 cameras from 100 different adversaries in your bedroom, **and it is the same thing as with leaving ONE camera from ONE adversary in your bedroom** , the simple fact remains, **you do not have privacy as long as there is at a camera pointed at you.**

![](4.png)

When you have Windows installed, you constantly have a 100 cameras pointed at you, no matter what you do on the OS. 

When you have MacOS installed you may have 70 cameras pointed at you, you don't have privacy there all the same.

You may have linux installed with only FOSS software, except that you have installed one closed-source software such as Discord, meaning you have only one camera pointed at you, **and because of that one closed-source software you didn't remove yet, you don't have privacy either.**

![](5.png)

So when you go on communities online that pretend to talk about privacy, you need to remain vigilant to what they recommend you should do, If at any point in time it includes doing something on Windows or macOS or using any other closed-source software to have privacy, **you need to realize that they are trying to mislead you into a false sense of privacy** as shown in the examples above.

_TLDR:_ you will never have privacy until you remove ALL of the cameras in your bedroom, you do not have privacy when you have 75 cameras, nor when you have 1 camera remaining, This means that **you only have privacy once you have removed all closed-source software from your computer, and that includes permanently getting rid of MacOS and Windows**

## **Why is this relevant for Privacy?**

Privacy as a usecase on your computer requires that you only run software from which you are able to read the sourcecode of:

I can just as easily write a software (let's say a chat application like Telegram), **I can make that software grab as much information as possible** like save the computer model, serial number, get information on what other apps are running on your computer, what's the public IP address, take screenshots of what you're doing on your computer, **and I can make that application send all of that sensitive information to a remote server, while officially pretend that the additional network traffic is for "for telemetry purposes"**. 

All i need is to simply prevent you from being able to read the sourcecode, that way you have no way to disprove that this isn't actually telemetry.

What's happening is that you have no visibility on what the software is doing, **it is not transparent**

That's why the first step is always to ONLY use software that is fully free and open source (FOSS), **so that you are at least ABLE to know what the software you are running is actually doing.** To be able to achieve Transparent use.

![](3.png)

Once that's in check, you should spend some time to read the sourcecode of the software you are running. Or at the very least listen to what other privacy-minded people have to say about each piece of software. **So that you are able to know that the software does not contain any spying mechanism.**

If you find any software that actually does telemetry or any other spying mechanism, **you should remove it from your computer, if you intend to have privacy there**.

It is only once you destroy all the cameras in your bedroom, and once you close all the blinds that the adversary outside can't peek into what you're doing in your bedroom. **In the same way, closed-source software is exactly the same, a camera for an adversary (the manufacturer of that software, or the government that they act on behalf of) to peek into what you're doing on your computer.**

![](../privacy/3.png)

Keep that in mind, as this is the ABC of OPSEC you'll have to remember throughout the rest of the next blogposts i write, On any device of yours, there is only one type of acceptable software for Privacy, and that is FOSS software. It has always been this way, and will always remain this way.

If at any point in time you see people recommend closed-source software for privacy purposes, **you need to realize that they are either misled or are actively trying to mislead you into a false sense of security** , and you should remind them that **[privacy and closed-source software are mutually exclusive.](https://discuss.privacyguides.net/t/should-privacy-guides-require-open-source-source-first-or-source-available-as-a-criteria-for-all-tools/22684/62)** hence the non-negotiable need of using FOSS software for privacy.

## **Security in FOSS**

  
  


Open Source Software is **essential for security.**

A common argument made for closed source software is that it is 'more secure', often brought up in disagreements like iPhone vs Android or the general Company Software vs Community FOSS debate. 

In reality, **security is compromised and reduced when software is closed source.**

We have to first understand that perfect security is not possible. There will always be potential vulnerabilities in any software regardless of what it is. This what security patches and updates are for, changing of the software to fix issues. 

Let's compare Apple's MacOS vs the Linux Kernel as an example to display why open source is better for security. Below is an image of the top section of of Apple's security page for MacOS Sequoia 15.4. 

![](7.png)

  


Although we get brief confirmation that the listed vulnerability has been fixed, **we cannot actually verify the patch.** We have to trust that it has been fixed reliably in the MacOS source code and none of the questions listed above are answerable. 

This opens up several questions or even threat vectors. If the patch was not done properly and created a new vulnerability, we would not be able to tell. Or if a malicious government/adversary pressured them into adding a **backdoor or spyware** into a patch, we similarly would have no way of knowing. Put simply, nearly **all specifics of updates are opaque and only known to the developers.**

Below is an image of the Linux kernel's git history. 

![](8.png)

  


Unlike the one sentence security patches on the MacOS page, you can see **every single line of code that was changed** in each commit of the Linux kernel. This transparency and visibility is very important for security. 

Firstly, unlike only the Apple developers being able to patch security vulnerabilities or review the source code, **anyone can review the source code** of the Linux kernel. This means that vulnerabilities can be **searched for in the source code itself instead of just on the application layer.** The concept of security through obscurity or purposefully making software closed is flawed since that does not actually solve existing vulnerabilities. 

Having source visible almost always leads to high security since anyone can **submit patches** after their code review if they found an issue. Compared to just a single developer team for the closed source software, **the number of eyes** on the code of a piece of open source software is much higher, which means **more code review and more safety testing** , ultimately leading to greater security. 

![](9.png)

  


Moreover, the visibility is crucial: Apple can claim they fixed a critical security issue but as mentioned, we cannot review the code ourselves to check if it properly fixes it or of there is spyware/a backdoor. In open source software, we can **verify the update and make sure there isn't any spyware ourselves.**

The **transparency and availability** in open source software provides **auditable, trustable changes** and the **best possible security**. 

## **Spyware example, and how to replace it**

**Discord: a Privacy Nightmare**

Let's take a popular example: [Discord](https://spyware.neocities.org/articles/discord) as detailed in their article on spyware watchdog, it's one of the worst pieces of spyware out there. It's sourcecode is not public, and they confirm that they collect large amounts of sensitive user data (as much as they can).

Discord even goes out of it's way and contains a process logger to spy on what you do on your computer.

That service even forces you to add a phone number in case if it suspects you tried to create an account anonymously (via a vpn or via tor).

You get it, it's a nightmare for privacy and anonymity there is out of the question. The perfect governmental proxy to spy on the masses.

**SimpleX : The Decentralised and Open Source Alternative**

Take the counter example, [SimpleX](https://simplex.chat/) is an [open source](https://github.com/simplex-chat/simplex-chat) chat application. Meaning if there were any spyware to be baked into the software, you would see it in the sourcecode, and rest assured the entire open source community would go into huge turmoil to blame the developers and you would know it. 

![](2.png)

## **Remove surveillance using Open-Source Software**

To conclude, here are the requirements you need to look for, for any software that you use:

  1. It must be FULLY free and open source (FOSS)

  2. Ideally, if servers are involved, it must be self-hostable (for decentralisation) (meaning the serverside code must also be fully open-source)

([see how this is no longer the case with Signal](https://www.change.org/p/signal-foundation-resume-open-source-code-for-signal-server-do-not-close-source-it))
  3. It must implement privacy features like encryption.

  4. It should not contain any telemetry, or any spyware.

  5. It should ONLY do what it was originally meant to do.




By that standard, you can already discard software like Windows, Discord, Whatsapp, Instagram, iOS, pre-installed phone host OSes, Word, Excel, etc, as none of them are open source, and you can be damn sure that they are spying on everything you do, wilfully or not. (ever since the US government passed the [FISA section 702](https://www.dni.gov/files/icotr/Section702-Basics-Infographic.pdf).)

**YOU CAN NEVER TRUST PEOPLE.**

**SO YOU CAN'T TRUST THEIR CLOSED SOURCE SOFTWARE.**

**YOU CAN ONLY TRUST TECHNOLOGY THAT CAN BE VERIFIED!**

**SO YOU NEED TO USE OPEN SOURCE SOFTWARE!**

![](../privacy/1.png)

Now that you have the full reasoning laid out, and [if being watched by an entire crowd when you are using your computer doesn't sit well with you](../privacy/index.md), it's time for you to move out of all that surveillance, out of that theater/circus that is closed-source software (in which you are the clown on stage, for corporations to see), **it's time for you to close the blinds and declare that the show is over** to these entire crowds that have infringed upon your basic right of privacy. [It's time to install Linux](../linux/index.md).

