---
author: nihilist
date: 2024-08-14
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/87"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
tags:
  - Anonymity Explained
---
# Why isn’t Privacy enough for Anonymous Use?

```
TLDR: It's easy to deanonymize VPN users.
```

In this post we are going to see why Privacy is not enough for Anonymous Use, and what can be done about it.

## **Why isn’t privacy with a VPN enough?**

Bob is using an open-source browser and a VPN to access a website (in our example youtube), but then he starts thinking that it's enough to start to use that website anonymously, even though they don't allow it. **He starts to sign up and mentions a false name and address when creating an account. which infuriates the Youtube employee:**

![](3.png)

Bob's current setup is suitable for Private use as he is using [open source software](../closedsource/index.md), and a [VPN](../vpn/index.md), **But is it suitable for Anonymous use too ?**

When you think about it, currently He is anonymous, as he hides his real IP from the destination website, and he didn't deanonymize himself through his actions while on the website. **The problem is how expensive is it to deanonymize Bob ?**

To answer that, let's take the example of a Youtube employee being infuriated that Bob dared to lie about his personal information, and the employee decides to call some corrupt police agents (yes they have very close ties to the authorities) to do their bidding in order **to scare the VPN provider into revealing the real IP of whoever connected as Charlie Chaplin on youtube.com** , around the time where Bob signed up, in order to deanonymize Bob.

![](2.png)

The end result is that the VPN provider has to give the data they have to the authorities, ([which only works if they keep logs!](https://www.pcmag.com/news/mullvad-vpn-hit-with-search-warrant-in-attempted-police-raid)) and reveal Bob's Identity, and that only cost a few pennies to the adversary (here the youtube employee) to deanonymize Bob. 

_Conclusion:_ Bob's setup is not suitable for Anonymous use, **because it is inexpensive for an adversary to deanonymize him.**

This situation would have been avoided had Bob used [Tor](../anonymityexplained/index.md), **which makes deanonymization attacks as expensive as possible.**

![](../torvsvpns/5.png)

