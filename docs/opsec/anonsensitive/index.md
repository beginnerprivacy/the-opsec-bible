---
author: Robert
date: 2024-06-08
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/0"
xmr: 871Hun183Cc2yXRmP4cEeUG8uiCkXfZPFQt5WVK6tCgxedWTXrpFGNTi9aRgknjYsh3jCD6iY9eyxMpGdr4xNyDNT7ZrKsK
tags:
  - Deniability Explained
---
# Why isn’t Anonymity enough for Sensitive Use?

```
TLDR: an adversary could bust down your door and force you to type a password (legally, ordered by the judge).
```

In this post we are going to see why Anonymity is not enough for Sensitive Use, and what can be done about it.

## **What happens when you are forced to give out your password?**

Let’s say that Bob is using a popular online forum to leak information about a government agency’s unethical behavior. To stay anonymous, he makes sure to connect to the forum using Tor at the very minimum. He uses a burner email address to sign up to the forum and upload the sensitive files. His Anonymity during this sensitive action remains intact.

![](1.png)

However, there are only 10 people who could have originally had access to the leaked information, and Bob is one of those 10 potential suspects. 

The adversary makes use of key disclosure legislation to issue search warrants to all 10 people, and to get to know the contents of their personal drives. Essentially, the adversary doesn’t have anything solid against any of them, since the perpetrator’s anonymity is intact, **but some guess work is being done to try and find something incriminating anyway.**

![](6.png)

Here’s the problem: the adversary can just bust down Bob’s door and **force him to unlock his laptop, including every encrypted volume.** What happens then?

![](../deniability/4.png)

![](../logos/de2.png) **Since Bob has no other choice but to comply when the adversary forces him to unlock his hard drives, and since he didn’t implement Deniable Encryption** , he has to show all the incriminating evidence, and therefore he can no longer deny implications with the sensitive activity.

![](5.png)

Bob’s setup, although suitable for Anonymous Use, is not suitable for Sensitive Use **due to the lack of Deniable Encryption**

![](../logos/de0.png)For instance, if Bob had implemented [VeraCrypt’s deniable encryption](../veracrypt/index.md) to store the sensitive data, **he could’ve given password A to open the decoy volume for the adversary, and could’ve claimed that there was no hidden volume. The adversary would have no way to prove otherwise.**

