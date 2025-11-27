---
author: loki_opsec_inc
date: 2025-07-08
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/84"
xmr: 8AaLSmixWFJhgMmrBvqi6827v27YYT6H8C6SjUasHySBKna2JDk1dtEf2ZAUpXue64JDEBxkTL9oZGaoKtcWppWKHLSkTLM
tags:
  - Core Tutorial
  - Privacy Explained
---
# Why can't I trust Server-side Encryption ? 

```
TLDR: No. Either the encryption happens on your device (E2EE using PGP for example), or the server admin will anyway be able to see the contents.
```

## Server-Side encryption is a myth

What is Server-Side encryption?

Let's say Bob is messaging Alice over the internet on Discord, a chat platform. In this example, Bob and Alice are clients, and Discord is the server.

When Bob sends a message to Alice, the message is encrypted between Bob and the server during transmission. Then, the server relays the message to Alice, encrypting the message again during this second transmission.

This means that when the server receives the message, the server can read what it says because the encryption was established only between the client (Bob) and the server (Discord).

The service or server can claim a thousand times that they are safeguarding your data, but **it doesn't matter**. You are trusting a third party and can never be sure what they will do!

If anyone like police were to come to Discord and ask for chat logs or files, Discord would be willing and able to give them all they want. This happened in 2023 when a whistleblower [leaked military documents on Discord](https://web.archive.org/web/20230601040256/https://www.washingtonpost.com/national-security/2023/04/12/discord-leaked-documents/)

![](01.png)

## The Solution: End-to-End Encryption

What is End-to-End Encryption?

Put simply, End-to-End Encryption (abbreviated as E2EE) is encryption directly between 2 clients. Only those 2 clients can read the message.

This is accomplished through a process called **asymmetric encryption, or [public key cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography)**. In this process, messages are encrypted and decrypted with a Key Pair, a Public and Private Key. The Public Key will encrypt the text, but only the Private Key can decrypt that text:

![](02.png)

You can probably see where this is going. Bob can give Alice his Public Key. Alice can use Bob's Public Key to encrypt a message. She gives that encrypted message to Bob, who then decrypts the messages with his Private Key:

![](03.png)

This can be doubled up, and Alice can also send her public key to Bob, so he can also encrypt messages for Alice to decrypt. **This is the basis for End-to-End Encryption.**

Let's take our Discord example and instead use a service that has E2EE, [SimpleX](https://simplex.chat/) ([onion](http://isdb4l77sjqoy2qq7ipum6x3at6hyn3jmxfx4zdhc72ufbmuq4ilwkqd.onion/)), which by the way, does not use a central service, but a collection of many relay servers.

Here we can see that the SimpleX relay is passing around the message. But even though the messages are going through the relays, those relays can see absolutely nothing because the text is E2EE:

![](04.png)

And if anyone, like police, contact anyone who runs these SimpleX relays, those relay admins can provide little to nothing, especially not any message content.

## Real-World Example of the Service-Side encryption fallacy

Here I'll give you an example where server-side encryption got people in big trouble and how E2EE could've saved them.

**Incognito Market**

Incognito was a Darknet Market like Silk Road that one could buy and sell illegal substances and drugs. Darknet Markets have a few possible ends: they are either seized by authorities, or they exit-scam and steal their users' cryptocurrencies that are still in their custody before disappearing. 

Or, they exit-scam and additionally extort their users for money. How are they able to do this? **By getting you to trust server-side encryption.** After years of operation, Incognito shut down and chose this option:

![](05.png)

The key detail is, **"Our auto-encrypt functionality"**. During the operation of the market, the website would offer and option to "Auto-encrypt" communications and information between buyers and sellers, faking the functionality of End-to-End Encryption.

Because there was no real key exchange happening between users, messages were being transmitted to the darknet server and were totally transparent to the server admin, which gave them material to blackmail their users with.

They saved every unencrypted message and then decided to extort the users, by threatening them to give out their sensitive data (such as their home address), to the authorities.

All of that situation could have been avoided **if users didn't trust the platform with server-side encryption.**

![alt text](image.png)

In this case for instance, Alice was lured into not encrypting her data containing her home address, before sending it to Dave, **meaning that pharaoh knew who alice was IRL, and where she lived.** Which meant that by extension when pharaoh was arrested, the authorities also knew who alice was and where she lived, which means that she was arrested aswell. All of that happened because she didn't use PGP encryption to encrypt her critical data (being her home address)

And inversely, Charlie used PGP encryption to encrypt his sensitive data containing his home address, before sending it to dave on the incognito market website, **meaning that all pharaoh could see was some PGP encrypted message, he had no way of knowing who charlie was, nor his home address.** And by extension, the authorities couldn't know either who charlie was nor where he lived, which means that he couldn't get deanonymized and arrested.

For further details on the incognito market downfall check out our blogpost [here](../incognito_market/index.md).


## How to use End-to-End Encryption?

The easiest way to use E2EE is to use software that automatically implements it, such as SimpleX which we mentioned above. 

Another way is to use it manually yourself by performing your own Public Key Cryptography using PGP, or Pretty Good Privacy. To learn how to use PGP, check out [this tutorial](../pgp/index.md).

## Conclusion

In short, never trust server-side encryption, or random websites that claim that you're definitely using E2EE while using their site.

The only encryption you can trust, is your own encryption happening on your device, such as using PGP encryption, or running [open source verifiable software](../closedsource/index.md) that implements E2EE.

