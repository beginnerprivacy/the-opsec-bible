---
author: UserSurname
date: 2025-08-02
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/389"
xmr: 82jqKSrZsUQBP8uEbzj23AhTyvh6hsoXRhvg4xsiNH8cajiUwhhqqvS9TCDac5PiAHUEYv9GYGgEKUw6GRngAxjQHSfvMQ7
tags:
  - OPSEC Mistakes
  - Not Using SimpleX
  - Clearnet Sensitive Activity
---
# Being lured into telegram for sensitive use

```
TLDR: Just like signal, you need to put your phone number to sign up on Telegram, that makes it unsuitable for Anonymous use. And because anonymity isn't there, deniability is not possible either.
```

### Introduction

You might see people offering you to contact them on Telegram for illegal services on DN platforms like Pitch/Dread.

Here's some examples:

![Offering drugs on Telegram](1.png)

![Offering counterfeit money on Telegram](2.png) 

In most cases, they either want to scam you, or want to put you behind bars.

## **Why shouldn't I use Telegram?**

Telegram has multiple intentional flaws, that make it not suitable for Private or Anonymous use.

### Telegram shares your data with Law Enforcement

>If Telegram receives a valid order from the relevant judicial authorities that confirms you're a suspect in a case involving criminal activities that violate the Telegram Terms of Service, we will perform a legal analysis of the request and may disclose your IP address and phone number to the relevant authorities. If any data is shared, we will include such occurrences in a quarterly transparency report published at: https://t.me/transparency.

source: [Telegram's Privacy Policy](https://telegram.org/privacy/eu#8-3-law-enforcement-authorities)

Note: The transparency report is locked to your registration country and placed behind a sign-up wall, you can view it without signing up [here](https://te-k.github.io/telegram-transparency/).

![](3.png)

After the arrest of Pavel Durov (Telegram's CEO) in August 2024, Telegram had a spike in amount of data handed over to LE's of various countries.

For example, in 2024, Telegram had complied to 14641 requests from Indian government, handing over information of 23535 users.

### Phone number verification

![](telegramanonymity.png)

Just like [Signal](../signalnoanonymity/index.md), to register on Telegram, **you have to provide your phone number and verify it through SMS**.

Even if you bought a fake number, you'd still have to register on it with a mobile client, since registration is inaccessible for Desktop clients.

After you create you account, anyone who knows your phone number can see your Telegram profile.

### No E2EE by default

![](telegramprivacy.png)

By default, **all your messages are stored in plaintext** on Telegram's data centers. Telegram can access them at any time and share them with Law Enforcement.

Though it does feature E2EE in Secret Chats, it is only accessible on a mobile device or a Mac, which makes it not suitable for Private use.

## **People getting prosecuted by using Telegram**

Here are examples of people getting prosecuted after using Telegram for sensitive purposes:

### Case 1:

![](case1.png)

[source](http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/post/fdf357f1ed9acddb8649)

Hacker on Dread from France registered a Telegram account to get more customers.

Consequences: Arrest with Cybercrime charges, released due to lack of evidence.

### Case 2:

![](case2.avif)

Jehanzeb Amar, 29, from London and Salahydin Warsame, 29, from Birmingham, used a Telegram bot to distribute large amounts of cocaine.

Consequences: Both imprisoned for 13 and 10 years respectively.

### Case 3:

Benjamin Hunt, 26, of Boston, used Telegram to advertise and sell a total of 2310 pills containing Fentanyl, several firearms and firearm parts for Bitcoin.

Consequences: 20 years in prison and a fine of $1 million.

## **What should i use instead?**

If you need a messenger suitable for Sensitive use, you should use [SimpleX](../anonsimplex/index.md).

It is FOSS, decentralized, uses E2E encryption by default, supports Tor routing and has deniable chats.

**Note that we DO NOT encourage using SimpleX to conduct any illegal activities, as stated in our disclaimer above.**

![](telegramsimplex.avif)

To use it, refer to our guides on SimpleX:

- [Anonymity - Easy Anonymous Chats Using SimpleX (and onion-only servers)](../anonsimplex/index.md)
- [Anonymous Simplex SMP & XFTP Servers setup](../anonsimplex-server/index.md)

## Conclusion

Telegram is a centralized service that requires going through KYC procedures (phone verification) to register, and **hands your information to LE on a silver platter**. It cannot be used neither Privately, nor Anonymously. 

Instead, [SimpleX](../anonsimplex/index.md) should be used. It features a UI somewhat similar to Telegram (easy to switch), and all the functionality required for Sensitive use.
