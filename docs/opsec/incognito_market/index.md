---
author: odysseus
date: 2025-07-07
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/365"
xmr: 83tvixnZaL5SbN8fWiPAAje4mvdZnfrJUM5H1pnbLTZmT1d6eGC1qCp7aFB7jUpt3wECm33L9quvkAVtJH4GDvYmEuoPgrr
tags:
  - OPSEC Mistakes
  - Bad Identity Segmentation
  - Not Using Monero
  - Bad Email Provider
  - Clearnet Sensitive Activity
  - KYC exchange
---

# The Downfall of Incognito Market

```
TLDR: Bitcoin is a mass surveillance tool used by law enforcement to deanonymize people and put them in jail. Don't use bitcoin and especially don't use bitcoin on centralised exchanges where you have to KYC yourself.
```

## What was Incognito Market?

**Incognito Market** was a darknet marketplace that facilitated the buying and selling of illicit drugs, connecting over **1,000 vendors** with approximately **200,000 customers**. Accessible exclusively through the **Tor network**, the platform generated revenue by charging a **5% commission** on each transaction, in addition to operating a small online casino that was introduced later. Transactions on the marketplace were conducted using **Bitcoin (BTC)** and **Monero (XMR)**.

Established in **October 2020**, Incognito Market ultimately ceased operations in **March 2024** due to an **exit scam**. This scam involved the removal of users' ability to withdraw funds from their accounts, while still allowing them to place orders and deposit money into the site.

The marketplace was managed by an individual known as **Rui-Siang Lin**, who operated under the aliases “**Pharoah**” or “**Faro**.”  Lin ran the market for approximately **four years** before executing the exit scam and was subsequently **arrested at John F. Kennedy Airport** on **May 18, 2024**.


## What were the OpSec mistakes that the owner of Incognito Market Pharoah made?

This section outlines how the FBI went after him and what the operational security (OpSec) mistakes where that led to Pharoah's arrest.

Upon finding Incognito Market law enforcement first conducted a few orders to see if the market was real and worth going after. After the drugs ordered arrived and were confirmed to be what they claim to be in the laboratory, law enforcement started working on bringing the market down.

## 1. Surveillance of Market Wallets

The FBI started with surveilling Incognito Market itself, Pharo the admin and the Bitcoin moving through the market. They observed that significant amounts of Bitcoin were being transferred from the main market wallets to the administrator wallet, associated with Pharo.

## 2. Pharo talking too much

Pharo wrote on dread about his Bitcoin being seized during a swap, detailing the time and amount involved. Law Enforcement thanks to the information given found the mentioned transaction and with that further confirmed that wallet belonging to him and knew now that he was using swapping services to get his bitcoin into monero and then cashing out the monero.

## 3. Monitoring of Fund Transfers

The authorities monitored how Pharo's wallet, which was directly receiving funds from the market, was subsequently sending money to a centralized swapping service to convert it into Monero (XMR). Minutes later, an account on a Know Your Customer (KYC) requiring exchange received nearly identical amounts.
(Law enforcement doesn't state what exchange he used, but it's believed to have been Binance or Kraken)

![](0.png)

## 4. Personal Information Discovery

After Pharoah repeatedly converted btc to xmr and cashed out with his KYC'd account the FBI obtained information linked to the KYC account, revealing personal details of Rui-Siang Lin, including his email address, driver's license, and phone number.

![](1.png)

## 5. Domain Purchases

Additionally, Lin utilized funds from the Incognito Market’s administrator wallet to purchase at least four internet domains on Namecheap. Three of these domains were related to darknet markets (one even was a direct promotion site for Incognito Market), while the fourth was a personal site for Rui-Siang Lin (his personal site is down now but can be viewed on [the web archive](https://web.archivep75mbjunhxc6x4j5mwjmomyxb573v42baldlqu56ruil2oiad.onion/web/20240920135220/https://rs.me/)). The Namecheap account was also registered to Rui-Siang Lin and shared the same email address and other information as the KYC crypto account.

![](2.png)

## 6. Email Evidence

After obtaining a warrant for the email which he used for the Namecheap and his KYC'd crypto account, investigators discovered that Lin had emailed himself a plan for a darknet market prior to the launching of Incognito Market.

![](3.png)

## 7. Server Search and Software Findings

Following a warrant to search the market's servers (of which the FBI doesn't state how they found), authorities found software to run the market on the servers that Lin had also made available on his personal GitHub, which is linked on his personal site, [rs.me](https://web.archivep75mbjunhxc6x4j5mwjmomyxb573v42baldlqu56ruil2oiad.onion/web/20240920135220/https://rs.me/).

Those tools include:

- **[“PoW Shield”](https://github.com/RuiSiang/PoW-Shield)**: A tool designed to combat DDoS attacks.
- **[“Monero Merchant”](https://github.com/RuiSiang/monero-merchant)**: A tool that facilitates online payments in XMR.
- **[“Koa-typescript-framework”](https://github.com/RuiSiang/koa-typescript-framework)**: A web framework utilized as a foundation for web applications.

Lin also participated in an [interview on YouTube](https://www.youtube.com/watch?v=zeNKUDR7_Jc) regarding the DDoS attack prevention tool he developed and used on Incognito Market as well as putting it on Github.

![](4.png)

## 8. Search Activity During Server Take Down

Furthermore, it was discovered that when authorities took down a server and were copying its content, Lin began searching on Google, while logged in, for ways to restore the server. Looking into his older search history its clear how his searches correlate with activities surrounding the market and Pharoah.

| Date and Time (UTC)         | Activity Description                                                                                          |
|------------------------------|---------------------------------------------------------------------------------------------------------------|
| May 7, 2021, 08:51          | Lin googled “one pixel attack for fooling deep neural networks github.”                                      |
| May 7, 2021, 08:51          | Lin visited "GitHub URL-1."                                                                                  |
| May 7, 2021, 18:40          | Lin, as "Pharoah", posted on Dread a post titled “A Proposal for ML-proof improvement on DeCaptcha.”             |
| May 7, 2021, 18:40          | In the post, Lin states, “One pixel attacks should deem the spammers/DDoSers ML efforts to fail.”            |
| May 7, 2021, 18:40          | The post also contains "GitHub URL-1" for further reading on the topic.                                      |
| September 2, 2021           | Lin googled “provable fair calculator.”                                                                      |
| September 3, 2021           | Lin googled “slot game terminology.”                                                                         |
| September 4, 2021           | Several searches related to animating dice rolling.                                                           |
| September 5, 2021           | Several searches regarding playing cards, poker, and blackjack.                                               |
| September 7, 2021           | Several searches regarding animating card flips and blackjack mathematics.                                     |
| September 7, 2021           | Incognito Market "Changelog" lists "Integrated online casino Incogitobets."                                  |
| September 15, 2021          | Admin posts on Dread that Incognito Market now offers Incognitobets with a “provably fair mechanism.”        |
| September 19, 2021          | Lin googled “three-way conversation.”                                                                        |
| September 20, 2021          | Admin announces that the Market now offers a new dispute system with “per-order three-way chats.”            |
| February 7, 2022            | Lin googled “cryptopunk generator js,” “array.reduce,” “get random in array,” and “js random true false.”   |
| February 28, 2022           | The Market's Changelog says "Added punk avatars, unique generated icons that represent you."                  |
| March 1, 2022               | Admin also says on Dread “added punk avatars: randomly generated icons that represent you.”                   |
| July 19, 2022, 23:30        | LE shut down a server and copied its data.                                                                    |
| July 20, 2022, 00:18        | Lin googled "pm2 crashed.”                                                                                    |
| July 20, 2022, 00:19        | Lin googled “view pm2 daemon logs.”                                                                          |
| July 20, 2022, 00:20        | Lin googled “pm2 daemon logs.”                                                                               |
| July 20, 2022, 00:23        | Lin googled “pm2 changelog,” indicating attempts to restore server functionality.                             |

![](5.png)


## 9. Financial Discrepancies

The FBI having access to his employment history couldn't find a way of explaining were the money he was getting came from. He himself was also unable to provide an explanation for the substantial amounts of money he was receiving, which also increased as the market expanded.


## What should Pharoah have done differently?

Firstly, he should have read our article on [The True Goal of Crypto](http://opbible7nans45sg33cbyeiwqmlp5fu7lklu6jd6f3mivrjeqadco5yd.onion/opsec/truecrypto/) and removed Bitcoin from the Incognito Market. This action would have made it impossible for the FBI to trace his and the market's transactions to begin with.

In addition, he should also have read our article on [Internet Segmentation](http://opbible7nans45sg33cbyeiwqmlp5fu7lklu6jd6f3mivrjeqadco5yd.onion/opsec/internetsegmentation/) and [How to Keep Identities Separated](http://opbible7nans45sg33cbyeiwqmlp5fu7lklu6jd6f3mivrjeqadco5yd.onion/opsec/multiple_identities/) to avoid making it easy for the FBI to link him to his darknet identity. To conduct these steps correctly, he should have avoided centralized services like Google, the swapping service he used, or the exchange where he completed KYC (Know Your Customer) verification.

Instead of Google, he should have utilized a service that is not designed to spy on their users, such as [DuckDuckGo](https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/) or [SearXNG](http://searxspbitokayvkhzhsnljde7rqmn7rvoga6e4waeub3h7ug3nghoad.onion/) through [Tor](http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/), which function just as effectively.

Rather than relying on a centralized swapping service that can seize funds, as happened to him, he could have used a service like Retoswap. Providing his information on a centralized exchange merely to cash out his money was also a significant mistake. Instead, he should have read our article on [Why One Can't Trust Centralized Exchanges](http://opbible7nans45sg33cbyeiwqmlp5fu7lklu6jd6f3mivrjeqadco5yd.onion/opsec/chainalysisattempts/) and subsequently our guide on [How to Use Haveno DEX](http://opbible7nans45sg33cbyeiwqmlp5fu7lklu6jd6f3mivrjeqadco5yd.onion/opsec/haveno-client-f2f/) to cash out or purchase Monero in a more secure manner.

Lastly, instead of backing up any sensitive data on services like Gmail, which he should not have used in the at all, he should have read our guide on [how to properly back up sensitive data](http://opbible7nans45sg33cbyeiwqmlp5fu7lklu6jd6f3mivrjeqadco5yd.onion/opsec/plausiblydeniabledataprotection/).

After following all of these steps, there may still be ways to compromise one's operational security (OpSec). For instance, by simply speaking too freely, as he did on Dread. Therefore, it is important not only to use the right tools but also to behave appropriately, as explained [here](http://opbible7nans45sg33cbyeiwqmlp5fu7lklu6jd6f3mivrjeqadco5yd.onion/opsec/opsec/).
