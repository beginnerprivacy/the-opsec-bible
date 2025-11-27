---
author: loki_opsec_inc
date: 2025-07-14
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/403"
xmr: 8AaLSmixWFJhgMmrBvqi6827v27YYT6H8C6SjUasHySBKna2JDk1dtEf2ZAUpXue64JDEBxkTL9oZGaoKtcWppWKHLSkTLM
---

# Improper Monero Usage

```
TLDR: Monero must be used correctly to be ensure that privacy and anonymity are preserved while using it.
```

For all intents and purposes, Monero is virtually untraceable, but only in a vacuum, that is, within the context of Monero itself. Monero cannot protect things that are outside of itself. It cannot obfuscate real life and cannot protect your from social attacks. What you do outside of it can easily de-anonymize your activities. 

In this post we are going to be dealing with various mistakes and pitfalls to avoid when handling your Monero and other financial matters. We will show you how to avoid them. Then we will give you some real-world examples of people who didn't take care of those mistakes and paid the price.

Throughout this post we will reference several different concepts that you should already be familiar with from our [Decentralised Finance series](../truecrypto/index.md), so please explore that first before tackling this article. We also assume that you already understand the basics of how to use Monero.

For additional reading we highly recommend to check this site as well, for basic info on how to avoid various leaks and some real-world examples: [MoneroLeaks.xyz](https://moneroleaks.xyz) | [Archive.org onion](https://web.archivep75mbjunhxc6x4j5mwjmomyxb573v42baldlqu56ruil2oiad.onion/web/20250710044032/http://moneroleaks.xyz/)

## Always Transfer To and From Your Own Wallet

The first important thing you should always remember is to never treat any exchange as your personal wallet. The exchange has all the client-side information on that transfer including the transaction ID and private keys. A transfer from a centralised exchange is no more private than Ethereum or Bitcoin. Remember this when dealing with Monero transaction:

**The sender is only as private as the endpoint from where the Monero was sent**

If your endpoint (meaning, server or device controlling the wallet) isn't private, then your transaction isn't private.

![](./b2b-xmr.png)

## Timing/Amount Correlation Attacks

Let's make an example, and say that Alice wants take some Bitcoin and cash them out into her bank account through her KYC exchange. So first she is going to trade her BTC into XMR through a non-KYC exchange. Her XMR ends up, of course, into her personal local wallet. She will then send that XMR to her KYC exchange. All this happens within an hour or two.

What's wrong with this scenario? See below...

![](./basic-timing-attack.png)

As you can see, although the centralised exchange cannot prove where the fund came from, because it's Monero, a coordinated effort can be made to link the funds simply through a correlation of timing and $XMR amount. 

This kind of attack is called EAE, meaning Eve-Alice-Eve or Exchange-Alice-Exchange. More reading: [MoneroLeaks.xyz](https://moneroleaks.xyz/#eve_alice_eve_attack) | [Archive.org onion](https://web.archivep75mbjunhxc6x4j5mwjmomyxb573v42baldlqu56ruil2oiad.onion/web/20250710044032/http://moneroleaks.xyz/#eve_alice_eve_attack)

There is an older more technical variant of this attack called EABE (Exchange-Alice-Bob-Exchange) which was discussed heavily in 2017. It involved blockchain data and technical analysis, as well as public CEX data, and was used to trace the WannaCry hacks in 2017: [Deep dive article on Medium.com](https://medium.com/@nbax/tracing-the-wannacry-2-0-monero-transactions-d8c1e5129dc1) | [Archive.is onion](http://archiveiya74codqgiixo33q62qlrqtkgmcitqx5u2oeqnmn5bpcbiyd.onion/y4ijB)

It was viable due to a few weakness in the Monero blockchain such as a small RingCT size where there were only 4 decoys at the time, but these days there are 15 decoys. This was often mitigated with a process called churning where balances to sent to oneself over and over, which these days due to many improvements is not necessary any longer (except possibly for extreme OpSec situations). All this is discussed and concluded [here (Monero Github issue link)](https://github.com/monero-project/monero/issues/1673#issuecomment-312968452)

The solution: 
 - Use amounts that aren't similar when moving your money in and out of your XMR wallet
 - Time those transactions as far apart as possible.
 - Keep your XMR within the Monero economy by using it with others who accept Monero, such as on [XMRBazaar](https://xmrbazaar.com/), keeping you from being exposed to centralised entities.
 - Trade your XMR for fiat using [Haveno](../haveno-client-f2f/index.md)

## Using a trusted node

The best way to use Monero is to run your own node and send transactions using that node. The next best option is to connect to a trusted remote node over TOR onion. This protects your IP address which is one of the most important pieces of info when a malicious node is trying to de-anonymize users. Other pieces of info include fee structure and input/output information.

This became especially known in 2024 when it was leaked that the company Chainalysis were running honeypot nodes on the clearnet as their primary attack vector against Monero transactions:

![](../chainalysisattempts/1.5.png)

More info about that including links to run your own onion node can be found [here on our blog](../chainalysisattempts/index.md) and [here (MoneroLeaks)](https://moneroleaks.xyz/#spy_node_attack) ([archive onion](https://web.archivep75mbjunhxc6x4j5mwjmomyxb573v42baldlqu56ruil2oiad.onion/web/20250710044032/http://moneroleaks.xyz/#spy_node_attack))

In conclusion:
 - Never use someone else's node, else use an onion node if you have to use a remote node
 - Always use the default/automatic fees suggested by your wallet

## Misc Considerations

Once in a while you may need to use an online Monero Explorer to look up a transaction ID for some purpose. Stop. Think about how you are going to access this tool, from which IP address and network, and at what time. You have no idea what the explorer admin is logging or where that info is going if he is. Make sure you are using TOR browser, that's best.

Also makes sure never to use the same receiving address over and over. Use a different one for each identity you have. Otherwise you are creating a cross-correlation.

There is a niche social attack described in getmonero.org blog post [here (onion)](http://monerotoruzizulg5ttgat2emf4d6fbmiea25detrmmy7erypseyteyd.onion/2019/10/18/subaddress-janus.html) called the Janus Attack. Basically if you give someone a receiving address, they may suspect you also own a different address they found in a forum or something. They send money to you using the suspected address instead of the one you gave. They ask you if you got the money, and if you do own the suspect address, you'll say yes without checking exactly which address the money came to, and essentially confirm that you are the owner of both addresses. There are no known successful attacks of this. If you're wary of this attack, it's best to use totally different seeds for each of your identities, which you should really do anyway for better local security and avoiding mistakes.

## Real-world Example 1: Incognito Market Admin

We have written extensively about the OpSec failures of Incognito's admin [here](../incognito_market/index.md). But let's point to one particular failure related to Monero.

Quoted from the official criminal complaint against him:

```
On or about May 31, 2022, at approximately 08:33 UTC, Administrator
Wallet-1 transferred 2 Bitcoin to Swapping Service-1 (approximate value at the time of transfer was $63,432), where it was swapped for approximately 304.74 XMR. Approximately 35 minutes after the 2 Bitcoin transfer from Administrator Wallet-1, which was converted to 304 XMR, Crypto Account-1 received a deposit of 300 XMR (approximate value at the time of transfer was $59,580).
```

Source (Page 25): [justice.gov (PDF)](https://www.justice.gov/usao-sdny/media/1352546/dl) | [archive onion](https://web.archivep75mbjunhxc6x4j5mwjmomyxb573v42baldlqu56ruil2oiad.onion/web/20250531180415/https://www.justice.gov/usao-sdny/media/1352546/dl)

For context, "Crypto Account 1" is his personal KYC'd exchange account who has all his personal legal info. 

As you can see, this excerpt needs no further explanation. This was done several times, not just once. This is a classic textbook example of exactly what we discussed above. Do not move money between 2 Centralised Exchanges in quick succession and in similar amounts, especially such large amounts as he did.

![](../incognito_market/0.png)

## Real-world Example 2: Columbian Drug Dealer

This incident was leaked along with the Chainalysis leaks mentioned in the [above section](#using-a-trusted-node)

More info about this can be read here: [MoneroLeaks](https://moneroleaks.xyz/#case_studies) | [Archive Onion](https://web.archivep75mbjunhxc6x4j5mwjmomyxb573v42baldlqu56ruil2oiad.onion/web/20250710044032/http://moneroleaks.xyz/)

The details are a bit convoluted but the primary takeaway is that the drug dealer was consistently using many random clearnet Monero nodes with little regard for their legitimacy. He did not know that many of these nodes were run by the Chainalysis corporation. Between IP logging, not using a VPN on one occasion and exposing his IP, poisoning outputs, scanning all the data of the transactions he was sending, the malicious nodes were able to compile enough data to incriminate him.

The lesson of course being, **Don't make transaction using random clearnet nodes**.

## Real-world Example 3: Vastaamo Ransom

There is a lot of false information surrounding this case. More info about this can be read here: [MoneroLeaks](https://moneroleaks.xyz/#case_studies) | [Archive Onion](https://web.archivep75mbjunhxc6x4j5mwjmomyxb573v42baldlqu56ruil2oiad.onion/web/20250710044032/http://moneroleaks.xyz/) and [here (Redlib onion)](http://redlib.nowhevi57f4lxxd6db43miewcsgtovakbh6v5f52ci7csc2yjzy5rnid.onion/r/Monero/comments/19emsfe/finlands_national_bureau_of_investigation_claims/)

The gist is that a Finnish hacker tried to ransom a service he broke into by demanding Bitcoin in exchange for not publishing personal info.

Many cryptocurrency tabloids will scream that "Monero was traced" or "Monero was cracked". This is pure falsehood. The hacker, during the attack, foolishly leaked his private keys and personal info. 

Some reports seem to indicate an EAE or timing/correlation attack, but even this is dubious as the hacker was arrested long before they did any crypto "tracing":

```
KRP (police) sent 0.1 Bitcoin to the virtual address where the blackmailer had requested ransom money.

Julius Aleksanteri Kivimäki, who was accused of extortion, was eventually tracked down by other means, and the fake purchase is not even mentioned in the actual preliminary investigation report of the case.
```
Source: [Finnish News Report Jan 24 2024](https://www.mtvuutiset.fi/artikkeli/vastaamo-jutussa-iso-paljastus-krp-jaljitti-jaljittamattomana-pidettya-kryptovaluuttaa/8864046) | [Google Translate](https://www-mtvuutiset-fi.translate.goog/artikkeli/vastaamo-jutussa-iso-paljastus-krp-jaljitti-jaljittamattomana-pidettya-kryptovaluuttaa/8864046?_x_tr_sl=auto&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp&_x_tr_hist=true)

The article is pretty convoluted but talks about several OpSec mistakes made by the hacker including cross-contamination of CEX accounts by using emails connected to his real name, and transferring in and out of CEXs many times. The hacker did trade his BTC for XMR, but it's unclear what they were able to do with any on-chain XMR data.

The Finnish police are tight lipped about how they apparently did "Monero tracing" but cannot be considered legit, since they arrested him after the fact, and had access to all his leaked keys, personal info, and CEX info, and benefitting from his OpSec mistakes in the subsequent investigation. Whatever they want you to believe about their "Monero tracing" is likely bogus and dependent on real-world data.

In conclusion: Monero actually had very little to do with the arrest of this man, regardless of what police want you to believe, who are really only after the advancement of their career and want to appear elite and god-like. Nevertheless, again, always take care of your cross-contamination and of timings and amounts of your swaps.

## Conclusion

Save this graphic to remind yourself and others about the primary rules of Monero OpSec:

![](./xmr-rules.png)

