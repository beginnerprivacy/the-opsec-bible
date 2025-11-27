---
author: odysseus
date: 2025-08-27
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/445"
xmr: 83tvixnZaL5SbN8fWiPAAje4mvdZnfrJUM5H1pnbLTZmT1d6eGC1qCp7aFB7jUpt3wECm33L9quvkAVtJH4GDvYmEuoPgrr
tags:
  - OPSEC Mistakes
  - Bad Identity Segmentation
  - Not Using Monero
  - Not Using SimpleX
  - No Deniability
  - KYC on centralised exchanges
---

# The Downfall of Pompompurin

```
TLDR: don't use gmail (KYC) accounts to login on websites that are sensitive in nature.
```

## Who was Pompompurin?

**Conor Fitzpatrick**, widely recognized by his online alias **Pompompurin**, was the founder and administrator of the **BreachForums** cybercrime website. He resided in **Peekskill, New York**. Fitzpatrick established BreachForums in **March 2022**, in response to the law enforcement dismantling of **RaidForums**, a previously prominent cybercrime marketplace.

Under his leadership, BreachForums emerged as a significant platform for cybercriminal activities, providing access to around **900 stolen databases** that collectively contained over **14 billion individual records** for its members. Fitzpatrick also served as an intermediary for transactions involving stolen data, facilitating the exchange of illicit information among users.

![](0.png)

## What were the OpSec mistakes that Pompompurin made?

This section outlines how law enforcement pursued him and the operational security (OPSEC) mistakes that led to Pompompurin's arrest.

### 1. Feds Seized RaidForums

Law enforcement agencies initially assumed control of RaidForums, thereby obtaining access to a substantial amount of information, including login timestamps, IP addresses, and private messages exchanged among members. Upon reviewing the IP logs associated with the RaidForums account of Pompompurin, investigators identified that at least nine distinct IP addresses accessing the account were associated with a mobile device containing a SIM card registered to Conor Fitzpatrick. This evidence established a direct connection between Pompompurin and Conor Fitzpatrick.

![](1.png)

### 2. Private Messages Discovery

While reviewing Pompompurin's private messages, federal investigators discovered a conversation between him and the forum owner, Opnipotent. In this exchange, Pompompurin indicated that he had purchased the ai.type database. However, despite the fact that Have I Been Pwned listed his email as compromised, he was unable to locate it, implying that it was not the complete database. In response, Opnipotent inquired about which email Pompompurin had searched. Pompompurin replied:

> "I don’t want to share my actual email for obvious reasons, but this email seems to have the same case as mine."

He then proceeded to provide the email address "conorfitzpatrick02@gmail.com." This marked the second direct link identified by investigators, making it obvious that this was indeed his actual email address.

![](2.png)

![](3.png)

### 3. De-anonymization through missing identity segmentation

Upon investigating the Google account, federal agents discovered that prior to the conversation, Pompompurin had created a second email account, conorfitzpatrick2002@gmail.com, to replace the previous one. The Google Pay account linked to both email addresses was registered under the name "Conor Fitzpatrick," and included his address, phone number, and credit card information, further substantiating that both accounts were owned by Conor Fitzpatrick.

In examining the logs for conorfitzpatrick2002@gmail.com, investigators found that on March 7, 2022, the account was accessed via a VPN IP address, which was the same IP that connected to Pompompurin's Zoom account the following day. This Zoom account was registered to the email address pompompurin@riseup.net, which is the same email he used to register on RaidForums.

Further analysis of the logs revealed a total of 31 unique IP addresses that accessed the conorfitzpatrick2002@gmail.com account. Of these 31 IP addresses, 12 were also used to access Pompompurin’s RaidForums account.

![](4.png)

### 4. Additional evidence through Purse.io

Four of the IP addresses used to access both the Google and RaidForums accounts, along with seven of the nine unique IP addresses that accessed the purse.io account, were also utilized to access Pompompurin's RaidForums account. The purse.io account was registered under the name "Conor Fitzpatrick," using the email address conorfitzpatrick2002@gmail.com and his phone number. Additionally, items were shipped directly to his home address, and the purchases were made exclusively using Bitcoin wallets known to be associated with Pompompurin.

![](5.png)

### 5. Identity confirmation through real live surveillance

Following the numerous direct connections established between Conor Fitzpatrick and Pompompurin, the FBI obtained a warrant to access Fitzpatrick's phone location data and deployed undercover agents to monitor his residence. Over time, they confirmed that each time Pompompurin went online, Conor Fitzpatrick was present at home.

![](6.png)

### 6. Arrest

To facilitate the arrest, the FBI deployed an undercover agent posing as a package delivery person. This strategy was designed to lure Conor Fitzpatrick outside, allowing agents to apprehend him while simultaneously executing a raid on the house. Once Fitzpatrick was outside, he was handcuffed and taken into custody.

Video of the arrest:

<video controls>
  <source src="7.webm" type="video/webm">
</video>

(After Conor Fitzpatrick's arrest and subsequent access to the BreachForums servers, investigators discovered that he had logged into his BreachForums account directly from his parents' home.)

## Sentence

After being taken into custody, Conor Fitzpatrick's parents paid a $300,000 bond for his release, under the conditions that he would:

1. Surrender his passport.
2. Submit to ongoing police surveillance.
3. Remain off the internet.

The sentencing hearing was scheduled for November 17, 2023. On April 20, Fitzpatrick attempted to commit suicide and was subsequently admitted to a hospital.

In July, Conor Fitzpatrick pled guilty to several charges, including:

1. Conspiracy to commit access device fraud.
2. Access device fraud.
3. Possession of child pornography, with federal agents discovering 26 videos and over 600 images of child pornography on his SSD.

It is believed that his suicide attempt was likely motivated by the impending discovery of the CSAM on his SSD. Following this, he was allowed to return home under pre-trial release with new conditions:

1. He was not permitted to be around minors unless accompanied by an adult who was aware of his charges.
2. He could not access the internet without monitoring software enabled.

Due to mental health evaluations requested by his lawyer, the sentencing was postponed to January 19, 2024.

Two and a half weeks before his sentencing, the FBI raided his home again after he purchased a new phone and connected to a VPN. Investigators later discovered that he accessed Discord chats in which he claimed that the charges he pled guilty to were untrue and discussed hacking government entities and releasing classified information.

Despite the federal recommendation of a 15-year prison sentence, the judge, considering the mental health evaluations that indicated Fitzpatrick was on the autism spectrum, sentenced him to 17 days of time served and 20 years of supervised release. The conditions of his release included:

1. Spending the first two years on house arrest with a GPS ankle monitor.
2. Being prohibited from accessing the internet for the first year (after which any computer he used must have monitoring software installed, subject to unannounced checks).
3. Forfeiting $698,714, which the federal authorities seized from his Coinbase and Exodus wallets.
4. Being ordered to pay restitution to the victims of the child pornography (the specific amount was not yet determined).
5. Being placed on [the sex offender registry.](https://www.criminaljustice.ny.gov/SomsSUBDirectory/offenderDetails.jsp?offenderid=56924)

The judge's reasoning was that, despite being 21 years old, Fitzpatrick's mental maturity was more akin to that of a 16- or 17-year-old, and that the Federal Bureau of Prisons would be unable to adequately address his autism spectrum disorder. The judge expressed concern that Fitzpatrick would face being "ravaged" in prison.

![](8.png)

## What should Pompompurin have done differently?

The first step is to review our guide on [Internet Usage Segmentation](../internetsegmentation/index.md), as the most common mistakes made involved linking separate identities. On multiple occasions, he utilized a VPN but failed to change servers while engaging in different activities. To rectify this, he should consult our guide on [How to Implement Automatic Server Randomization with Mullvad](../mullvadvpn-daily-connect/index.md).

Following our guide on [How to Set Up a Sensitive Use Virtual Machine](../sensitivevm/index.md) would also facilitate the separation of his activities and ensure that he does not access websites over the clear web. While I do not condone any illegal activities, including the possession of CSAM, if he would have liked to to prevent the feds from finding his files, reading our guide on [Deniable Encryption](../veracrypt/index.md) would be beneficial.

Furthermore, he should have avoided using Bitcoin and instead reviewed our guides on [How to Set Up a Monero Wallet](../monerowallet/index.md) and [Monero Node](../monero2024/index.md) to ensure that his transactions remain untraceable.

Lastly, even after adhering to all this advice, one can still encounter issues by inadvertently disclosing personal information, as Conor did when sharing his email. Therefore, it is imperative for him and everyone else to read our guide on [Using the Right Technology and Behavior](../opsec/index.md).
