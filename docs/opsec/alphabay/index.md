---
author: odysseus
date: 2025-08-04
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/blog-contributions/issues/364"
xmr: 83tvixnZaL5SbN8fWiPAAje4mvdZnfrJUM5H1pnbLTZmT1d6eGC1qCp7aFB7jUpt3wECm33L9quvkAVtJH4GDvYmEuoPgrr
tags:
  - OPSEC Mistakes
  - Bad Identity Segmentation
  - Not Using Monero
  - No Deniability
---

# The Downfall of AlphaBay

```
TLDR: don't use a KYC mail account for sensitive activities
```

## What was AlphaBay?

AlphaBay was a prominent darknet marketplace that operated from **2014 until 2017**, becoming the largest of its kind. Accessible through both the **[Tor](../torvsvpns/index.md)** and **[I2P](https://geti2p.net)** networks, AlphaBay facilitated a wide range of illicit activities, including the sale of drugs, hacking services, and various other illegal goods.

At its peak, AlphaBay generated impressive revenue, reaching over **half a million dollars in sales daily**. The marketplace operated on a commission model, taking between **2% to 4%** of each transaction. Users primarily conducted transactions using cryptocurrencies such as **Monero**, **Bitcoin**, and **Ethereum**.

The marketplace was managed by **Alexandre Cazes**, who operated under the alias **Alpha02**. Cazes's administration of AlphaBay came to an abrupt end in **July 2017** when law enforcement agencies shut down the platform, leading to his arrest shortly before his untimely death.

![](1.png)

## What were the OpSec mistakes that the owner of AlphaBay, Alpha02, made?

This section outlines how law enforcement pursued him and the operational security (OPSEC) mistakes that led to Alpha02's arrest.

### 1. The Forum email

In addition to the AlphaBay marketplace, Alpha02 also created the AlphaBay Market Forum. In the early stages of the forum, users received an **automated welcoming message**. When obtaining that message, law enforcement examined its origin and found the sender to be **"pimp_alex_91@hotmail.com."**

![](2.png)

### 2. LinkedIn Profile

After havin obtained that email LE looked at accounts connected to that address and found in between other things a **linked in profile**. The profile **belonged to Alexandre Cazes**. It listed skills that could be used to create a darknet market. Also said that he has his own IT company named EBX Technologies.

![](3.png)

![](4.png)

### 3. Reusing Usernames

Further investigation of the email "pimp_alex_91@hotmail.com" led to a post on commentcamarche.com by a user named **Alpha02**, who explained how to remove viruses from images. He also used the same email and username on a pickup artist forum named Roosh V. The admin of that forum even created a thread about him, which can be viewed [here](https://web.archivep75mbjunhxc6x4j5mwjmomyxb573v42baldlqu56ruil2oiad.onion/web/20250727225342/https://rooshvforum.network/thread-63910.html).

![](5.png)

### 4. Unexplained Wealth

While his display of wealth may not be a direct OpSec mistake, it certainly did not help his case. He owned various luxury cars, real estate around the world, and more. Law enforcement stated that he used his company, EBX Technologies, to obscure the source of his wealth. Having such a significant amount of money with a questionable source made him even more suspicious and increased the likelihood that he obtained it from AlphaBay.

![](6.png)

### 5. EBX Technologies raid

Upon uncovering the information mentioned above, it became evident that Alexandre Cazes was Alpha02 and owned AlphaBay. Consequently, authorities first raided his company, EBX Technologies, which was where the servers hosting AlphaBay were located. Now in control of the servers, law enforcement caused an error on the servers with the intention of prompting Alexandre Cazes to log in to rectify the issue.

![](7.png)

### 6. Leaving His Laptop

After causing the error on the server, an undercover agent drove a car into the gate of his residence. As Alexandre Cazes went outside to investigate, multiple agents rushed in, arresting him and entering his home, where they secured his PC that was logged into the servers where he was trying to resolve the server problem caused by law enforcement. This allowed them to clearly demonstrate that he was the administrator.

Video of the arrest:

<video controls>
  <source src="7.webm" type="video/webm">
</video>

### 7. Sentence

Although there are no specific figures regarding the sentence he would have received, one can infer that, given AlphaBay's size being over ten times that of [Silk Road](../silk_road/index.md), for which its owner received two life sentences plus 40 years, Cazes' sentence would not have been lenient. After being arrested while being detained in Thailand, Cazes committed suicide.

Additionally, his wife was charged with money laundering.

## What should Alpha02 have done differently?

He should have reviewed our guide on [how to maintain multiple identities online](../multiple_identities/index.md). This would have informed him not to use the same email address across different platforms with varying identities. The same principle applies to the username "Alpha02." Had he read our article on [OPSEC over ego](../opsecoverego/index.md), he would have learned the importance of changing identities over time, ensuring that OPSEC mistakes, such as the email one, were associated only with the Alpha02 identity and not with future ones. Furthermore, he should have refrained from listing skills necessary for managing a darknet market on his personal LinkedIn profile.

Improving his wealth concealment, for instance by following our guide on [how to hide Monero wealth](../monerowealth/index.md), would be beneficial in safeguarding his assets from law enforcement.

It would have been wise to avoid hosting an illegal market on the servers he controlled. Instead, he should have referred to our guide on [how to acquire a remote server and connect to it anonymously](../anonymousremoteserver/index.md).

Lastly, it can't be stressed enough how important it is to encrypt one's drives. Not doing so was a major mistake. He should have read our guide on [deniable encryption](../veracrypt/index.md). Just having encryption would already be miles better than not having any, as he did. However, in cases where the authorities raid one's home or stage an accident, like they did in this case, it's important to be able to lock one's devices quickly, for example, by following our guide on [setting up USB-triggered shutdowns](../usbdeadmansswitch/index.md). Even if one has encryption set up on a device, it's useless if the authorities access the device while it is unlocked.
