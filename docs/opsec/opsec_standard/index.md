---
author: odysseus
date: 2025-08-18
gitea_url: "http://git.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/nihilist/the-opsec-bible/issues/371"
xmr: 83tvixnZaL5SbN8fWiPAAje4mvdZnfrJUM5H1pnbLTZmT1d6eGC1qCp7aFB7jUpt3wECm33L9quvkAVtJH4GDvYmEuoPgrr
---

# OPSEC Mistake Template

```
TLDR: Write opsec analysis graphs to detail what are the gaps in one's operational security
```

This will show you how to write an article on a person's/groups'/organizations' OPSEC mistakes.

### Why this is important

The reason its important to have these articles on opsec mistakes is so that we can learn from the errors of others and avoid committing them ourselves. They underscore the significance of the opsec guides found in the Opsec Bible. Additionally, it provides us with a means to identify opsec mistakes for which there is currently no solution covered in the OPSEC Bible, allowing us to contribute to its improvement.

## Overview of the Article Writing Process

1. **Explain who the person/group/organization is**
   - Mention details such as name, origin, affiliation, work/occupation, etc.
   - Assume the reader doesn't know anything about the person/group/organization.

2. **What were the OPSEC mistakes?**
   - Take the reader through how the authorities found and arrested the person.
   - Step by step, explain how one thing led to another.
   - Include [OPSEC analysis graphs](../qualitystandard/index.md#how-to-make-opsec-analysis-graphs) (including the privacy, anonymity, and deniability icons).

3. **What were the consequences of those OPSEC mistakes?**
   - Show charges, sentences, and other consequences that might have occurred.

4. **What should have been done differently?**
   - Link to the relevant tutorials we wrote: what they didn't know and what they didn't implement.
   - Include [OPSEC analysis graphs](../qualitystandard/index.md#how-to-make-opsec-analysis-graphs) (including the privacy, anonymity, and deniability icons).
   - If there isn't already a tutorial for a solution to link, open an issue so that one gets created.

## Minimal Example

# The Downfall of Haxxor_1337

## Who was Haxxor_1337?

Haxxor_1337, whose real name is Jim, lived in Ohio. Haxxor_1337 was a known figure in the hacking world, conducting various high-level breaches...

![](1.jpg)

## What were the OPSEC mistakes that Haxxor_1337 made?

This section outlines how law enforcement pursued him and the operational security (OPSEC) mistakes that led to Haxxor_1337's arrest.

## 1. Deanonymization through clearnet use

While exfiltrating data from one of his victims, Haxxor_1337 once forgot to route his connection to the servers through Tor, letting the authorities see his bare home IP.

![](2.png)

## 2. Surveillance

After finding Haxxor_1337's IP and getting the records from the ISP, the feds found out that the IP belonged to Jim and now had his address. Following that, the feds set up a surveillance operation, placing multiple undercover agents to follow him wherever he went. They also used public cameras and his own phone to track his every step.

![](3.png)

## 3. Bitcoin Correlation

While surveilling Haxxor_1337, they saw how he went into a sneaker shop that accepted Bitcoin and walked out with two bags. After he left, the feds went into the store, making the shop owner give them the address of the wallet with which he paid. After getting the address of Jim, they saw that it was the same one that the NSA had to pay 10 Bitcoins to get their data back from Haxxor_1337.

![](4.png)

## What were the consequences of Haxxor_1337's OPSEC mistakes?

After getting arrested and charged with being an evil hacker, Jim got 10 times life in prison.

## What should Haxxor_1337 have done differently?

Instead of accessing servers from his home IP, he should have read our guide on [how to connect to servers over Tor](../anonaccess/index.md) and considered following our guide on [how to set up Black Hat Hacking Whonix VMs](../blackhathacking/index.md) so that everything gets routed through Tor.

![](5.png)

Avoiding KYC and directly paying for things in crypto was a good thing, but since Bitcoin has a transparent blockchain, he still got tracked down. Instead, he should have read our guide on [how to set up a Monero wallet](../monerowallet/index.md) and a [Monero node](../monero2024/index.md) and used Monero instead, which would have prevented the feds from connecting the separate transactions.

![](6.png)

# Conclusion

At the end these articles help people analyze their OPSEC from all angles to know where they lack privacy, where they lack anonymity, and where they lack deniability. People might realize OPSEC mistakes that they were making up until now and then stop doing those things.

If this isnt enough and you would like to see more examples of what a opsec mistakes article should look like you can go through the already approved articles. 