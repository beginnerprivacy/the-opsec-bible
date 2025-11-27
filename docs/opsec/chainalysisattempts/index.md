---
author: nihilist
date: 2024-09-07
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/96"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
tags:
  - Clientside Anonymity
  - Decentralized Finances
  - Agorism
---
# Why can't I trust Centralised Exchanges, and random Monero nodes ?

```
TLDR: 
- the adversary runs monero nodes, so you can't trust random monero nodes, you should run your own
- Centralised exchanges will all be forced to KYC their users by financial regulations, so you're anyway going to be forced to use decentralised exchanges sooner or later
```

As of September 5, 2024 sech1 posted on monero.town the following [post](https://monero.town/post/4220893), which was a repost of the following [reddit post](https://redlib.nowhere.moe/r/Monero/comments/1f8jv6w/comment/llnyemp/?context=3) talking about a leaked Chainalysis meeting video about what was their progress on tracing monero transactions back in August 2023. This is a great opportunity to highlight the opsec weaknesses they are targeting so let's dive into it.



## **Chainalysis are running malicious monero nodes**

The main attack vector of Chainalysis is their honeypot monero nodes. Meaning there are monero nodes out there (even though their IPs didnt get mentionned in the meeting), that ARE malicious.

![](1.png)

So the first thing to be aware of is that you can't just trust random remote nodes. Chainalysis IS running an unknown amount of malicious monero nodes out there, to spy on users that decide to trust them. **Therefore, I strongly suggest that[you run your own monero node](../monero2024/index.md), and use only that node. Run it from home, or [from a remote server](../anonymousremoteserver/index.md), but run your own!**

## **Chainalysis targets IP addresses and behavior anomalies (such as non-default fees)**

![](1.5.png)

Now, if you decide to trust a random remote node that is not yours, and let's say you decide to trust one of their malicious nodes, you need to be aware that they can see:

  1. The timestamp of each transaction

  2. The transaction behavioral characteristics (the number of inputs, outputs, the fee structure (1x, 10x, 100x, etc)

  3. Which IP address is connecting there (clear attack on dandelion++), and it's latency.




Therefore, **if you decide to trust a remote monero node, at least keep Tor in between you and the malicious node** to maintain your anonymity, **use the .onion monero nodes preferably!** , And I also recommend that you leave the default fee option when you want to send monero somewhere**.

But **so far they cannot tell how much you are sending or recieving** , because you are not touching centralised exchanges (assuming you are using [Haveno DEX](../haveno-client-f2f/index.md) to buy or sell Monero)).

## **Chainalysis targets centralised exchanges that have KYC procedures**

As [I have mentionned many times previously](../govfear/index.md), Businesses can all be governmental proxies to do their bidding. **Centralised exchanges are businesses too, they also comply with their requests.** Or in their own words, they are "Subphoenable entities". But guess what, **these very Centralised Exchanges are forced to use Chainalysis' malicious monero nodes too!**

![](2.png)

Therefore if you decide to trust one of those popular Centralised Exchanges to buy / sell monero, the implications are way, way worse than what we previously explained;

Those centralised exchanges all comply with the requests of governmental entities such as FBI, LA, Robinhood, IRS-CI, UNK and of course Chainalysis, **and due to that fact alone you cannot trust them**.

If you decide to trust a popular centralised exchange, you'll first see that **it'll run you through KYC procedures (and if it doesn't, rest assured that they will eventually be forced to do so).** That is to deanonymize you, and to know who to blame if ever asked by the authorities. **NEVER KYC IF YOU WANT TO REMAIN ANONYMOUS!**

This meeting of theirs has been preety revealing, not only do these centralised exchanges give out everything they have about their users to Chainalysis (as "Transactions of interest", **mentionning the amount transacted** , the **transaction ID** , and **who transacted**) But it's also naming a few of THOSE very centralised exchanges that are now confirmed to actually comply with their requests:
    
    
    Changenow,
    FixedFloat, 
    Morphtoken, 
    Exodus, 
    Swaplab, 
    Coinomi
    
    

The info of whatever you did so far, and will ever do on those centralised exchanges, be warned, is being handed over directly to the authorities. (Timestamp 26:02 to 26:47) in the video. **This list is most likely (as of a year later, in september 2024) way bigger, they are eventually going to force every centralised exchange out there to implement KYC procedures and comply to their deanonymization requests.**

My recommendation, once again is the same as i have mentionned [previously](../truecrypto/index.md): If you want to use a centralised exchange, you are shooting yourself in the foot. **Stop using centralised exchanges and use decentralised exchanges, such as[Haveno DEX](../haveno-client-f2f/index.md).**

If you want to use a centralised exchange anyway, **remain anonymous when doing so (at least keep Tor in between you and the service, and never KYC yourself there)** , but remain aware that you will eventually have to move to decentralised exchanges sooner or later, because they are not going to stop until every centralised exchange out there complies with their demands. 

