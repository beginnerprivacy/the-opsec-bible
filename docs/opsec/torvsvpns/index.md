---
author: nihilist
date: 2024-04-30
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/88"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
tags:
  - Anonymity Explained
---
# The main source of Anonymity: The Tor Network 

```
TLDR: Because it's easy to deanonymize VPN users, it's important to use the Tor network to remain anonymous online.
```


## **Why aren't VPNs enough?**
    
    
    Privacy Analogy:
    Alice is talking to Bob, but Jack can hear their conversation, they have no privacy.
    Alice is talking to Bob, behind closed doors. Jack can't hear their conversation, they now have privacy.
    
    

As explained [previously](../aps/index.md), Privacy is about excluding someone from being able to spy on what you're doing, the **whole marketing point for VPNs is to provide privacy for your internet usage, from your internet service provider (ISP)**

![](1.png)

By default, you are using your computer from home, from your home connection which is provided by your Internet Service Provider (ISP), and you are using it to access services remotely. **In that scenario, your ISP is able to see (to spy on) what you're doing with your internet connection.** From there, the entire VPN industry emerged.

![](2.png)

A VPN provider is a centralised entity (see our previous [explanation](../governments/index.md) on why these are highly likely to be used as a spying proxy for the governments), they offer you to connect to their infrastructure **in order to offer you privacy from your ISP.**

However when you do that, the VPN provider becomes your ISP, **The VPN provider becomes the one who is able to spy on your internet traffic, instead of your ISP.**

By connecting to a VPN you are moving your trust from your ISP to the VPN provider, **but since both your ISP and your VPN provider are centralised entities, you can be damn sure they are spying on what you're doing.**

Moving your trust from a centralised entity to another is not going to protect you against targeted surveillance. **It won't protect you from being reported to the authorities either if you do something illegal.**

_DISCLAIMER ON VPNs:_ Keep in mind that if you choose to use a VPN anyway, you must conduct a strict VPN selection, see [Privacy Guides' Recommendations](https://www.privacyguides.org/en/vpn/) on that topic, out of which i recommend [Mullvad](https://kycnot.me/service/mullvad) because they accept Monero without any KYC.

## **Tor Network: the main source of Anonymity**
    
    
    Anonymity Analogy:
    Jack sees that Alice is talking to Someone. But Jack can't make out who that person is. 
    Until Jack can figure out who that Someone is, that someone is Anonymous.
    
    

So we can't trust our ISP, nor VPNs alone, what can we trust then ? 

That situation is what started the [Tor Project](https://torproject.org). Tor is above all an open source routing protocol, that aims to not only encrypt traffic (like what VPNs do) **but the aim is also to obscure where connections come from, and where they go**. 

It aims to blend all of the users together, to make everyone look the same to prevent any identity correlation. (that is also why you shouldn't edit your tor browser configs, as it will make you stand out as an unique user. 

![](4.png)

We have the following scenario: you don't want your internet service provider to know what you're doing, **but you also don't want the end services like google youtube or duckduckgo to know that you are accessing their service.** in other words, you want to remain Anonymous while browsing the web, and Tor provides that for you.

![](5.png)

Tor is unique as it is the anonymity network that received the most donations, studies and patches, but also due to it's popularity there's alot of nodes ran by anyone (individuals, companies, and potentially also governments), the decentralised aspect is vital there, because **by using Tor, you are trusting 3 random entities, in 3 different countries**

It takes all 3 nodes used by your tor circuit (**in 3 different legislations if they are in 3 different countries**) to actually be malicious and to record connections to be able to successfully deanonymize you. While at the same time, the Tor protocol does not log any connection by default.

For more details you can see the repartition of tor nodes per [country](Https://metrics.torproject.org/bubbles.html#country), or per [ISP](https://metrics.torproject.org/bubbles.html#as) on metrics.torproject.org

![](6.png)

Keep in mind that it is still possible for you to get deanonymized sometimes if you're unlucky to have all 3 nodes ran by the same entity. So **it is not perfect** , but it is definitely many times more trustworthy than having to trust a centralised entity providing you with a VPN connection. 

As we have discussed [previously](../anonymityexplained/index.md), sometimes Anonymity is the difference-maker between Life and Death, especially for Journalism in censorship-heavy countries, Tor's main attraction is that **De-anonymization attacks are made to be as expensive as possible** , even for state-actors.

Some people argue that Tor can't be trusted, but as we have discussed [previously](../govfear/index.md), Governments need to be able to know what happened (lack of Privacy), and once they know what happened, they need to know who did it (lack of Anonymity), **in order to enforce their laws.** When that is the case, [how come is there still so many illegal marketplaces with years of uptime on the Tor network](https://status.nowhere.moe/status/darknet) ? One thing is for sure, these marketplaces are very high on international authorities' priority list. If they are still there after all this time, It must be because the Tor network is protecting them from being discovered by the authorities isn't it ?

Even though i don't recommend to use Tor for any illegal purposes, the fact that these marketplaces have remained in activity for such a long time are a clear testament to the resiliency of the Tor network.

