---
author: nihilist
date: 2001-01-30
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/431"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
---
# What's On-topic and Off-topic ?

```
TLDR:
Opsec: Privacy, Anonymity, Deniability, Agorism, Anarchy
Offtopic: Unrealistic advice, automating everything, Generic security/hacking, Tech that doesn't protect you against anything, overcomplications
```

The Opsec Bible's Operational Security tutorial category is on purpose restricted to a few topics to avoid the subject from being too vast and to remain fully explorable.

## Topic 1: Privacy

Privacy topics are basically tutorials that explain what privacy is:

![](../aps/privacy.png)

It also involves clientside tutorials showcasing how to operate without having an adversary observe what we're doing. For instance, we showcase how to have privacy on your own computer by following the rules that are required to achieve privacy (which is by only using FOSS software, to prevent adversaries from spying on you)

![](../linux/52.png)

And we also talk about serverside privacy tutorials, which largely revoles around explaining the concept of self-hosting services.

## Topic 2: Anonymity
Anonymity topics are basically tutorials that explain what Anonymity is:
![](../anonymityexplained/10.png)

It also involves clientside tutorials that showcase how to operate without an adversary being able to determine what our identity is (meaning we have to remain identical to others in a given group, like among the Tor users). It generally involves explaining how to route apps through Tor to make them function while enforcing anonymity at the same time.

![](../monero2024/25.png)

We also cover how to enforce serverside-anonymity, by explaining how to acquire servers anonymously, and use them anonymously (maintaining Tor in between us and the servers), and how to make services work through Tor alone using .onion Hidden Services.

![](../nextcloud/60.png)

## Topic 3: Deniability

And Lastly, the holy grail of Operational Security being deniability, where we cover what it takes for your operations to survive the eventuality where you're forced to type your password to unlock what's encrypted on your computer.

![](../deniability/4.png)

This is where we showcase how to implement host OS livemode, and Veracrypt hidden volumes into one's setup, to make sure that there are no proofs left behind that could prove that the individual is behind said sensitive operations upon being forced to unlock his devices.

![](../veracrypt/20.png)

On the clientside, the core scenario is to explore how to ensure that the individual's operations can survive a police raid, and the order from the judge where he's forced to type his own password.

On the serverside, the core scenario is to explore how to ensure that a given service can survive multiple server takedowns. (meaning ensuring high availability, how to organize the multi-server setups, etc.)

## Side Topics: Anarchy, and Agorism

Anarchy is at the absolute core of Operational Security, because it is about protecting the individual's freedom by using the proper technology, in the proper way, following the proper Opsec practices. **This entire blog is there to enable individuals protect their freedom from Tyranny, essentially telling them how they can become ungovernable.**

![](../whytheblog/7.png)

We also welcome topics relating to Decentralized Finances which massively enable Agorism the making of circular economies outside of the control of the state, it follows Anarchist principles where the individual should be able to transact freely, without state intervention. (see our tutorials on Monero, Xmrbazaar, and Haveno in particular)

![](1.png)

# **What's Offtopic?**

Here are the list of things that are offtopic, and that we will NOT cover in the blog (for the foreseeable future at least):

## General security and hacking: 

Making sure a software is secure, how to test if it is secure or not, this is a BOTTOMLESS rabbithole that we won't go into again. I went down that rabbithole myself, in the [Hacking section](../../hacking/index.md). The Point being that you anyway cannot defend against the threat that you don't know anything about (0days). 

This is also an oxymoron because every software out there is secure until you find a vulnerability in it. And upon a vulnerability being disclosed publicly, it gets patched anyway.
What can you do against that vulnerability that didn't get disclosed publicly yet, that you don't know about ?

![](2.png)

You're never going to eliminate all 0day risks by going for ultra minimalist software, since every damn line of code your minimal software can potentially contain a vulnerability. **Trying to protect against the threat you don't know about (0days) IS a pointless and futile endeavor.** You can reduce the risks of 0days by going for ultra-minimalism, but we'll leave that at the discretion of the viewers. 

**Tell the viewer to run the software on it's latest update. If a malicious commit is pushed into the software, don't trust that repository and maintainer anymore, fork it on your own .onion forgejo instance, remove the bad commits, and compile the software yourself.** We will consider some FOSS software as suitable for opsec use _until proven otherwise (so don't bring up the 0day excuse)_ , not the other way around.



## Closed-source hardware privacy workarounds: 

No, we won't recommend to the 90% average joes out there to wire up cables to their CPU in order to disable intel ME, install coreboot, or whatever else, and risk bricking their motherboards/CPUs permanently. 

![](65.png)

**We will recommend that average joe to purchase fully open hardware devices, that are free of potential backdoors in the first place, when they are available on the market.** 

We do with the tools at our disposal, so until those tools are made available, we use what we can use. **We will consider FOSS Host OS as suitable for privacy, even on closed-source hardware for the time being.** (so don't bring up the google pixel graphene OS or the Intel/AMD CPU hardware backdoor argument until you find an actual open hardware alternative that does the job aswell)



## Unrealistic advice:

The advice we bring forth in this blog should defeat 99% of the risks while still be doable by 90% of the average joes out there, by explaining it correctly. 

For instance, no, **90% of the average joes out there are not going to go dressed up in black coats, wear an anonymous mask, sit in mcdonalds, to try and use someone else's public wifi anonymously for entire days on end just to browse the web anonymously and avoid it being tied back to their irl identity. NOBODY is going to do that**. 

![](66.png)

Keep that unrealistic advice off this blog, as it doesn't help anyone. The realistic approach to this situation would be to just do a (you -> vpn -> tor -> destination) setup, since it defeats 99% of the attack vectors, and 90% of the joes out there can do it if you explain it properly. End of the story. 

**I don't care about the 1% most unlikely scenario that only the top 1% non-average joe can pull off.** Simply mention the other options briefly, while focusing on the method that 90% of the people out there are the likely to be able to adopt.



## Overcomplications:

I want you to go for the simplest option that actually leads to the intended result. Especially if there are a ton of options that can actually lead to the destination like with chat applications.

For example, you can achieve private chats (E2EE) with both Signal and SimpleX, but on Signal you have to use a phone number to be able to get to the same result, which is an unjustifiable complication, (also given how many threat vectors it actually introduces).

![](../whytheblog/4.png)

If, from point A you can go to point B, to arrive at result Z, **then do not add steps in between, because you are offtopic in over-complicating it.** 

If a simpler solution exists, show that option only and do not waste diskspace writing innefficient methods that the readers don't need to read or know about. 

**I will categorically refuse any overcomplications that isn't properly justified with adequate opsec scenarios and threat modeling.**

## Oversimplifications:

I've also been asked, why are we not automating every setup we showcase to make it easier for everyone to setup what we talk about (using nixos, terraform, ansible, or other automation scripts) ?

![alt text](image.png)

First of all, we are here to properly explain why, what and how to achieve every setup we showcase, from step A to step Z, therefore there's no reason anyone wouldn't be able to replicate the setups we showcase.

The only reason we would try and automate everything, would be to satisfy the lazy readers out there, that are unwilling to take the technical steps we showcased. **No, we won't.** You are expected to put some effort reading, and understanding what we talk about, and then putting at least some effort to get the setups we showcase.

**We're not going to take on the responsibility of making the setups work for you**, our responsibility lies in properly explaining why it's important, what the solutions are and how you can implement said solutions. **We're not going to actually setup those setups for you, you will anyway have to go through the path we carved out for you.**



## Technology that does not protect against anything    	

For example, showcasing how to install a [web radio](../../selfhosting/0_lainradio/index.md), is a preety cool thing to showcase, but it has absolutely ZERO justification to be showcased because it does not fit into any threat model.

![](../../selfhosting/0_lainradio/0.png)

You're not going to use a web radio to protect against any threat to your privacy, anonymity, or deniability.

You get the idea, I no longer care about regular sysadmin tutorials, like the ones i wrote in the selfhosting category of the blog.

The closest thing i'll accept to regular sysadmin tutorials is how to make a popular/very useful service work via a hidden .onion service like we did for the [Nextcloud](../nextcloud/index.md) or the [Anonymous Monitoring](../anonymous_server_monitoring/index.md) tutorials, because you essentially showcase how to implement a service while maintaining serverside anonymity.

The given technology that is being showcased has to fit into a proper threat model and opsec scenario, the showcased technology needs to either provide a solution to protect against a given threat, or serve a purpose for another technology that protects against a given threat, otherwise it is simply offtopic.