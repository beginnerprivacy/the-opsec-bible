---
author: Nihilist
date: 2025-06-29
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/359"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
tags:
    - Anonymity Explained
    - Conspiracy Theory
---
# The German and Netherlands Tor Nodes problem

```
TLDR: I don't think it's normal that there are so many german and netherlands Tor nodes, but there's no definite proof of who's behind them.
```

On the surface, it looks like the Tor network is preety diverse if you look at the [distribution of Autonomous Systems for Tor relays](http://hctxrvjzfpvmzh2jllqhgvvkoepxb4kfzdjm6h7egcwlumggtktiftid.onion/bubbles.html#as):

![alt text](image-3.png)

However when you open the Tor Browser, go on any website, and click "New tor circuit for this site" a few dozen times, noting down which countries come up the most, you might see the same as i do:

![alt text](image-1.png)

![alt text](image-2.png)

![alt text](image.png)

Have you ever wondered why there are so many tor nodes in [Germany and the Netherlands](http://hctxrvjzfpvmzh2jllqhgvvkoepxb4kfzdjm6h7egcwlumggtktiftid.onion/bubbles.html#country)? 

![alt text](image-4.png)

This is currently shrouded in mystery, if a state were to be behind this disproportionate tor relay repartition, and there are no concrete proof of anything, but still i hope everyone approaches this with the same level of skepticism as i do:

**Disclaimer, Since there is no definitive proof and only speculations, be warned that we're entering into conspiracist waters. Take this blogpost with a big grain of salt.**




## The Optimistic Speculation: All preety flowers

In an optimistic scenario, this could just be that German and Dutch people are more privacy and anonymity-aware than the rest of the world, and that's why they are nearly running half of the tor nodes in the entire world. Which would be a good sign.

If this is the case, then i recommend to not edit your Torrc at all, simply blend in with the other users 

It could also simply be because german and netherlands cloud providers have cheaper hosting prices in general, hence they attract more people to run tor nodes there, unlike in other countries which charge much more to rent servers.

### The Darknet Markets serve as a Benchmark to Tor's provided Anonymity

![alt text](image-16.png)

Let's take a recent example: [The Archetyp Market](http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/d/archetyp) has been online for 5 entire years (from 17th May 2020 to their seizure on June 2025)

![alt text](image-10.png)

Still we're not sure as to what opsec mistakes led to their arrests, but 2 things are IMHO very unlikely to have been the root cause:

- Monero is (imo) very unlikely to have been the source of their opsec mistakes, otherwise they and their users would have been arrested a long time ago
- Tor is also (imo) very unlikely to have been the source of their opsec mistakes either, because otherwise the infrastructure would have been immediately taken down upon showing up and being on the cops' most wanted.

**Their longevity alone says that the Anonymity provided by the Tor network is still intact**, until proven otherwise when the court documents will be released, i think it's safe to assume that neither Tor nor Monero were the source of their downfall. As it has been the case for all previous darknet market seizures [with the exception of Silk Road 2.0 in Operation Onymous](https://en.wikipedia.org/wiki/Operation_Onymous).

This is my optimistic outlook on this issue, If either the Tor network or Monero were actually compromised, then all Darknet Markets would have been taken down right now, but it's not the case. 

## The Realistic Speculation: The Mixed Bag

In my opinion, the realistic scenario is that the existance of the Tor network itself has been making the authorities around the world very butthurt about the fact that individuals, worldwide can stay anonymous online, and to try and assert their god complex, they repeatedly tried to do deanonymize it's users over the years, with varying levels of success.

Tor 0days have been used to successfully deanonymize users in the past like in operation Onymous, but upon said 0day being revealed as such, the Tor developers fixed it afterward.

![alt text](image-5.png)

![alt text](image-6.png)

The States and their bootlickers around the world want to give everyone the impression that the state is all knowing, all seeing, and all powerful, in an attempt to instill fear and make everyone respect their arbitrary laws, so whenever they have the opportunity to spread FUD that tor has been cracked, they don't hesitate like in the examples below:

![alt text](image-9.png)

![alt text](image-8.png)

_Sidenote: Sam bent made a [40 minute long video](https://www.youtube.com/watch?v=spLqyfHV8TQ) to refute that article in particular_

And despite the amount of effort it takes to refute made up bullshit is greater than that required to produce it, Tor project themselves have stepped up to refute their FUD attempts:

![alt text](image-7.png)

In short, the german authorities twisted the facts and framed it as if tor was no longer secure, despite their only way of arresting said tor user was to pwn the outdated ricochet software that they were running.


In the 25 years of Tor's existance, states around the world must have had enough time to :

- grow increasingly more butthurt about Tor's provided Anonymity, and increasingly more desperate to stop it
- try to shut down the tor network (which failed obviously)
- try to infiltrate the tor network with malicious tor nodes (which i believe there is a very high chance that they are trying to do that)
- put state-level resources and international police cooperation to try and to deanonymize users to try and stop darknet markets on priority.
- try to DDOS hidden services in an attempt to take them offline (such as the [DDOS attacks that dread faced](https://undercodetesting.com/dread-under-ddos-attack-understanding-darknet-infrastructure-resilience/) which led to the development of [Endgame](http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/d/endgame) and the introduction of the [PoW challenge to stop DDOS attacks](https://blog.torproject.org/introducing-proof-of-work-defense-for-onion-services/))

Given the past attacks that Tor has sustained and evolved from, i think it's not unlikely that state-level adversaries are running malicious tor nodes to try and spy on the network to deanonymize some users whenever their circuits pick the wrong nodes.

For instance i've experienced many times some german / netherlands tor circuits that were exceptionally slow, and the high probability of having one of those nodes in any circuit makes it suspicious aswell.

I'm guessing that there are timing attacks at play, the adversary may have deployed a large amount of tor nodes to try and make it so that the largest amount of people in the world inadvertedly use their nodes as their circuits. Yet the problem is that there is no way to prove that this is the case.

![alt text](image-11.png)

In theory, if all nodes are controlled by the same entity, then that user using that particular tor circuit is effectively deanonymized. Which led me to create this thread on the [torproject forum](https://forum.torproject.org/t/what-if-an-adversary-is-running-all-3-nodes-that-your-circuit-has-picked/16968):

![alt text](image-12.png)

I didn't get a definitive answer on the issue, but i firmly believe that all traffic should look identical, to make it impossible for an adversary to differentiate anyone's traffic from each other, even based if all of your tor nodes are owned by the adversary. The traffic shape (the latency, the bandwidth usage, the packet size, etc) is all potential deanonymizing metadata that [Mullvad VPN claims to solve with DAITA](https://mullvad.net/en/vpn/daita) and that [NymVPN claims to solve aswell](https://nym.com/)

![alt text](image-14.png)

![alt text](image-13.png)

As usual, approach VPNs with caution as these are centralized entities that are after profit first and foremost, so they may not be fully honest in their marketing claims. Always double-check their claims on their git repos, to validate if there's truth behind it.

## The Pessimistic Speculation: the majority of German and Netherlands Tor nodes are malicious

Now here's the third speculation that i hope isn't true; **take note that there is neither proof that is true, nor proof that it isn't true.** What if the majority of the German and Netherlands Tor nodes were in fact malicious ?

If that were the case, it would mean that everytime you have a Tor circuit that only goes through these 2 countries, you might end up deanonymized without your knowledge, as the adversary would see from where you connect, to where you're connecting.

In the case of a clearnet connection, it would require that your circuit goes through 3 malicious tor nodes, and on the hidden service connection case, your circuit would need to go through 6 malicious tor nodes to end up deanonymized.

IMHO if it were to be true that a state-level threat actor is running the majority of the tor nodes of Germany and Netherlands, then this is not something that we should let happen. If it were to be true, that would mean that one adversary would be able to deanonymize all users whose tor circuits go through Germany and the Netherlands, which has a very high likelihood of happening due to the amount of tor nodes in those 2 countries.

**Then, to explain (in a pessimist way) the exceptional longevity of legit darknet markets, if the deanonymization was actually real, it would mean that the authorities would already know who to arrest and what to seize, and still intentionally wait years to try and gather enough intel to arrest as many users as possible.** That strategy could be like waiting for the fruit to be ripe enough to make headlines around the world, but i highly doubt it, i lean more on the aforementionned optimistic speculations i wrote above.

### The Pessimistic solution: What can i do about it ?

By tweaking your Tor torrc configuration, you can make sure that your tor circuits do not go through either Germany or Netherlands, by doing the following steps:

On both the clientside and the serverside you can edit your torrc config file to have the following lines:

```
[ localhost ] [ /dev/pts/7 ] [~]
→ vim /etc/tor/torrc

[ localhost ] [ /dev/pts/7 ] [~]
→ cat /etc/tor/torrc | tail -n3
ExcludeNodes {de},{nl} 
ExcludeExitNodes {de},{nl}
StrictNodes 1

[ localhost ] [ /dev/pts/7 ] [~]
→ systemctl restart tor@daemon
```

On the tor browser side, you can edit the torrc configuration as follows:

```sh
[ localhost ] [ /dev/pts/6 ] [~]
→ vim ~/.tb/tor-browser/Browser/TorBrowser/Data/Tor/torrc-defaults

[ localhost ] [ /dev/pts/6 ] [~]
→ cat ~/.tb/tor-browser/Browser/TorBrowser/Data/Tor/torrc-defaults | tail -n5
[ localhost ] [ /dev/pts/6 ] [~]
→ cat ~/.tb/tor-browser/Browser/TorBrowser/Data/Tor/torrc-defaults | tail -n4

ExcludeNodes {de},{nl} 
ExcludeExitNodes {de},{nl} 
StrictNodes 1
```

Then simply restart the Tor browser by hitting Ctrl+Q and then re-launch it, Then check if your tor circuits are going through those 2 countries or not:


## How does that impact my anonymity ?

First of all the amount of nodes your circuits can go through is reduced since we're excluding nodes based on their countries, but this is a mechanism that is enforced from the tor daemon side, it's not as if the german or netherlands tor nodes were recieving a message that you don't want to use them, so i don't think this is necessarily an issue.

Therefore as far as i'm concerned, it's not as if you were signaling to the potential adversary that you dont want to use their tor nodes, it's just that you're using other nodes than their potential malicious nodes.

However, since Anonymity is about blending in with other users, in theory we shouldn't change any default option on the Tor browser, but if this pessimistic speculation were to be true, then i think we wouldn't have a choice but to actually resort to this workaround until Torproject fixes the underlying problem: Making sure that all traffic in between all users are indistinguishable from each other, [in a mixnet fashion](https://nym.com/mixnet).

![alt text](image-15.png)

In my opinion, i think we should not have to pay to get those features that nymvpn is offering, those should be bundled in Tor directly, as Tor is supposed to stay the leading Anonymity network out there.

I think that this is a clear opportunity for the Tor network to evolve further, by implementing at least parts of the technology that Nym is trying to provide, to prevent packets from being deanonymized by their size and timing patterns. That way in theory it wouldn't matter if the adversary were to run all nodes, they would not be able to distinguish where bob and alice and any other users' traffic exits their nodes, maintaining their Anonymity.

## How Can I contribute to the Tor network without worsening this potential problem ?

As i detailed in my other tutorial on [how to run a Tor node](../tor/relay/index.md), you should NOT run tor nodes in the germany, nor the netherlands. there are already way too many nodes in those 2 countries. On the contrary you should try to run powerful tor nodes (with dedicated servers, with unshared 1gbps bandwidth ideally) in countries that have very few tor nodes.

That would decrease the likelihood of everyone's tor circuits to go through those countries, and increase the decentralisation of the Tor network even more.

In conclusion, there is an abnormal amount of tor nodes in Germany and the Netherlands, i don't believe this to be a coincidence, even if there is no proof to validate that an adversary is running those nodes, nor proof that an adversary isn't running them. Again, take this entire blogpost with a grain of salt, as this has been bothering me for a while now.