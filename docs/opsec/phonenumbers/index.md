---
author: user@Whonix
date: 2024-05-26
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/14"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
tags:
  - Anonymity Explained
---
# Phone Numbers are incompatible with Anonymity

```
TLDR: Law enforcement has access to the history of where every simcard has ever been, and where they currently are, down to a few meters precision.
The only way of using a simcard anonymously is to use a non-KYC SaaS simcard provider that accepts monero payments.
```

## **Sim Cards: the Deanonymization Tool**

A Simcard is what you need to put into your smartphone in order to have a phone number. These simcards, once inserted into your smartphone are always communicating their geographical position to the nearest mobile carrier antennas. **Meaning the mobile carriers knows where your simcard is, at all times** , and they know where this simcard has been ever since it got inserted into your phone.

Now, it is possible for you to purchase a sim card (or e-SIM) anonymously using for example this service [here](https://kycnot.me/service/silent.link), but the fact remains the same, that once the simcard is active into your smartphone, **there is a permanent record of where that simcard has ever been** and there is nothing you can do about it. 

Naturally, law enforcement agencies LOVE to keep their hands on this data. They use it all the time. For example, **all it takes for LE to figure out who has been in a public protest is to record the protesters up close, while keeping track of the current time.** Then, if any of the protesters did anything illegal out there, **they can know who did the act by simply looking at which simcards were at the exact same time, at the exact same place.**

As we discussed [previously](../governments/index.md) for the law to be respected, it needs to be enforced. And to be enforced, the authorities need to know:

  1. ![](../logos/su2.png)What happened ? (lack of Privacy)

  2. ![](../logos/on2.png)Who did it ? (lack of Anonymity)




That's why protesters make the conscious choice to not go out to protest with their phones in their pockets, as they can get deanonymized very easily while wearing them. 

Because Simcards are actively used by Law Enforcement to know what is the location of a particular phone number is [using tools like StingRay II](https://iv.nowhere.moe/embed/wzSgLpNrr2E), but not only them, **every cellular provider also knows the location (up until present moment) of every phone number,[thanks to cellular triangulation](https://4n6.com/cell-phone-triangulation/).**

## **You cannot have an anonymous Phone at home.**

Let's suppose the following scenario:

  1. You bought an old phone (let's say a google pixel) anonymously using Monero, without going on a Centralised marketplace, Peer to Peer.

  2. You wiped that google pixel OS to install an open source host OS such as [GrapheneOS](https://grapheneos.org/)

  3. you made sure that phone never connected to the internet since you got it, and never used a simcard either.

  4. You then purchase an e-SIM card anonymously from a non-KYC service such as silent.link, using monero, and you activate it inside the phone.




Great, you now think that you obtained an anonymous phone number right ? Did you just forget that **there is a permanent record of where that simcard and phone number is, at all times ?** And did you forget that this record of where your simcard is, is always consulted by LE at all times ?

Where do you plan to use that simcard ? At your own house ? **The moment that simcard (and phone number) becomes active, LE knows that the simcard associated with that phone number is located your own house.** And then you take it with you to go to work ? If you are seen going anywhere at anytime, and LE looks at where the simcard went, **they can easily correlate that you are the owner of that simcard.**

Make no mistake with cellular tower triangulation they can pinpoint the location of a cellphone down to a few meters of precision, so it is preety accurate. Let's see what that looks like by taking Bob's phone location over the course of one day:

![](normal_map.png) If you keep your phone on, then an adversary with your phone number and the required level of access can pinpoint your location over time simply by asking the phone provider for your data, without you being aware of it.   
  
  


## **But what if I use a burner phone I keep in a faraday bag when not in use?**

![](faraday.png)

You might think that having stringent SOPS (standard operating procedures) around the use of burner phones in your organization could solve this problem. It does help as this map shows, but it's not enough. An adversary investigating your activities will have access to a lot of data and they will be able to use tools such as PostGIS to query their datasets in order to infer relible position information from scattered datapoints.   
  


###  **The Protest**

On the last day of december 2024, protest happened in Los Angeles. This event will be referred to as the **the Protest**.   


#### _From your point of view_

Using burner phones and cash payments, you rented a car under a false identity with Alice and Bob, both members of your organizations. You have strong OPSEC, you don't know each other's names or faces and keep your burner phones off and in faraday bags when not in use. You took this car to a specific place at a specific time in order to acomplish a goal that goes contrary to the policies and aims of a strong adversary. Your adversary has access to phone data and no meaningful budget limitations, they aim to identify you, physically locate you and then follow their policies. 

####  _From the adversary's point of view_

_Starting information:_

  * They have identified where the car was rented from
  * They have identified one suspect: Alice who was caught on camera being careless with their cap while renting the car
  * They have identified one other potential suspect of the three-persons team, a known associate of Alice, Bob
  * They need to identify you, the third member



#### _What happened_

Luckily, your OPSEC was flawless. Shades, cap, tradecraft, you have managed to stay under the radar. They know you exist from a blurry trafic cam picture but that's all. You did use your burner phone only when required.   
  
_What will the adversary do?_

  * Create a set of suspect sim cards based on spatial coordinates and timestamps: was this sim card in the same place and at the same time as Alice or Bob?
  * Refine this set by correlating it with other spatial coordinates and timestamps: when the car was rented, when the protest took place
  * Look for behaviourial anomalies: a sim card popping up in one place, disappearing for days and then reappearing later

They can quickly reduce their suspect pool from hundreds of thousands of people to a dozen using this method (see the concept of [Anonymity Odds](../anonymityexplained/index.md)). **If you were to make the mistake of reusing the same SIM card for another operation (such as simply taking out the phone while being at your own house)** after the protest you will have dramatically increased your chances of being identified by the adversary.   
  
  
As shown on the above map, **once a Sim card goes on, even if the phone is later shut off it will still leave a data trail**.  
  
**With each datapoint, an adversary will be able to reduce the pool of potential suspects** until they have enough certainty to start using active measures.

## **The only way to have an anonymous phone number, is remotely**

If you have a simcard next to you, no matter how anonymous you managed to get it, **the moment you start to use it, you are deanonymized**

![](1.png)

So the only way to be able to use a phone number anonymously, is to use a remote service provider, that allows you to use a phone number, anonymously (allows tor connections, and monero payments), and even then, don't expect to get privacy going that route. Examples of such services: [Crypton](https://kycnot.me/service/crypton) or [Smspool](https://kycnot.me/service/smspool). (see the full list [here](https://kycnot.me/?t=service&q=sms&xmr=on))

## **If a service requires your phone number, they are against your Anonymity**

If a chat service requires you to enter your phone number, it means they categorically refuse that you can use their service anonymously. Moreover, **it means that they want to be able to inform the authorities of your actions** , and rest assured that **LE will pay big money for that sensitive info they may have of your actions.**

Yes, you heard me correctly. **If a service asks for your phone number, they are anti-anonymity by design**. This means that you can already stop using the following services: 
    
    
    Signal, is a centralised service that requires a phone number upon signup[[1]](https://github.com/signalapp/Signal-iOS/issues/194)[[2]](https://github.com/signalapp/Signal-Android/issues/1085), see also [[3]](https://bencrypted.gitlab.io/post/8/) [[4]](https://digital-justice.com/articles/skip-signal.html)
    Telegram, is a centralised service that [also requires a phone number upon signup](https://www.geeksforgeeks.org/how-to-create-account-on-telegram/), on top of being forced to comply to EU demands as of 2024.
    
    

When you take into consideration how phone numbers harm your Anonymity as i listed above, **Nothing can can possibly justify requiring a phone number upon sign up.**

The only reason for such a requirement, is that **the service takes bribes from LE, for successfully lying that their users are safe.** Make no mistake, the bigger the service, the more lucrative it is!

Now if you want to be able to communicate anonymously with someone online, use [SimpleX](https://simplex.chat), and tell them to use it too with [this tutorial](../anonsimplex/index.md).

