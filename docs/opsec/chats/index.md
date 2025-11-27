---
author: XMRonly
date: 2025-04-19
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/232"
xmr: 8AHNGepbz9844kfCqR4aVTCSyJvEKZhtxdyz6Qn8yhP2gLj5u541BqwXR7VTwYwMqbGc8ZGNj3RWMNQuboxnb1X4HobhSv3
tags:
    - OPSEC Concepts
---
# Public Chats / Private Chats / Anonymous Chats / Deniable Chats

```
TLDR: SimpleX can be used to have public, private, anonymous and deniable chats online
```


![](0.png)



## **Introduction**

  


When discussing the topic of OPSEC, an important concept that inevitably arises is compartmentalization. Broadly speaking, compartmentalization can be defined as separating different activities into different buckets in order to prevent them from being linked together. This concept is perhaps most commonly seen using online emails. You may want one email for all of your social media, a different email for all of your online purchases and a different email still for all health related items. This same concept can be applied to your online chats. In this tutorial, we will explore the different types of chats, how to compartmentalize them based on their contexts and when each one is optimal to use. 

## **OPSEC Requirements in Chats**

Another thing to note is that there are a ton of chat apps out there, and as we have explained [previously](../opsec4levels/index.md), depending on the level of Operational Security you are aiming for (whether it is privacy, anonymity or deniability), **the tool has to meet certain criterias to be suitable for the intended use**.

![](../opsec4levels/0.1.png)

As you're going to see shortly, depending on the types of chats you want to have, the chat platform you use is very much dependant on meeting the OPSEC requirements to match the intended uses.

## **Types of Chats**

The chart below describes 4 different types of chats. They are separated by their unique characteristics, and a brief description is provided along with technical details and some pros/cons for each category. 

- | **Public Chats**![](../logos/su2.png) | **Private Chats**![](../logos/su0.png) | **Anonymous Chats**![](../logos/on0.png) | **Deniable Chats**![](../logos/de0.png)  
---|---|---|---|---  
Description | A conversation that is viewable by anyone, taking place in a public medium | A conversation whose contents are known only to the participants | A conversation where some/all of the participants are not know by their real identities | A conversation that cannot be proven to have taken place  
Example | Alice and Bob speak in a sports stadium | Alice and Bob speak in a private glass conference room at work | Alice speaks to a mysterious man in a trench coat | Alice speaks to Bob but there is no record of their conversation or proof of what was said  
Technical Requirements (Online) | -None. **(everything you say is public knowledge)** | **-FOSS Software**</br>**-E2EE is required**</br> -You can self-host the chat server yourself![](../logos/ce0.png) | -FOSS Software</br>-E2EE is required</br>**-Upon signup, requires no phone numbers, no user IDs, and no IP address linkability (using Tor)** | -FOSS Software</br>-E2EE is required</br>-Upon signup, requires no phone numbers, no user IDs, and no IP address linkability (using Tor)</br>**-Disappearing messages**  
Pros | -Easiest to achieve</br>-No restrictions</br>-Suitable for any environment | -Contents of the conversation are visible only by the participants</br>-Many apps now implement E2EE | -May assume different anonymous identities for different conversations</br>-Suitable for exploring controversial topics</br>**-Anonymity is possible in public chats too!** | -Off the record</br>-No history of the conversation</br>-Suitable for sensitive topics  
Cons | -Anything said can be linked to your real identity | **-very few chat apps are FOSS on both the clientside and the serverside**</br>-The identity of the participants are known</br>-May still be known the conversation took place</br>-May be able to build patterns based on conversations | **-even fewer chat apps can be used to sign up anonymously**</br>-Deanonymization may happen based on what the anonymous party says | -Can't read the history of the chat beyond the time limit
  
  
  


![](1.png)

As with many things, these chats exist on a spectrum between being more convenient and being more secure. 

## ![](../logos/su2.png) **Public Chat Example**

Let's take a look at a few examples to illustrate these concepts. First up is a **public chat** similar to what you'd find online, on social media, in public chat rooms, etc. 

![](2.png)

This conversation, tied to Alice and Bob's real identities, is visible for anyone to see. Public chats such as this one pose the smallest barrier to entry as they can take place anytime/anywhere. Any information discussed, such as their plans together next weekend and mode of transportation, are now publicly known by anyone present at the time of the conversation. Alice and Bob may openly show their support for their favorite football teams, but what if there was some information they didn't want others to know? 

## ![](../logos/su0.png) **Private Chat Example**

For discussions involving information that is not necessarily meant for everyone to know about, we have **private chats**. In private chats, participants may still use their real identities, but the key differences is that the information is only accessible between the parties chatting and nobody else as the conversation is End-to-End Encrypted (E2EE). 

![](3.png)

Alice may be uncomfortable announcing to the world she's short on cash at the moment, but can confide in her friend Bob with this information. In this private chat, only Alice and Bob know what was discussed and a record of this conversation exists. Luckily many popular chat apps are starting to implement E2EE, but without also including metadata protections, patterns can still be gleaned based on which contacts you are talking to and how often. But there may be situations where someone may not want you to know who they are when they're speaking with you. What happens in that situation? 

## ![](../logos/on0.png) **Anonymous Chat Example**

For discussions where one participant (or multiple participants) don't want the conversation tied in any way to their real identity, we have **anonymous chats**. With increasing OPSEC requirements comes the need for more specialized software, which may be more inconvenient for certain people. 

![](4.png)

In this example, Alice is speaking with someone who doesn't want to have their persona tied to their real identity (the participant is using an incognito profile). The nature of the conversation may include controversial topics such as insider information. To achieve an anonymous chat, there must specifically be no user identifiers and no IP address linkability. An added benefit of having no user identifies is that a person can create disposable personas on the fly and use a different anonymous identity for each new conversation. But what if we need to communicate and can leave no trace of the conversation ever having taken place? 

## ![](../logos/de0.png) **Deniable Chat Example**

For the next step up, **deniable chats** , we must build on everything we've discussed up to and further employ disappearing messages. This is the only chat type suitable for discussing sensitive topics. 

![](5.png)

When Alice starts up this chat, she selects using a new incognito profile. Additionally, she navigates the chat settings to enable disappearing messages and sets a desired timeframe. 

![](6.png)

The icon next to the contacts name denotes Alice is speaking anonymously in this chat, and the timer in the chat denotes how long until the conversation messages auto-delete for all participants. After 24 hours, the contents of this chat will appear blank thus providing **plausible deniability** for all participants. This type of chat requires not only the specialized software, but also adjusting some settings to achieve, making it the most secure but also the most inconvenient of chat types discussed. 

## **Conclusion**

By compartmentalizing our chats based on our different requirements we can prevent topics we want to keep private from overlapping with our real identities. The advanced configurations discussed in this tutorial may cause some friction during setup, but the intuitive user interface makes it manageable for anyone willing to give it a try. More advanced users should look into [self-hosting their own SimpleX servers](../privatesimplex/index.md) and [routing traffic through Tor](../anonsimplex/index.md). 

