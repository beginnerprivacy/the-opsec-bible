---
author: Nihilist
date: 2025-07-25
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/151"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
---
# How to transfer activities across identities

```
TLDR: Abandon your sensitive identity after 3 years, and use a new one, start fresh. Opsec Over Ego.
```

In this tutorial we're going to cover how to transfer activities from one identity to another, in case if an activity were to become unsuitable to be done from said identity.

## The separation of your 4 basic identities

As we have covered previously, we recommend that you segment your internet uses, using 4 distinct VMs:

![](../internetsegmentation/6.png)

- From the Public use windows VM you have your IRL identity (for instance Linus Torvalds)
- From the Private use kicksecure VM, you have your private pseudonym identity (for example being Nihilist)
- From the Anonymous use whonix VM, you have your anonymous identity (which is a random pseudonym like Zachary Jr)
- and lastly from your Sensitive use VM you have another random pseudonym as your sensitive identity, for example "DreadPirateRoberts"

## Using your identities for different activities

![alt text](image.png)

Each identity NEEDS to remain used separately from one and the other to avoid contaminations. 

For instance the banking app is to be used from the public identity, chatting with online friends needs to be done using the private identity, trolling on social media needs to be done anonymously using your anonymous identity, and any sensitive activity like criticising xinnie the pooh needs to be done deniably from your sensitive identity.

**Under no circumstances, should any of the 4 identities talk to each other publicly, nor directly interact with each other, nor indirectly mention each other.** That is to make sure that an adversary wouldn't suspect the possibility of any identity being linked to any other one.


## The right identity for the right kind of activity

You may have been maintaining a technical blog that covers hacking and sysadmin topics for years, which is perfectly suitable for private use, meaning you can keep managing it from your private identity just fine, 

But one thing to note is that over time, some of the activities that you used to do with your identities may start to turn into sensitive activities.

![alt text](image-1.png)

For instance, the technical blog that you were maintaining all this time could've evolved and matured into a blog that explains to everyone how to become ungovernable, by explaining why and how they can achieve privacy, anonymity and deniability. 

Directly going against every states's propaganda out there by literally telling everyone exactly why and how they can become ungovernable, may not be illegal, but let's be honest, it is most likely enough to make most adversary very butthurt and determined enough to take that service down in the future. **This is especially true when a given service becomes popular and big enough for an adversary to start caring about it.** Therefore if you have doubts when it comes to how sensitive your activity is, i advise you to not take any risks and ensure that sensitive activities are exclusively performed from your sensitive identity.

TLDR: **you may face the need to transfer activities from an identity to another.**

## Transferring activities from an identity to another

### The Controlled way: Passing the Torch (same project name, different identity)

The most controlled way of doing it is by "Passing the Torch". For instance let's suppose you have the following sensitive service:

![alt text](image-2.png)

For instance in the nowhere hierarchy we have 3 main ranks: Contributors, Maintainers, and Administrators.

You, as an administrator operating from your private identity, you may want to introduce your sensitive identity into the current organization starting from the bottom of the hierarchy, as a contributor.

![alt text](image-3.png)

Then gradually over time, you may want to make sure that this sensitive identity of yours gradually goes up the ranks (for example promoting it to the Maintainer rank)

![alt text](image-4.png)

And then finally you promote that identity of yours to the Administrator rank, and that's when it is ready to replace your original private identity:

![alt text](image-5.png)

Here comes the hardest part of the whole process: Publicly stating to everyone that you are retiring from said project. **This is especially difficult to do if you gathered a substantial reputation over the years as the private identity, because you have to publicly leave it behind, and abandon it.** The goal here is to officially retire your private identity from the project altogether.

For instance you can make a public statement like so:

```
Hello everyone, i am Officially retiring from the Nowhere project due to [insert some bogus reason]. I am transferring the all of my responsibilities and accesses to the Administrator DreadPirateRoberts, so please go to him instead of me for anything related to the nowhere project if you have any queries going forward.

It has been a good run, and I wish the nowhere team good luck for the future of the project. 
```
If said administrator is a relatively trusted member in the community, then it probably won't be suspected that you are said administrator, and you can carry on as ususal, the only difference being that you're now performing the same activities under a different name, for the same project.

![alt text](image-10.png)

This is a very long and controlled way of doing the activity transfer from one identity to the other. But as we're going to see, there is another way of doing it, that is much faster at the cost of being much more chaotic:

### The Chaotic way: Leaving the Torch (different identity and different project name)

This is other way of doing it is basically about abandoning the activity / shutting down the service altogether, and letting the competition take over. This way of doing things works well if you don't have time to infiltrate your sensitive identity in the organization.


For this way of doing it, the first step is to setup the competitor service using your sensitive identity:


![alt text](image-7.png)

Then the next step is to basically shutdown the existing service:

![alt text](image-8.png)

To do so you can publicly announce on a PGP signed message the following:

```
The Nowhere project and all of it's activities are ceasing immediately due to [insert bogus reason].
It's been a good run and we had a blast, but all good things come to an end.
```

As you can see this exit message leaves zero mention to the competitors names, you are basically trusting that your community is going to have the sense to actually find the competitor service and go there as a substitution. Hence the lack of control that this option has.

And from there you can keep doing the same activity but under a different name and under a different project name.

![alt text](image-9.png)

This way is more chaotic because by operating under a different project name you not only ditch your previous identity's reputation, but you also ditch the previous project name's reputation in the process.

This means that the effort it takes to restore the reputation is doubled, because you have to work again to restore the reputation of both the project and also of your new identity.


## The Aftermath

After transferring the sensitive activity from your private identity to your sensitive identity, you have a few rules to follow:

- as your private identity, the one and only public message you are allowed to say is **"i do not do any sensitive activity."**
- as your private identity, even if pressured to do so, **never claim that you are behind that sensitive identity.**
- as your sensitive identity, even if pressured to do so, **never publicly claim that you are the same person behind the private identity.**

This is to ensure that both identities remain permanently separated from each other, even after the activity transfer has occurred. You must never allow an adversary correlate that you are the same person behind both your private and sensitive identities.


## Sacrificing your Ego for Opsec

You can view act of abandoning a persona (and it's reputation) to uphold Opsec as the ultimate proof that you're [not egocentric](../../productivity/sum-nihil/index.md).

I doubt many people are willing to sacrifice the reputation that they've gathered over the years to uphold the projects that they are working for. Sometimes it is because people are unwilling to abandon the prestige and reputation they worked so hard to achieve that ultimately their operational security ultimately erodes, and they get caught.

Over time, even if you do everything to protect your true identity from being discovered, you are increasingly more likely to do deanonymizing Opsec mistakes without knowing, and if you actually do opsec mistakes that may deanonymize yourself, over time it is increasingly more likely for an adversary with enough resources to actually find them.

![alt text](image-12.png)

That's why i think, if you want to be an actual operational security purist, that **you should periodically (let's say every 2 to 3 years) officially retire your sensitive identity, in favor of the next one**, that way if there are any opsec mistakes to be found later down the line, those should only affect the previous sensitive identities that are no longer being used right now.

Opsec over ego. Sometimes the sacrificing one's ego and reputation is the price to pay to uphold one's opsec, especially if there are risks of deanonymization at play, for sensitive activities in particular. 