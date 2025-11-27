---
author: loki_opsec_inc
date: 2025-07-13
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/377"
xmr: 8AaLSmixWFJhgMmrBvqi6827v27YYT6H8C6SjUasHySBKna2JDk1dtEf2ZAUpXue64JDEBxkTL9oZGaoKtcWppWKHLSkTLM
tags:
  - OPSEC Mistakes
  - Bad Identity Segmentation
---

# Identity Segmentation Fails: Emails, Usernames, and Passwords

```
TLDR: Identity segmentation extends to the usernames, emails and passwords that you use accross services
```

In this post we're going to discuss how to handle email, how to properly segment your names for your various identities, and how to manage your passwords. Then we'll show you real-world examples of how people were caught by not adhering to these rules.

## Emails: An Easy Pitfall

One of the most common pieces of data used in surveillance is the email address. Email addresses are almost always used multiple times for multiple account sign-ups and communications with various people. They are easy to create, easy to establish correlation with between activities, and it's generally annoying to maintain more than a few email accounts at once which makes us want to use only a few at most at a single time. 

Not to mention that no legitimate email service is safe from government overreach and mass data harvesting, or even from email service providers themselves, as email is not inherently E2EE or metadata-resistant. Every single email provider hands data over to the government of the nation they reside in, even "private" ones like Proton, often without any resistance at all. So they will find every single service you signed up for and every person your contacted with that email account.

And when governments come knocking on the doors of any corporation, that corporation happily will give them your account info, including your email address, which will then be used to correlate your other activities. Corporations also will sell your email address to other corporations, further creating an even larger web of online footprints.

All this makes for the perfect piece of information for corporations and governments to target in surveillance. In short, email addresses are like a virus, infecting everything it touches, but useful when contained.

You SHOULD:
 - Create it and use it inside the context (Laptop, Virtual Machine, IP Address) of the identity you use it for.
 - Only use it for accounts and communications where you speak about things pertaining to the identity for which you created it
 - For extra paranoia, use different email services for different identities. Using the same service could possibly help with pattern correlation, such as displaying a preference for Proton email.

You SHOULD NOT:
 - Log into your email outside of your identity's context
 - Speak about or do things pertaining to your Public Identity while using an online account designated for Private Identity. 
 - Contact a single person using multiple emails from multiple identities

The ideal setup. Alice is not using her public email to contact any person or sign up for any account pertaining to her private ID, and vice versa:

![](./email-setup.png)

## Names: Why So Important?

It doesn't take a genius to figure out that you should not be using the same name to create accounts for multiple different identities.

However this importance goes beyond just naming yourself differently. One must also take care to not provide indirect correlation through topic matter.

Let's take a guy named Bob Smith. Bob Smith has a public identity with a LinkedIn, Twitter, and Youtube presence. His interests are clear: He likes cowboys and rock music. Everyone also knows his age and birthday. 

Now say Bob Smith wants to create a private identity to perform some grey-area activities. What should Bob call his new identity? Certainly not his real name. So Bob makes a name that feels close to himself and familiar, "RockinCowboy1991", alluding to his interests and birth year. Bob may *think* he is safe because he is not openly exposing his real name. But Bob does not realize he has just created correlation between his public and private identities.

![](./names.png)

In this instance it would be trivial for surveillance agency to do a metadata search on anyone born in 1991 who likes cowboys.

Naming correlation can also extend to conventions. For example, are you always using names of superheros? Are you always using a single word followed by 3 numbers? These kinds of conventions can create plausibility between your various identities especially if an adversary is already suspecting linkage.

![](./name-covention.png)

The best thing you can use is randomly generate your names, through random online generation tools searched for and accessed in the TOR Browser, or to use a password manager that has password and diceware generations. Some like BitWarden even have basic username generators too.

## Passwords

Although there are little to no major OpSec failure examples of using correlation techniques against passwords or hashed passwords, it is important to take care of your password management

In [this post](../passwordmanagement/index.md) we talk about how bad password management can lead to all accounts in a single identity getting hacked.

This [Whonix wiki article](http://www.w5j6stm77zs6652pgsij4awcjeel3eco7kvipheu6mtr623eyyehj4yd.onion/wiki/Passwords) is also a wonderful resource about password strength, increasing threats of brute-force cracking, and how to plan ahead accordingly.

So use very strong random passwords, and use master passwords for your managers and drives that are as strong as possible and you can remember.

## Real-World Failures

Now we're going to show you some real-life examples of people who did not follow these considerations, and paid the price for it.

### Example 1: Yossi Sariel, Israeli Spy Chief of Unit 8200 (April 2024)

Relevant news articles: 
 - [The Guardian (onion): "Top Israeli spy chief exposes his true identity in online security lapse"](https://www.guardian2zotagl6tmjucg3lrhxdk4dw3lhbqnkvvkywawy3oqfoprid.onion/world/2024/apr/05/top-israeli-spy-chief-exposes-his-true-identity-in-online-security-lapse)
 - [The Guardian (onion): "Digital trail identifying Israeli spy chief has been online for years"](https://www.guardian2zotagl6tmjucg3lrhxdk4dw3lhbqnkvvkywawy3oqfoprid.onion/world/2024/apr/09/digital-trail-identifying-israeli-spy-chief-has-been-online-for-years)

Sariel made MANY mistakes here. In this example, he was supposed to have 2 identities. One for his public life and one for his secret like an intelligence chief of a special unit. In the news articles you can likely point out many errors, but let's focus on just a couple here.

Firstly, is that he wrote a book about his activities as an intelligence officer and the leader of a particular unit. Then, in the book, he gave an email that was connected to his real name:

```
In a surprising lapse in security, the Unit 8200 commander included an anonymous email address in an electronic version of his 2021 book, The Human Machine Team, about the use of AI in military intelligence. The address can be easily traced to a private Google account created in Sariel’s name.
```
Although allegedly this email was created specifically for the matters of the book, he did not even practice basic OpSec as to exclude his real name. This violates the most basic rule: do not use matching names between identities.

Then, his sloppiness of linking his secret work to his public social accounts essentially erased any doubt of his position:

```
It also appears that Sariel maintained a number of social media accounts under his own name. The Guardian identified accounts apparently connected to him on Facebook, Instagram, Skype and LinkedIn.

The Facebook account, which was deleted late on Friday, appeared to include a photo of his face and was associated with a page belonging to an alumni group for Unit 8200 officers. The LinkedIn profile listed his rank of brigadier general and could be traced to accounts linked to the military intelligence unit.
```
Secondly, I want to point out one more key detail: The pseudonym he chose, "Brigadier General YS". You can see how wrong this is. He gave out 2 pieces of information in his "private" name. That he is an officer of this specific rank, and that his initials are YS. This of course is a huge violation of naming conventions.

![](./sariel.png)

### Example 2: Spanish Activist de-anonymized by linking emails across identities

Relevant News:
 - [CyberInsider: "Proton Mail Discloses User Data Leading to Arrest in Spain" (Wayback Machine onion)](https://web.archivep75mbjunhxc6x4j5mwjmomyxb573v42baldlqu56ruil2oiad.onion/web/20250701095225/https://cyberinsider.com/protonmail-discloses-user-data-leading-to-arrest-in-spain/)
 - [TechRadar: "Proton Mail recovery email leads to arrest of Catalan activist" (Wayback Machine onion)](https://web.archivep75mbjunhxc6x4j5mwjmomyxb573v42baldlqu56ruil2oiad.onion/web/20250512085424/https://www.techradar.com/computing/cyber-security/proton-mail-hands-data-to-police-again-is-it-still-safe-for-activists)

In this example, what happened is pretty simple: An activist created a ProtonMail account, then used an Apple email address as a recovery email for his Proton account.

So let's designate 2 identities that the activist has: a Public identity and an Anonymous identity. But rather than keep them both separated, he cross-contaminated by giving a piece of information from his Public identity over to an account that is only supposed to be for his Anonymous identity.

Then once he caught the attention of government by using his Proton email, the Spanish government went through the Swiss government and requested all available information on this account, which then gave them the recovery Apple email address, which they then went to Apple with and got his real-life name and information.

![](./spain-activist.png)

The lesson here is that, whether or not they do, Proton COULD give this info, and that in itself is more than enough reason to never cross-contaminate. You should never trust a corporation to safeguard your identity segmentation, the only proper segmentation is the kind you create for yourself.

### Example 3: Ross Ulbricht

This classic case of the former owner of Silk Road is known by many, but we want to go over one piece of info.

A good short article explaining the various OpSec fails made concerning email/naming choice: [Schneier.com](https://www.schneier.com/blog/archives/2013/10/silk_road-au.html) | [Archive.org onion](https://web.archivep75mbjunhxc6x4j5mwjmomyxb573v42baldlqu56ruil2oiad.onion/web/20241228140937/https://www.schneier.com/blog/archives/2013/10/silk_road-au.html)

```
In an October 11, 2011 posting to a Bitcoin Talk forum, for instance, a user called “altoid” advertised he was looking for an “IT pro in the Bitcoin community” to work in a venture-backed startup. The post directed applicants to send responses to “rossulbricht at gmail dot com.” It came about nine months after two previous posts—also made by a user, “altoid,” to shroomery.org and Bitcoin Talk—were among the first to advertise a hidden Tor service that operated as a kind of “anonymous amazon.com.” Both of the earlier posts referenced silkroad420.wordpress.com
```
The incriminating screenshots:

![](./ross-btctalk-post.png)

Source: [bitcointalk.org](https://bitcointalk.org/index.php?topic=47811) | [Archive.org onion](https://web.archivep75mbjunhxc6x4j5mwjmomyxb573v42baldlqu56ruil2oiad.onion/web/20240612213736/https://bitcointalk.org/index.php?topic=47811)

![](./ross-shoomery-post.png)

Source: [shroomery.org](https://www.shroomery.org/forums/showflat.php/Number/13860995) | [Archive.org onion](https://web.archivep75mbjunhxc6x4j5mwjmomyxb573v42baldlqu56ruil2oiad.onion/web/20250420102808/https://www.shroomery.org/forums/showflat.php/Number/13860995)

The lesson here is pretty simple. Ross used an identity for both Silk Road matters and also for giving out his Public identity information.

## Conclusion

Through these examples you can see how important these concepts are and be sure to practice them in your daily OpSec.
