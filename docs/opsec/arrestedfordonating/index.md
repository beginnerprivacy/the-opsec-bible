---
author: Crabmeat
date: 2025-08-31
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/449"
xmr: 89aWkJ8yabjWTDYcHYhS3ZCrNZiwurptzRZsEpuBLFpJgUfAK2aj74CPDSNZDRnRqeKNGTgrsi9LwGJiaQBQP4Yg5YtJw2U 
tags:
  - Opsec Mistakes
  - Not Using Monero
  - Not Using SimpleX
  - Bad Email Provider
  - Clearnet Sensitive Activity
---
# Man arrested for donating to a terrorist organization

```
TLDR: if you want to send money anonymously and privately, use monero
```

> We do not, and will never, encourage anyone to support actual terrorist organizations in any form. The purpose of this blog post is to **analyze the mistakes** that were made and how they could have been avoided. It is intended **solely for educational purposes**.

## Governments are the only one choosing who is a terrorist 

Before going further in this blog post, it is important to understand the following notion: any group, individual, or organization can be designated as terrorist by the state if it opposes the state's interests. This means that if you are known for supporting such a group, your actions could suddenly become illegal, depending on shifting political decisions. Ultimately, it is the state that decides who will be labeled a terrorist, and these designations [vary](https://en.wikipedia.org/wiki/List_of_designated_terrorist_groups) from country to country.

The definition of terrorism is a tricky one, and it can be applied to various contexts depending on how you interpret it. Here is a commonly accepted definition:

1) The use of violence or the threat of violence, especially against civilians, in pursuit of political goals.

2) The act of terrorizing, or being in a state of terror; a mode of government by terror or intimidation.

3) The practice of coercing governments to accede to political demands by committing violence on civilian targets; any similar use of violence to achieve goals.

![](countries.png)

Does this sound familiar to you? You can actually apply this definition to any state's actions, including the United States. Let's take a look at the U.S. example, which is where Jonathan Xie's story took place.

1) The use of violence or the threat of violence, especially against civilians, in pursuit of political goals.

*During the [Vietnam](https://en.wikipedia.org/wiki/Vietnam_War) War, the U.S. army dropped napalm on civilian populations in order to “fight communism.” This is a textbook example of using violence against civilians to pursue political goals.*

2) The act of terrorizing, or being in a state of terror; a mode of government by terror or intimidation.

*In some U.S. states, the death [penalty](https://deathpenalty.org/usa-death-penalty/) is still in place, and this can be seen as a form of government-sponsored intimidation, where the threat of state-sanctioned violence can be used to coerce compliance with the law.*

3) The practice of coercing governments to accede to political demands by committing violence on civilian targets; any similar use of violence to achieve goals.

*The U.S. government has been involved in military interventions that resulted in civilian [casualties](https://en.wikipedia.org/wiki/Casualties_of_the_Iraq_War), such as the Iraq War, which was, in part, an effort to force the Iraqi government to implement a democratic system, through violent means.*

Based on that, anyone or anything can be considered a terrorist and labeled as such. This means that whoever you decide to support in any way, you should do so anonymously.

As an example, several people supporting ecological movements in [France](https://www.politico.eu/article/france-emmanuel-macron-disbands-climate-movement-eco-terrorism-allegations-soulevement-de-la-terre/) have been labeled as terrorists, simply because they oppose state decisions. This illustrates how the definition of terrorism can be manipulated to target those who challenge the status quo.

![](soline.png)

This blog post isn't just about what happens when someone donates to a terrorist group. It's about what can happen as any donation could be classified as support for a terrorist organization if the government decides to label it as such. The goal here is to show you how to avoid the situation Xie faced by understanding the critical OPSEC mistakes that led to his downfall.

## What happened ?  

Jonathan Xie, an American citizen, was sentenced in 2019 to more than five years in prison after being [convicted](https://www.justice.gov/usao-nj/pr/somerset-county-man-sentenced-64-months-incarceration-concealing-material-support-hamas) of sending money to Hamas. Since Hamas was designated as a terrorist organization by the U.S. at that time, the official charge was “Concealing Material Support to a Terrorist Organization.”

The purpose of this blog post is to analyze how he was caught and to identify the OPSEC mistakes that led him to jail. You will see that he made several errors that could have been avoided quite easily. This analysis does not aim to judge Jonathan Xie as a person, but only to examine his actions through the lens of OPSEC best practices.

![](xie.png)

## What mistakes were made

As stated before, Jonathan Xie made several OPSEC [mistakes](https://web.archive.org/web/20250816220323/https://www.dailymail.co.uk/news/article-7061697/Pictured-Hamas-obsessed-New-Jersey-teen-bragged-Instagram-plot-blow-Trump-Tower.html) that led to his arrest. 

### Using Instagram 

The first, and most obvious one, was using mainstream social networks to share both his actions and his political opinions. Let's take a look at two posts he published on Instagram.

The first was a post he made just after sending $100, in which he wrote:

![](instagram.png)

In this post, published on a Meta-owned social media platform, Xie openly stated that he had sent money to Hamas and that he didn't care about the legal consequences of this action. Since Meta is well known for widely [sharing](https://www.wire19.com/government-requests-for-user-data-surge/) user data with authorities, it was a major mistake to publicly admit to something considered illegal on their platform.

But Xie didn't stop there. Later, he shared a video of himself wearing a ski mask, carrying a gun, and holding a Hamas flag, in which he said he wanted to join a pro-Israel march to shoot participants. Once again, he posted content that could be interpreted as a terrorist threat on Instagram, providing even more evidence for federal investigators.

I won't go into detail about all the posts and conversations in which he claimed he wanted to bomb the Trump Tower or the Israeli embassy. The key point remains the same: he shared these threats on [Meta-owned](../closedsource/index.md) social networks, which made it easy for authorities to collect evidence against him.

Here, the message is just: If you admit to perform "illegal" actions, do it anonymously and through the correct media. Not like he did. 

![](meta.png)

### Using Bitcoin and Moneygram

In order to send money to Hamas, Xie used Bitcoin. The issue here is that Bitcoin does not allow for true [anonymity](https://buybitcoinworldwide.com/anonymity/). Bitcoin [blockchain is transparent](../truecrypto/index.md#a-cryptocurrency-is-born) that enables governments to track transactions and trace user activity. Additionally, he used [MoneyGram](https://www.moneygram.com/us/en) to facilitate the payment.

MoneyGram is a clear-web platform dedicated to sending payments to foreign countries from the US. This platform is not anonymous, as registration requires personal information such as:

![](moneygram.png)

So, he basically used non-private and non-anonymous cryptocurrency through a non-anonymous and non-private platform to perform illegal actions. That's exactly where the issue lies. Performing such actions under open surveillance from the government is never a good idea.

He even kept the receipt that was found by the FBI later. 

![](receipe.png)

### Talking about it online 

The final major mistake made by Xie was discussing his actions online and explaining how he carried them out. The key principle here is that if you want to remain anonymous, you should never use accounts linked to your identity to talk about sensitive actions.

In Xie's case, he ended up communicating with an undercover FBI agent and disclosed details about how he sent money to Hamas. Here is an example of an email he sent:

![](mail.png)

As you can see, several mistakes were made here. First, the email was sent from a Gmail account. Since Gmail requires a valid phone number for activation and is heavily tied to government surveillance, it is far from anonymous. Even if the address itself doesn't show his full details, it appears to contain at least part of his real name, which already compromises his privacy.

On top of that, he sent a tutorial to the undercover agent explaining how to send money to Hamas. By doing this without anonymity, he essentially provided investigators with additional evidence against himself, making it even easier for them to build a case.

![](tutorial1.png)
![](tutorial2.png)
![](toturial3.png)

### To summarize

In order to summarize the mistakes made by Xie, here is a quick graph: 

![](xiepath.png)

## What could have avoided being caught ? 

First of all, it is all about [privacy](../privacy/index.md) and [anonymity](../anonymityexplained/index.md). Every mistake made by Xie was connected to these two principles. If you want to donate anonymously to any cause of your choice, you should carefully follow these steps:

### Using Monero 

First of all, any transaction carried out on the internet should be done with [Monero](../monerofirst/index.md) if you want it to remain anonymous. It is the only cryptocurrency designed to allow private transactions without surveillance and without relying on KYC (Know Your Customer) platforms. We have a lot of tutorials about Monero, do not hesitate to take a look at it. 

![](xmr.png)

### Not talking about it online

Talking about something you know is illegal online is one of the best ways to get caught. Sure, you could use [SimpleX](../anonsimplex/index.md) to guarantee your anonymity, but in Xie's case, since he was communicating with an undercover agent, he would have been caught anyway.

Even if we look beyond that, posting about illegal activities on a platform like Instagram is a huge mistake. It's essentially the same as talking directly to the government. To drive this point home, let me share a 2022 [analysis](https://web.archive.org/web/20241014153255/https://backlightblog.com/instagram-privacy-policy-review) of Instagram's privacy policy.

Here's a summary of what Instagram collects from you:

- Everything you record using the in-app camera

- Location data: both the location of your photos and your real-time location based on your IP address

- Interaction data: What content you view, what actions you take, who you interact with, and how often

- Your contacts: The people you text, along with timestamps and message frequencies

- Metadata: Things like your device model, OS, app version, battery level, available space, browser type, device ID, Bluetooth signals, language, and time zone

- Network data: Mobile operator, phone number, IP address, connection speed, Wi-Fi signal, and more

- Third-party data: Data from partners, such as Facebook login, APIs, SDKs, or the Meta Pixel

![](review.png)

What a cute little spy... 

As you can see, Instagram isn't just collecting surface-level information. This kind of granular data, if tied to illegal activity, gives authorities all they need to track, trace, and ultimately connect the dots. This is why publicly talking about illegal actions online, especially on platforms like Instagram, is one of the worst mistakes you can make if you want to remain anonymous.

### Using an anonymous email service 

Using Gmail is never a good idea when you want to remain private and anonymous. Gmail shares data with governments and has strict KYC processes in place. Fortunately, there are [solutions](../anonemail/index.md) to create anonymous email addresses that allow you to avoid relying on such services.

> Just a little warning: even if your email address is anonymous, there are still ways you can be compromised while using it. For example, if you send an image, make sure to remove all [metadata](../anonymitymetadata/index.md) first, as it may contain information like location, device details, or timestamps.

![](kyc.png)

## Conclusion

As seen throughout this blog post, Xie made several mistakes that ultimately led to him being caught. Publicly exposing illegal activities is never a good idea. More broadly, if you want to keep anything anonymous, we are not talking specifically about funding terrorism here, but any activity, you must follow strong OPSEC practices.

There is absolutely no reason to allow the government to spy on you while you act online or offline. Protecting your privacy is protecting your freedom.

If you want to learn more about this case, here is the full [complaint.](https://www.justice.gov/usao-nj/press-release/file/1164941/dl?inline=) 
