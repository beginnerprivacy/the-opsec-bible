---
author: gregar17
date: 2025-09-08
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/330"
xmr: 4289v2jfjXmb8t7C3oyB7qVfyYG4BKeoDeiMKJMsrQTpcC7sFwcQ3CnWjtnYKnKXv9SDRjAgWWEoV2sg5Z7rWzQ2DuGyZjd
---

# Reddit’s Decline for Real Privacy Discussions

In this blogpost we're going to explain why Reddit is no longer interested in privacy and showcase some private alternatives to this popular news aggregator.


## **Why is this important ?**


If you've been alive for long enough, you might remember the times when Reddit used to be an **oasis of information** for people seeking to freely express themselves and have uncensored discussions. 

And if you've been close to Reddit in the last few years, you might have witnessed it's **slow descent into the opposite of what the original founders intended**. Or perhaps, you joined Reddit quite recently and have no idea about the privacy issues that plague the platform in its current form.

![](logo.png)

Whatever might be the case, hopefully your takeaway from this blogpost will be an **understanding of how Reddit no longer cares about privacy, and what you as a user can do about that**. 

Because even if you don't personally use Reddit, there's a high chance you know someone who does, as the amount of Weekly Active Users has grown in the last couple of years, and [spreading the word about online privacy is always a good thing.](../10-step-checklist/index.md)

![](weekly_active.png)

As of July 2025, Reddit is the 7th most popular website worldwide, measured by web traffic, which puts it close to or even **above Wikipedia's traffic**, depending on the source you check on. 

![](semrush.png)

**For a lot of people, it is their primordial source of information**, but it has many privacy considerations to take into account. So let's first take a look at a **brief history of this social news aggregator**, and some pertinent controversies that have surrounded the platform throughout the years.



## **Brief history of Reddit**

Reddit was founded in 2005 by Steve Huffman and Alexis Ohanian, with Aaron Swartz joining soon after. **The original idea behind this website was to allow users to share links, discuss them openly and promote free speech**. This should come as no surprise to you if you've heard of **Aaron Swartz, who was a major figure in the digital freedom and open-access movement.** 

![](aaron.png)

He was a **co-author of the Guerilla Open Access Manifesto, advocating for free, unrestricted access to information and academic research.** Sadly, this didn't sit well with people in power, who pressed **serious legal charges against him for uploading MIT academic papers to the open internet.** 

The charges kept adding up, and this led to a federal case being made against him, dubbed **"United States v Aaron Swartz"**. And so, allegedly because of fear towards the government and it's moves against him, **in 2013, Aaron commited suicide.** 

![](aaron_death.png)

Although his time in Reddit was short-lived, leaving in 2007, this same open access philosophy became a core part of Reddit's identity. **It's codebase was open-sourced in 2008, and it stayed that way for almost a decade, until 2017**, when, citing maintenance issues and code misuse, the website made it's source code private again, and that's generally [not a good thing](../closedsource/index.md).

Although the platform has found itself in the midst of multiple controversies throughout these years, let's touch up on some of the most relevant privacy-related incidents. 

### Reddit's Privacy-related controversies

Reddit has long battled accusations of shadow banning, manipulated visibility, and selective moderation—often **suppressing controversial but non-violent communities** under the guise of policy enforcement. 

This includes **banning** various subreddits including those discussing darknet markets, hacking, and controversial political views. **All of this despite previously claiming to support free expression.**

![](banning.png)

#### 2023 API Changes

In 2023, Reddit decided to **terminate the free access it had historically provided for its API**. This severely limited existing 3rd Party Reddit clients, like Apollo (iOS) and Reddit is Fun (RIF). 

Not only was it no longer free; the pricing was revealed to be ridiculous, and essentially a death sentence for alternate clients. Christian Selig, Apollo Developer, shared online that with the amount of Reddit Traffic his app had, **he would have to pay Reddit $20 Million USD per year in order to continue accessing their API.**

![](api.png)

**Their stated reasoning behind this move was to prevent AI scraping** and Ad-blocking, which "cut into Reddit's revenue". But all of this was recieved as a very unfriendly maneuver towards the userbase, which immediately started protesting.

**More than 8000 subreddits went private, in a planned blackout, which Reddit CEO Steve Huffman easily dismisse,** and doubled-down on the API changes, even blaming Apollo Developer of "threatening" Reddit, and mocking him, which he provided proof against, with an audio recording of his phone call with Reddit.

![](protest.png) 

Spoiler alert: they couldn't. **The Reddit team threatened moderator teams of protesting (closed to public access) subreddits**, that they would be removed if no moderator was willing to reopen the community. And so, **after two weeks of making their subreddits unaccesible, [most communities opened back up](https://www.theverge.com/23779477/reddit-protest-blackouts-crushed)**, returning the platform "almost back to normal". 


#### 2024 Deal with Google

Remember that the stated reason for Reddit pricing their API was to "prevent AI scraping"? **They must have meant, prevent AI scraping without us taking a cut of the profit**, because on February 2024, a deal with Google was made.

![](google_deal.png)

**In exchange for augmented exposure for Reddit in Google search results, Reddit posts would be used to train Google's AI chatbot Gemini.**

This apparently turned out great for Reddit, as more than half of its incoming traffic now comes from Google.

![](incoming_traffic.png)

###  Reddit is no longer interested in privacy

#### Banned Subreddit dedicated to darknet markets

Although it operated for various years, Reddit suddenly decided to take down one of the most used Darknet related subreddits, r/DarkNetMarkets.

![](banned_sub.png)

**Their official statement says:** “As of March 21, 2018, we have made a new addition to our content policy forbidding transactions for certain classes of goods and services. **Moving forward, we are prohibiting transactions that are either illicit or strictly controlled.** Communities focused on such transactions and users who attempt to conduct them will be banned from the site.”

#### Publicly traded company

One month later, in March 2024, **Reddit began trading on the New York Stock Exchange**, which made evident the controversial decisions it made in the last year, as **its main priority shifted towards profit above all else, including users and their privacy.**

![](ipo.png)

#### Official clients filled with trackers

This is evident if you take a closer look at their official Android app. After getting rid of big 3rd party clients through their API changes, most users access Reddit mobile either through the website or the official Android app.

On the one side, **the official Android app has been found to be filled with trackers**, including those from Google, Facebook and other third-party analytics companies. **These collect user behavior, device info, and interaction data for targeted advertising.**

![](app_trackers.png)

And their clearnet website is no different in this regard. It uses Google Analytics, DoubleClick, and other ad tech **scripts that profile users and track them across the web.**

According to their own privacy policy, Reddit states that the information they collect from their users include: 

![](privacy_policy.png)

**And all of this data is used for ad targeting, profiling, and now, resold for AI training.**

If you're interested in learning more about all the data Reddit collects, you can check out their [Privacy Policy](https://www.reddittorjg6rue252oqsxryoxengawnmo46qy4kyii5wtqnwfj4ooad.onion/policies/privacy-policy?rdt=63141#information-collected). And don't worry, this links directly into their Onion Site. Yes, you read that right. Despite all their recent anti-privacy decisions, Reddit still maintains a working Onion site.

### A weirdly positive move

So let's also give credit where credit is due. Reddit still has a [**working onion site**](https://www.reddittorjg6rue252oqsxryoxengawnmo46qy4kyii5wtqnwfj4ooad.onion/) which has been **active since 2022.**

![](tor.png)

And although this is better privacy-wise than accessing the clearnet website, **it doesn't offer meaningful anonymity beyond transport-layer protection.**

You can't create an account via Tor, so using a regular account registered on the clearnet wouldn't provide you with much privacy if you intend on interacting with the subs, and not just lurking. 

![](joke.png)

As you will surely be able to tell by now, Reddit's current practices starkly contradict its early ideals of freedom, transparency, and open access. **So, what can you as a user do against this?**

## Any alternatives?

### Fediverse

If what you're looking for is a community with which to share a common interest, there are other available new aggregator sites that are more privacy respecting. 

You could try a self-hosted or **decentralized option, such as Lemmy or Kbin**. These are federated Reddit alternatives based on ActivityPub (same protocol used by Mastodon). Some popular Lemmy instances include **[lemmy.ml](https://lemmy.ml)** and **[sh.itjust.works](https://sh.itjust.works)**

![](lemmy.png)

**These platforms gained popularity after Reddit's 2023 API changes**, but as they are completely separate platforms from Reddit, **they don't host the same content as Reddit.**

### Dread

If you're interested in delving into a darknet alternative, Dread is your best bet. It is the most popular darknet service, and according to their [website](https://dreadytognbh7m5nlmqsogzzlxjy75iuxkulewbhxcorupbqahact2yd.onion), has millions of visitors each month.

**Dread is a dark web forum that serves as a platform for users to discuss various topics**, primarily focusing on darknet marketplaces and related subjects. It was created by Hugbunter, a well known security expert and penetration tester as **a replacement for the infamous Reddit darknet markets subs, which were banned in 2018.**

![](dread.png)

### Alternative Frontends

**If what you're looking for is accessing Reddit's existing (and vast) communities**, then your best bet might be **setting up a RedLib frontend**. You can find out how to do it in [this article.](../redlibsetup/index.md)

And so, as Reddit is no longer the free-speech, hacker-friendly space it once was, and **it has fully embraced the surveillance economy, censorship, and data monetization**, the best thing you can do is stop accessing their platform from the clearnet site and its apps. 

Try one of these alternatives, and it might surprise you that **you'll probably prefer it to Reddit's convoluted, ad and tracker filled sites.**

![](redlib.png)

## Conclusion

Although Reddit started of as a privacy-first and free speech platform, **in recent years the platform has completely moved away from their initial goals**, and has become a profit hungry, data collecting Big Tech site.

There's no denying it's great amount of popularity and useful information that can be accesed, and so **you might want to have some access to this content without compromising your privacy. This is where private frontends such as RedLib have their place in the spotlight.**

But it's worth remembering that **Reddit's most useful content is completely user-generated. And thus, there is a possibility of generating that content elsewhere**, and enriching a more privacy respecting platform, such as Dread or Fediverse's Lemmy and Kbin. 

Whichever option you end up going for, **you are now ready to stop accessing reddit.com** and giving away your privacy in the process.
