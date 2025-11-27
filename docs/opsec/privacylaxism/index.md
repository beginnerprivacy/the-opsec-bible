---
author: Crabmeat
date: 2025-09-24
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/469"
xmr: 89aWkJ8yabjWTDYcHYhS3ZCrNZiwurptzRZsEpuBLFpJgUfAK2aj74CPDSNZDRnRqeKNGTgrsi9LwGJiaQBQP4Yg5YtJw2U 
---

# Privacy Laxism is real and it's part of the problem

```
TLDR: 
- Step 1: install a FOSS Host OS (grapheneOS, Linux), 
- Step 2: ONLY install FOSS apps (Tor Browser, Mullvad Browser, Thunderbird, etc)

If you skip steps, you are a privacy laxist. Man up and tell your audience to do step 1 before telling them to do step 2.
```

## Introduction

When it comes to privacy, laxism is the worst enemy. Privacy requires your full attention and deserves every effort you can put into it. Yet sometimes, even people who claim to sell or promote privacy show laxist behaviors that can have serious negative consequences. As you already know, your privacy is valuable, and corporations, states, and even individuals are constantly trying to undermine it for commercial gain or control. Achieving privacy is like waging war against multiple enemies, and you can't afford to add laxism to the list, as it's already a difficult battle. Today, we'll talk about privacy laxism and its impacts.

![](lazy.png)

## Why Privacy is important? 

There's a detailed blog [post](../privacy/index.md) on our site that covers this topic in depth, but I'd like to give you a quick summary. Privacy essentially means not being under surveillance. In other words, it's the ability to act freely without sharing your actions with any other group or individual.

This is an important concept because privacy is directly linked to [freedom](https://web.archive.org/web/20250620082601/https://teachprivacy.com/alan-westin-privacy-and-freedom/). If you can't act without someone watching you, you can't truly act freely. Imagine that every time you decide to watch a TV show, someone is immediately alerted and asks whether it wouldn't be better for you to work on a specific project instead. Wouldn't that be a nightmare? That's exactly why privacy matters.

![](bigbrother.png)

## What means to be Privacy Laxist? 


### Doing Half the work

Being privacy laxist means you're doing only half the work. Someone who promotes privacy or tries to achieve it but only sets up surface-level measures without addressing the deeper, foundational ones is a privacy laxist. Here's a quick example:

You want to communicate privately and decide to use [SimpleX](../privatesimplex/index.md). Good choice, that's your surface measure. **But then you use it on a windows-powered computer, which voids your attempt at achieving privacy.** Windows is the tool that microsoft (and by extension, the US government) uses to spy on almost everyone on the world. That's being lazy. Windows is not private at all, so using SimpleX on it is useless. To truly maintain privacy, you should be using a [Linux](../linuxbasics/index.md)-powered computer. That's your root measure.

![](linuxvswindows.png)

Here's the point: **You cannot achieve privacy if you're using closed-source software.** If the software you use is closed-source, it means that you can't know if that software is spying on you or not. No matter how many FOSS software you use, they'll never compensate for a non-privacy-oriented software.

If you're a Windows user, you are being spied on by microsoft. If you're a MacOS user, you are being spied on by apple. And guess what about ChromeOS users? It's exactly the same.

It's the same with web browsers. If you decide to pursue privacy but are still using Safari, Chrome, or any other corporate, closed-source browser, you are not serious about achieving privacy. Use a FOSS web browser instead, like [Mullvad Browser](https://mullvad.net/en/browser) instead. Simple as that.

![alt text](image.png)

### Trusting Corporations

Some people rely on [corporations](../closedsource/index.md) when choosing software. Because some corporations have strong public reputations, like Microsoft, which is widely used in professional environments, Apple, known for its innovative image, or Google, the "cool kid" on the block. Many believe they can trust these companies when it comes to their privacy. **No you can't.**

Corporations are always financially driven, their primary goal is to make money. **Collecting and selling [YOUR data](https://web.archive.org/web/20250505120647/https://www.under30ceo.com/25-companies-selling-your-personal-data/) is part of their business model.** They are more than willing to collaborate with any government if it means getting tax reductions or other benefits.

When you use a computer, there are multiple layers to it, but to make it simple, we have 3 main layers:
- **The Hardware** (your Desktop Computer, Your Laptop, Your Pixel Phone)
- **The Host Operating System** (Windows, MacOS, Linux, iOS, etc)
- **The Applications that you use** (Chrome, Safari, Mullvad Browser, Libreoffice)


The main problem nowadays is that these so-called """privacy influencers"""  (which we'll cover at the end of this blogpost) are unwilling to go all the way for privacy. **You'll often see that they are willing to switch some apps to their FOSS alternatives, but they'll entirely skip the Host OS replacement part.**

In Opsec, there is an order with which we do things, it's like an Alphabet, you start with A, and you end with Z. You do not start the alphabet with B, you start it with A. If you see a privacy influencer right now, and they tell you to start with using FOSS apps, before even replacing the Host OS, **then they are a privacy laxist.** They're basically telling you to start the Opsec Alphabet with B instead of A. Don't do that.

The correct way to achieve privacy is to first replace the Host Operating System, AND ONLY AFTERWARD to start replacing the apps you use within it with their FOSS counterparts. That's because you will never have privacy on any application if the Host OS itself is spying on you (like with Windows or MacOS).

![alt text](image-1.png)

You need to understand that in order to have Privacy, you need to address all layers of said device. **Privacy is BINARY, it's either 1 or 0, on all layers.** Either privacy is addressed on ALL LAYERS, and maybe it's achievable, otherwise it will remain 0, non-existant. **All it takes is to tolerate the presence of ONE closed-source software and your privacy is ruined, whether it is on the Host OS layer, or on the Application Layer.**

![](binary.png)


What you need to keep in mind is that a corporation's reputation is almost never based on privacy. In most cases, it's about how easy the product is to use or whether it's trendy.

Take Google Chrome, for example. It has a great reputation (which they themselves manipulate to their own advantage using their own search engine manipulation effect) and is widely used. People like it because it's connected to their Google account, allowing seamless integration between their computer and Android phone. But if you look closer, Chrome is nothing more than a beautiful RAM hog that will slow down any computer with limited RAM. Mozilla [Firefox](https://web.archive.org/web/20250627051043/https://www.firefox.com/en-US/compare/chrome/), which is less popular, can do the same things, but faster and most importantly, it comes with the possibility of achieving privacy. Why is Firefox less used? Because people have been led to believe that privacy is possible on closed source software. 

If you were to tell people the truth, that everything they ever did on chrome, on windows, on discord, or on whatever other closed-source software, no matter how intimate their actions were supposed to be, **everything they did using said software has been permanently recorded and stored on a datacenter** for corporations, companies and law enforcement to sell and browse through whenever they want, i'm sure they would want to have privacy.

You wouldn't accept me to put a CCTV camera in your bedroom, wouldn't you ?

![](chrome.png)

And yet here we are, Chrome is still the most used web browser in the world. The culprit is not that people don't care about privacy, **the real problem is that they are still uneducated, unaware that their privacy is non-existant on those mass-surveillance tools.**

### Being afraid of the learning curve

Some people take shortcuts when setting up their privacy because they lack the technical knowledge to go deeper. That's a huge mistake. Technical knowledge is like any other skill, it can be [acquired](https://web.archive.org/web/20250401044510/https://www.wikihow.com/Acquire-New-Skills). Even if it takes time, even if it looks complicated, there are countless tutorials online to help you learn. That's the core purpose of our blog: what seemed complex at first has become simple thanks to our well-written guides, we're here to bring you up to speed on why it's important, the what the correct tool to use is, and how to actually use them.

If you refuse to learn a new tool because it looks difficult, or because it takes time, or for any other excuse, it means that you're not serious about OPSEC. **You will never get privacy by playing make-believe, The only way to get privacy is by actually doing what's necessary to get it**, even if it means replacing windows with Linux, even if it means replacing chrome with Firefox, AND THAT'S NORMAL.

![](learningcurve.png)

Think Linux looks complicated? It's not. It's just another operating system that works differently, You just need to get used to it with a little bit of practice. In fact, once you're familiar with it, [Linux](../linuxbasics/index.md) is far easier to use than most others. It's designed to do exactly what you want. It works out of the box and everything within it can be customized.

Try, fail, learn, repeat... And succeed. That's the [only](https://web.archive.org/web/20250526134028/https://thelearningquest.org/blog/the-power-of-iterations-learning-failing-and-succeeding) way. And remember, it's the exact same process you went through when you learned to speak, walk, swim, or ride a bike. That's how you learn the basics of anything worth mastering.

It's completely normal for learning something new to take time. However, with the proper well-written guide, like the ones we're trying to bring forward with the OPSEC bible, **you'll go from 0 to 1 much faster than if you had to learn how to use those tools by yourself.** We're here to do the work and document it along the way, for you. All it takes is to be willing to put a little effort to follow the tutorials we write from start to finish. Everyone can do it. We've all been total noobs aswell when we first started learning OPSEC, you're not alone.

![](try.png)

People are often too comfortable in their habits and too attached to the familiar, even if those habits are [dangerous](https://www.nhnscr.org/blog/why-comfort-zone-is-dangerous-the-truth-behind-staying-comfortable/) in the long run. It's like how people keep using harmful substances because it's easier or more comfortable, but in the end, that comfort can be deadly.

When it comes to privacy, sticking to what you know, like Windows, Chrome, or other corporate tools, might seem easy, but you've been poisoing yourself without realizing it. So, when you finally realize that closed-source software has been poison all along, **you do what needs to be done to purge the poison out of your system to restore your privacy**. You replace it with FOSS software instead, and you put the time it takes to learn how to use it and to get used to it, **AND THAT IS ABSOLUTELY NORMAL**... The truth is, the tools that seem convenient and familiar are the ones that compromise your security, collect your data, and make you vulnerable to surveillance.

The change isn't easy, but just like with any habit, it's about [breaking](https://positivepsychology.com/comfort-zone/) free from the comfort zone, educating yourself, and learning the right way to protect yourself. It's tough at first, but in the end, it's worth it because your privacy is your freedom. And in today's world, it's worth fighting for.

![](zone.png)

**Yes it takes a little bit of effort to achieve privacy, and we try to simplify it as much as possible on the opsec bible. But we won't ever lie to our audience like all of the privacy laxists out there, which are all claiming that privacy is possible on closed-source Host OSes.**

## Why is privacy laxism dangerous ?

Privacy laxism can be dangerous in more ways than one. First, it can put you directly at risk. For example, if you're browsing the internet for activities considered illegal in your country, you could face legal [consequences](../becominganinformant/index.md) that could have been avoided by taking privacy seriously. I'm not encouraging anyone to do illegal things, but I'm also not here to police your choices. What I will say is this: if you want to stay safe, don't be laxist about privacy.

Using a [VPN](../vpn/index.md) to “hide” your activity on Google Chrome while logged into your Google account is just as risky as browsing without a VPN at all. Running Linux for "security" while buying illegal items on Snapchat is equally pointless when it comes to privacy.

Do you see the pattern? If you rely on even one easily trackable service while using privacy-focused tools, the weak link cancels out all your other protections. Privacy is only as strong as its weakest point.

![](weak.png)

Secondly, being privacy-laxist means you're feeding the parasite. In simple terms, it's accepting that you're handing your data over to the government, and in doing so, you're giving more power to the very system you should be resisting. The state is the [enemy](../stateistheenemy/index.md), and feeding your enemy is never a winning strategy. You must be extremely picky when it comes to privacy, because every state already has the tools, resources, and authority to track your every move if you let them.

Do you really want the state to know [everything](https://web.archive.org/web/20230413054730/https://www.sciencedirect.com/science/article/pii/S0308596123000538) you do online? To see your activities, read your conversations, and trace your location? I doubt it. Just like you wouldn't install surveillance cameras in your home and stream the footage online for anyone to watch, you shouldn't be lax when it comes to your privacy.

![](patriot.png)

One last thing: the false sense of privacy can actually push you into dangerous behavior. When you think you're secured, you're more likely to act recklessly, and that's when the consequences hit. Look at mainstream social networks. Many people believe they're anonymous there, but they're not. That illusion makes them more aggressive online, quicker to spread content or opinions that are considered illegal in their country. The result? Some end up facing [legal](https://www.utahdivorcenow.com/blog/2025/january/can-a-social-media-post-get-you-arrested-how-onl/) trouble for things like insulting or threatening political figures. That's exactly the kind of outcome you want to avoid, and it all starts with not fooling yourself about your level of privacy.

So, if you realize that your setup didn't permit you to achieve privacy up until now, that's good, that's progress. You are now aware of the problem, however this does not mean that it's time to give up and accept that you're the product, It means that it's now time for you to grow a fucking spine and to finally start doing what it takes to actually get privacy.

## Privacy Laxist Influencers

 Some of these influencers will evolve and become more knowledgeable over time, while others may not. While i want to emphasize that Mistakes happen, we're all wrong at some point, so even though we're not going to hold our breath to point the finger at the current ocean of bullshit OPSEC advice and who the culprits are, **keep in mind that we should judge these influencers on how they react to that criticism**. 
 
 If they acknowledge their mistakes and work towards improvement for themselves and for their own communities, rest assured that we'll mention it below, we'll give credit where it's due. 
 
 However if our criticism is negatively recieved, we'll leave it as it currently is below, as a permanent black stain on their reputation. We don't care.

If you notice that an influencer is being lax in their advice on privacy by not going into enough detail, don't hesitate to [reach](../anonemail/index.md) out to them if possible. If they are honest and truly committed to privacy, they should be open to correcting their mistakes quickly, that is, if they made said video for their audience to achieve privacy, rather than for their own profit.

Keep in mind that the [Dunning-Kruger](https://en.wikipedia.org/wiki/Dunning%E2%80%93Kruger_effect) effect is real, and it can contribute to this kind of behavior. When people overestimate their understanding or abilities, especially in complex areas like privacy, they might make decisions that seem confident but lack depth. This is why it's so important to stay humble and keep learning.

![](../whytheblog/8.png)

When you first discover the rabbithole of OPSEC and privacy, you'll get the same realization that everyone has at one point in their life: privacy is harder to achieve than expected, there are layers to your computer, and it requires you to address **ALL** layers on your computer (layers which are: the host OS, and the software running within it) to be able to properly achieve privacy. But as we have found out, some influencers online still decide to intentionally mislead their audience into a false sense of privacy, out of either incompetence, greed, or straight up malice.

### Why are they laxists ?

![alt text](image-2.png)

Some Privacy influencers are showing laxist behaviours, that can lead their communities to serious problems. But, why are they laxists? These are numerous reasons for that and we will explore it here. 

#### They are lazy

First of all, some of them are simply lazy. When it comes to explaining how to browse the internet privately, it's much easier to focus on one or two flashy tools instead of covering the full process. Recommending "just use Tor Browser and a VPN" is shorter and looks easier than explaining why you should start with Linux and how to properly install and configure it. But this shortcut shows they don't want to put real effort into their content, and if that's the case, maybe they're not doing it for the right reasons.

Here's an example:

In this video, Techlore is showcasing 10 privacy tools he can't live without: 

![](techlore.png)

In this video, the influencer discusses various privacy tools like MFA, Yubikey, password managers, privacy screen protectors, and VPNs. These are all useful tools and can be part of a solid privacy strategy. But here's the issue: when showcasing the Yubikey, Techlore uses it on a MacBook: 

![](mac.png)
![](macII.png)

There's a major issue here. We already know that you can't have privacy while using [MacOS](https://linuxstans.com/privacy-macos-vs-linux/) since the Host OS is closed-source. Yet, by showing this, the influencer is leading their audience a false sense of operational security, **implying they can have privacy without switching to a FOSS Host OS like Linux.** Like we've explained above, this is like trying to start the OPSEC Alphabet with B instead of A. Setting up a Linux machine should have been the obvious first step they should've told their community to do. But no. They went ahead and decided it was a good idea to talk about privacy on a closed-source Host OS, where privacy is impossible to achieve in the first place. 

Look, when you're making a 12 minute video to cover 10 different tools, and you've already got a minute locked down for the sponsor, there's not much time left to talk about Linux.

However this is not stopping there, Techlore is also intentionally misleading his audience into a false sense of privacy by pretending that his guides could allegedly allow people to achieve privacy on MacOS or Windows:

![](bullshitI.png)
![](bullshitII.png)

I think that this is malicious intent. A privacy influencer of his caliber (who's been actively recommending people to use Monero, to his credit), has to be technologically-literate enough to know that the software being FOSS is a fundamental requirement to achieving privacy. Yet he is pretending as if privacy was possible to achieve on Windows and MacOS, despite being obviously aware that it's not possible in the first place. 

This is despicable behavior. Because of those 2 videos, his audience has being led into a false sense of privacy, by playing make-believe privacy, pretending that removing some software that's installed by default on windows/macos is supposedly enough for restoring privacy, while you'll never have a sure way of making sure, with 100% certainty that all spying mechanisms have been removed because you don't even have access to the source code in the first place. 

If i were to guess the reason why he made those 2 videos, it's quite obvious: either it is to amass as many views as possible (and thus, making money out of ad revenue) out of greed, or it is actually malicious intent to lead people into getting busted for law enforcement. **In any case, if I were him i'd immediately remove those 2 videos, and make a follow-up video to apologize and explain to the audience what we just explained in the above sections.**

**The Opsec Alphabet starts with A, not B.** The letter A in the Alphabet of Opsec dictates that **The Host OS needs to be replaced first**. Windows and MacOS must be replaced with a [Linux Host OS](../linux/index.md), and Stock android/iOS must be replaced with [GrapheneOS](../graphene/index.md). AND ONLY THEN, privacy is possible to achieve on the application layer, not otherwise.

Another example of what could be considered as laziness is this video from Shadow Atlas: 

![](shadowatlas.png)

From 9:21 to 10:12, this influencer mentions our blog, suggesting that even if we are giving good advices, you don't need to follow our tutorials unless you're El Chapo. He also claims that using a VPN, Monero, and decentralized exchanges is enough to stay private. 

![](shadowatlasII.png)

While I won't get into a full argument about that, I'll point you to this [article](../financescausedownfall/index.md) and this [one](../everyoneisacriminal/index.md), which offer a different perspective. If you read this articles, you must understand that being laxist will not be a good choice. 

I get the El Chapo comparison, but what I'm trying to say is that while you know where you start, you can't always predict where things will go. There's no guarantee you won't find yourself in a situation down the line where total privacy becomes essential. 

**That's why aiming for full privacy from the start is NOT overkill, it is simply, what it takes to actually get privacy, either you get it, or you don't, on all layers.** Yes it takes time, more time than most people are willing to take for privacy, but that's how it is, that's normal.

#### Influencers use Privacy for their own profit

Money is a powerful motivator, and sadly, some influencers let it override honesty. Instead of truly guiding people toward privacy, they promote tools or methods that serve sponsors rather than the community. In these cases, privacy shortcuts are not just mistakes, they're deliberate compromises made for profit.

Here's an example with a Think Security video:

![](thinksecurity.png)

Take a look at this video titled "*Online Privacy & Security 101 | Protect Your Identity: Essential Tools for 2025.*"

It promises to cover essential tools that will help you maintain your privacy online. But here's the problem: when you click on it, you're expecting a variety of tools that will genuinely help protect your privacy. Instead, what you get is a 7-minute ad for just one tool.

![](thinksecurityII.png)

The title of the video is misleading. It promises a broad range of privacy tools, but what it actually showcases is a single tool designed to erase your online fingerprint. Here's the thing: the goal of true privacy isn't about erasing your fingerprint. It's about not leaving one in the first place. The idea that you can just erase your online presence is a myth. Once something is on the internet, it's there forever.

Here is another example with a All Things Secured video: 

![](allthingssecured.png)

In this video, the influencer offers guidance on improving your privacy on your iPhone. Yes, your iPhone, from Apple, the same company behind macOS. Once again, there's no true privacy with Apple products. However, if you take a closer look, you'll see that the video is sponsored by a cloud encryption solution. Offering privacy on a platform where it's practically impossible to achieve is simply a way to generate revenue.

![](allthingssecuredII.png)

Given what this influencer is promoting, it's no surprise that videos like this appear, claiming that privacy is impossible to achieve when, in reality, it just requires some effort and the right approach. (And if you were wondering, yes it is sponsored again)

![](allthingssecuredIII.png)
![](allthingssecuredIV.png)

This cringe defeatist mentality that supposedly it is normal to "give up" because "privacy is too hard to achieve" IS part of the problem, while he should've manned up and told his community that he was wrong, and to tell them to install GrapheneOS instead of using iphones, he instead chose to remain the product, AND he even went as far as telling his audience that they should also give up like he did. Despicable behavior.

**Grow a fucking spine. Tell your audience to use the correct tools, Show them how to use those tools, no matter how much effort it takes. Stop being part of the problem and start being part of the solution.**

> Update: 24th September 2025
> 
> All Things Secured recently did a long [video interview](https://www.youtube.com/watch?v=XkKxYI4osOs) with another creator (Side of Burritos) discussing Graphene OS and presenting it live to the public.
> 
> ![](allthingssecuredV.png)
>
> In another [video](https://www.youtube.com/watch?v=KsTxYhsiQvY), he also explained his reasons behind switching from iOS to much better [GrapheneOS](../graphene/index.md).
> 
> This is clearly a step in the right direction that deserves to be noticed.

#### They are not competent 

Another reason why influencers can be privacy laxist is that some simply aren't competent enough to speak on the topic. They know it's an area that attracts interest, so they decide to dive in and talk about it. But in reality, they don't fully understand the subject themselves.

Take this example from a CyberCPU Tech video:

![](cybercputech.png)

This video promise you to make Microsoft stop spying on you when using [Windows](../closedsource/index.md). How is that even possible when the software is closed-source and only displays what Microsoft decides to show? It's not. And that's the fundamental point this influencer is missing.

We can see the same issue with this video of Surfshark Academy: 

![](surfshark.png)

Or even with this video of Faculty of Apps who is offering privacy on a Meta powered app: 

![](facultyofapps.png)

Just like with Windows, some influencers are suggesting privacy solutions within the MacOS settings. But that's not possible, and it should never be promoted as such. If you want real privacy, you need to turn to privacy-focused operating systems like [Tails](../tailsqemuvm/index.md).

Take a look at the first two videos that pop up when you search for “MacOS privacy” on YouTube: one by Techlore, and the other by Naomi Brockwell: 

![](double.png)

#### They are not honest

Some influencers show a significant lack of honesty. Many of them are statist and will spread the government's narrative, ignoring the fact that privacy is, above all, about protecting yourself from the government.

Take, for example, this video by EEVBlog, where he's promoting government advice on privacy: 

![](eevblog.png)

I agree that using a VPN is a good first step. However, it's far from enough, and that's exactly why governments are recommending it, without offering any further guidance. It's a way to make people feel like they're doing enough while missing the bigger picture.

Another example, and this one is a tough one, is the following video from Fix369:

![](fix.png)
![](fixII.png)

How is it possible, in 2024 (when the video was released), to talk about privacy while using a Meta-powered app? Everyone knows that Meta sells your [data](https://edition.cnn.com/2024/02/29/tech/meta-data-processing-europe-gdpr) and heavily collaborates with governments. This can't be a lack of knowledge or competence, it can only be a lack of honesty.

### Famous examples

Here are some examples of products that were heavily promoted by influencers, only to later be revealed as dangerous. The goal of this section is to highlight how influencer laxism can affect their community, regardless of the reasons behind their lack of due diligence.

Several tech influencers, including TechCrunch and TechRadar, promoted [F-Secure](https://uk.pcmag.com/migrated-1036-vpn/40844/f-secure-freedome-vpn) Freedom VPN as a secure and reliable option. However, in 2020, reports revealed that F-Secure had misled users about its VPN's logging policy, and several security vulnerabilities were discovered, including DNS leaks. This raised concerns that the service was not providing the level of protection it had promised.

![](fsecure.png)

Influencers such as Unbox Therapy and Marques Brownlee promoted Huawei phones, specifically the Huawei P30, as a worthy alternative to Samsung and Apple, highlighting their cutting-edge technology at lower prices. Later, it was uncovered that Huawei had close [ties](https://www.npr.org/2018/12/07/674467994/huawei-and-the-chinese-government) to the Chinese government, raising fears that the devices could be used for state surveillance. Experts warned that these phones could potentially be exploited for spying on users.

![](huawei.png)

Popular tech influencers like Linus Tech Tips and Unbox Therapy endorsed the Ring Doorbell (an Amazon smart doorbell) as an essential and user-friendly home security device. Marketed as a reliable solution for home protection, it was later revealed that Ring had significant [security](https://www.bbc.co.uk/programmes/articles/4qdyGR9Gbd2dlPqL4JqPXTc/security-flaw-in-amazon-s-ring-doorbells-exposed) flaws, including weak encryption protocols, which left users vulnerable to hacking. Reports of unauthorized access to user accounts surfaced, and in 2019, a hacker gained control of Ring cameras, using them to spy on users, including children.

![](doorbell.png)

## The "Privacy" Guides

In addition to influencers providing "privacy" guides through videos, there are numerous websites that claim to help people achieve privacy through guides, yet exhibit privacy laxism. Here are a few examples:

[Here](https://www.privacytools.io/), PrivacyTools.io is presenting their choice for the "Best Privacy Software & Services in 2025 - Top 11 Picks." If you look closely at these tools, you'll notice that they have selected StartMail as one of their recommendations.

![](startmail.png)

As ProtonMail gradually shifts towards becoming a KYC (Know Your Customer) product, it's easy to feel relieved to have a new option in StartMail. But there's a catch. If you visit StartMail's [website](https://www.startmail.com/whitepaper/#35-open-source-vs-closed-source-software) and take a closer look, you'll see that most of the code is closed-source, with the open-source components being limited to infrastructure-related code only. So, you basically can't know what they are tracking or not. 

![](startmailII.png)

[Here](https://www.cloudwards.net/online-privacy-guide/), cloudwards.net provides "The 10 Best Online Privacy Tips", which could be useful for those looking to improve their privacy. Here's a summary of these tips:

![](cloudwards.png)

I decided to take a closer look at two sections, as they are often the most lax when it comes to privacy advice: the OS and the VPN. Since they don't even mention the OS, which should be a basic part of these kinds of lists, let's focus on the "Update your software and devices regularly to fix any security weaknesses" section, which should at least cover it.

![](cloudwardsII.png)

There's not a word about the OS. Not a single line explaining that for privacy, you should be using Linux, not just any other OS. The advice on updating software is good, of course, but why not mention something about Linux? The way this section is presented, people could think that any OS is fine for privacy as long as it's updated. But as we know, that's not the case.

Now, let's take a look at the VPN section. Which VPN does this website recommend?

![](cloudwardsIII.png)

Yes, they recommend NordVPN, which isn't even a good VPN. Mainstream VPNs like this don't do the privacy job properly because there's no proof that they don't log your activity, and it's widely known that they collaborate with authorities. Keep in mind that NordVPN is only well-known because they've spent a lot on sponsoring YouTubers.

If you're curious and click on the "Best VPN for Privacy" they're recommending, you'll be redirected to this list.

![](cloudwardsIV.png)

Of course, not a single mention of [Mullvad](../vpn/index.md) VPN, which is actually one of the best choices when it comes to privacy. And just to be clear, I'm not even paid to say that.

What I'm saying here isn't anything new. Just take a look at this [article](../closedsource/index.md) written over a year ago, and you'll see that the issue of privacy laxism in privacy guides is something that hasn't changed.

## Why are closed source software a big mistake 

As we've discussed earlier, much of the privacy laxism comes from people trying to achieve privacy using closed-source or corporate software. This is a major issue we constantly [emphasize](../closedsource/index.md). Open source is the only real path to achieving decent online privacy.

Let me break this down with a simple question: How can you be absolutely sure that a piece of software is helping you maintain your privacy if you have no way of knowing exactly what it's doing? You can't. It's impossible. It's like trying to ensure your neighbor isn't involved in illegal activities while having no insight into what they're actually doing.

![](compare.png)

Most closed-source software is developed by statist corporations that actively [oppose](../corporationscancerfoss/index.md) open-source alternatives, and there's a reason for that. Their main goal is to maintain control over the population and suppress freedom online. These corporations are maximizing their profits while ensuring government support. You can't rely on state-promoted software to hide from the state, it's pure logic.

These software create what we call a "Privacy Illusion". You might feel free, browsing the internet anonymously, but in reality, you're still under constant surveillance, often by the state itself or by corporations working hand-in-hand with them. The tools you're using might look secure, but they're still part of the system designed to track and control you, all while giving you the false sense of privacy.

![](illusion.png)

It's like putting a blindfold on and thinking you're invisible, while the reality is that you're being watched the entire time. The illusion of freedom is just that, an illusion.

## Admit that you were wrong 

Admitting you were wrong, especially when it comes to something as critical as privacy, requires humility, and not many people are comfortable with that. It's tied to [ego](../../productivity/nihilism-intro/index.md), fear of failure, and, to be honest, the discomfort of facing the truth. People get attached to their habits and tools, and admitting they've been misinformed or lax about their privacy can feel like a personal failure. But in the world of online privacy, that's a dangerous thing to avoid.

When you don't admit to your mistakes, whether it's using insecure software, giving too much personal info away, or trusting the wrong tools, you're essentially burying your head in the sand. It's like thinking you're in control of your data while you're actually handing it over to someone else without realizing it.

![](admit.png)

For some, the fear of being wrong outweighs the potential consequences, until it's too late. That's when things like data leaks, government surveillance, or even legal issues can come into play. It's hard to face, but the sooner you [accept](../../productivity/nihilism/index.md) that you might have made mistakes, the sooner you can correct them before the damage is done. It's about being open to growth and willing to admit when you've been misinformed or lax.

Being aware and adjusting your approach could literally be the difference between maintaining your privacy or losing it entirely. And if you wait too long to change, that "comfort" could come at a much higher cost than you ever imagined.

Some people also struggle to admit they were wrong because they're heavily influenced by individuals they view as near-untouchable. This is a common issue today, given the immense power influencers hold over their communities. It diminishes critical thinking and leads people to follow others' ideas blindly, without ever acknowledging when something is clearly a mistake.

![](influencers.png)

## Privacy Laxism examples

To illustrate just how dangerous privacy laxism can be, I'd like to share a few examples of people who were lax and ultimately got caught because of their actions. In this blog, we have dedicated several articles detailing common OPSEC (Operational Security) mistakes that often stem from privacy laxism. You can find these articles under the [OPSEC-Mistakes](../opsecmistakes/index.md) section.

### Chelsea Manning (2010)

Chelsea Manning, a former U.S. Army intelligence analyst, was convicted for leaking classified documents to WikiLeaks. One of the critical issues was her lax approach to personal security, using her personal accounts and easily accessible devices to transmit sensitive information.

Manning was [sentenced](https://www.aclu.org/news/free-speech/chelsea-manning-case-timeline) to 35 years in prison (later commuted by President Obama), and her personal data and actions were widely scrutinized. Her case brought attention to the risks of inadequate security and the consequences of mishandling sensitive information.

Ignoring the importance of proper data handling and personal security can have devastating consequences, especially when working with sensitive material. The investigation revealed that the data was stored on a personal macOS-powered computer, as well as on external hard drives and SD cards.

![](chelsea.png)

### Daniel Hale (2019)

Daniel Hale, a former U.S. Air Force intelligence analyst, was convicted for leaking classified information about drone warfare to a journalist. Hale, who used a standard Windows-based system to access and print classified documents, was caught after the government traced the print job back to him.

Hale's leak [exposed](https://www.npr.org/2019/05/09/721737050/u-s-charges-former-intelligence-analyst-with-leaking-classified-data-to-reporter) sensitive information about the U.S. government's drone strikes, and he was arrested in 2019. His use of a non-secure operating system (Windows) for accessing classified material allowed authorities to track his actions and catch him.

Despite being in a position of trust, Hale's use of a standard, unencrypted system like Windows, along with his failure to follow basic OPSEC protocols, led to his downfall. This highlights the importance of using secure, isolated systems and proper practices when handling sensitive data.

![](hale.png)

### Reality Winner (2017)

Reality Winner, a former NSA contractor, [leaked](https://www.npr.org/2018/08/23/641229886/reality-winner-sentenced-to-5-years-3-months-for-leaking-classified-info) a classified document about Russian interference in the 2016 U.S. elections. Winner printed the document from her work computer, which was running Windows, and then mailed it to a news organization. Though the document was highly classified, Winner's failure to maintain strong OPSEC, coupled with the security flaws in the system she used (a Windows-based machine), led to her being caught.

The government tracked Winner down by her unique printing activity on a Windows system, which allowed them to connect the document back to her.

Windows operating systems and lack of stringent controls within government agencies contributed to the security failure. Winner's failure to consider the digital footprint she was leaving on an unsecured system led to her exposure.

![](winner.png)

As you can see, these three examples show that people or organizations trying to control the population, such as the military, CIA, or government, claiming it's for our protection, are not even able to follow basic steps to protect themselves.

## Conslusion

As you can see, privacy laxism can have serious consequences and lead to major issues. Some influencers exhibit laxism and put their communities at risk for various reasons, such as lack of competence, laziness, or financial incentives. This isn't just limited to privacy, it can be found in any domain. Being lax is never a good idea when it comes to securing yourself, which is why we offer comprehensive, free resources on this blog. Don't hesitate to follow our tutorials, from the basics to the more advanced ones, to ensure you protect your freedom.

Keep in mind that there's always more to learn, and there's always something you might have missed. But if you stay humble and keep searching for ways to protect your privacy, anonymity, and deniability, you'll eventually reach your goals. It may seem difficult at first when you realize the effort it takes, but with the right, well-written guide, anyone can do it. That's what we're here for, and it's what every privacy advocate should be doing as well.
