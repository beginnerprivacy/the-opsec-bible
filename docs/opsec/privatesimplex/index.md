---
author: XMRonly
date: 2025-10-19
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/61"
xmr: 8AHNGepbz9844kfCqR4aVTCSyJvEKZhtxdyz6Qn8yhP2gLj5u541BqwXR7VTwYwMqbGc8ZGNj3RWMNQuboxnb1X4HobhSv3
tags:
    - Clientside Privacy
---
# Easy Private Chats - SimpleX

```
TLDR: you can chat privately using SimpleX, for free.
```

![](0.png)


## **Introduction**

Online communication is one of the most ubiquitous activities on all of the internet. From newsletters, corporate emails and even down to instant messaging with friends, its spread cannot be denied. With such wide reach, it would seem very important to protect these communication channels, yet this is almost an after-thought for most mainstream messengers. Platforms with millions of users market their services with the latest buzz words yet close-source their protocols leaving users with a "trust me bro". With so many options to choose from how can we best decide which app to use? In this article we'll compare a few options (Telegram, Signal and SimpleX) to see how their technical details stack up and determine which is best for easy private chats. 



## **Overview of Telegram, Signal and SimpleX**

Telegram is a very popular messaging app that boasts close to [1 billion](https://www.statista.com/statistics/258749/most-popular-global-mobile-messenger-apps/) active users worldwide. With support for massive chatrooms, Telegram is almost more akin to social media than to a traditional messaging app. Many companies offer news, updates, and support through their official Telegram channels making it a very convenient place for users to stay up to date with various interests. Due to its strong stance on free speech, Telegram built a reputation for not cooperating with law enforcement investigations. However, after the arrest of CEO Pavel Durov in part relating to Telegram's refusal hand over user data in lawful orders, Telegram changed their privacy policy to say they may share user phone numbers and IP addresses and indeed have [done so](https://www.404media.co/telegram-confirms-it-gave-u-s-user-data-to-the-cops/). Telegram supports E2EE but this is not enabled by default, which is probably its most significant drawback.

![telegrams privacy policy section 8.3](988lhl.png)

[Signal](../signalnoanonymity/index.md) is a champion for user freedom and its state-of-the-art security is the foundation upon which other chat applications are built. Signal is very intuitive to use, supporting all of the usual text/image/voice/video/etc features that users expect. Unlike Telegram, Signal is E2EE by default and the only information it knows about users are their phone number and time of registration. Numerous [court orders](https://signal.org/bigbrother/) have solidified how Signal has nothing else to hand over to law enforcement. The phone number requirement for SMS verification, while concretely a drawback if not [acquired anonymously](../anonsms/index.md), is an intentional decision for Signal's target audience (normies) as everyday users can be notified if other stored contacts join Signal. 

SimpleX is a relative newcomer on the scene and has a unique angle in that there are no user identifies of any kind. As such, users can create unlimited profiles (and even hidden profiles to improve plausible deniability) and connect with others anonymously. Unlike Signal, SimpleX supports native onion routing as well as the ability to self-host servers. Because of its default E2EE, servers are not able to see message contents and self-hosted servers can be shared with others, contributing to decentralization and thus making SimpleX more resilient. SimpleX's founder, in an [interview](https://www.wired.com/story/neo-nazis-flee-telegram-encrypted-app-simplex/), implied that SimpleX sees no information about its users but since it is new, it remains to be seen how they would respond to actual court orders. SimpleX has received some criticism for its reliance on Venture Capital to establish itself while it works to develop a business model. 

A comparison from [privacyspreadsheet.com](https://privacyspreadsheet.com/messaging-apps) has a breakdown of all the technical details. 

![](1.png)

When selecting a messaging app, certain [OPSEC criteria](../anonsimplex/index.md) should be considered.
  
**Privacy:**

1. The application is free and open source (FOSS).
2. The application is end-to-end-encrypted by default (E2EE).
3. The application allows self-hosting our own servers (Decentralization).

**Anonymity:**

1. The application supports Tor servers out of the box (Onion Routing).
2. The application requires no sign-up information (Emails, Usernames, Phone Numbers).
3. The application allows joining chatrooms without revealing our identity (Incognito Mode).

**Deniability:**

1. The application allows disappearing messages (Plausible Deniability).
2. The application allows creation/deletion of multiple profiles (Plausible Deniability).
3. The application allows hidden profiles (Plausible Deniability).
  
From the above comparison, we can see that only SimpleX meets all of the criteria. While we only focus on Privacy in this article, it doesn't hurt to have the other benefits of Anonymity and Plausible Deniability. 

## **SimpleX Desktop**

![](../context/private.png)

To download Simplex Desktop, you can go on [https://simplex.chat/](https://simplex.chat)

![](6.png)

Then you can download the appimage here:

![](7.png)

And lastly once downloaded, you can simply make a shortcut with it and make sure it's executable:
    
    
    [ localhost ] [ /dev/pts/10 ] [~]
    → cd .mullvad-browser/Downloads
    
    [ localhost ] [ /dev/pts/10 ] [~/.mullvad-browser/Downloads]
    → ls
    simplex-desktop-x86_64.AppImage
    
    [ localhost ] [ /dev/pts/10 ] [~/.mullvad-browser/Downloads]
    → mv simplex-desktop-x86_64.AppImage ~/Desktop/                                                                                                                                            (1)
    [ localhost ] [ /dev/pts/10 ] [~/.mullvad-browser/Downloads]
    → sudo ln -s ~/Desktop/simplex-desktop-x86_64.AppImage /usr/bin/simplex
    
    [ localhost ] [ /dev/pts/10 ] [~/.mullvad-browser/Downloads]
    → which simplex                                                                                                                                                                          (130)
    /usr/bin/simplex
    
    [ localhost ] [ /dev/pts/10 ] [~/.mullvad-browser/Downloads]
    → simplex
    
    

And from there you'll land in the simplex chat app:

![](8.png)

![alt text](image.png)

## **SimpleX on Mobile**

![](../context/private_mobile.png)

To also showcase how to use SimpleX from mobile, we'll be installing it from [F-Droid](https://f-droid.org/packages/chat.simplex.app/). Search for the app and then click Install. Navigate through the setup process, choose a username and click Create your profile. 

![](2.png)

With your profile complete, it's time to create a private group chat. Click on the pencil icon at the bottom of the screen and select Create group. Give your group a name and click Create group. Finally, skip inviting members for now. 

![](3.png)

Click on the group name to see some options. Click on Create group link. Finally, share the group link with your friends out-of-band. 

![](4.png)

Once your friends connect, you can start messaging. 

![](5.png)

Out of the box, SimpleX works perfectly fine. However, more advanced users may wish to tweak a few settings or self-host their own servers.

if you want to setup your own private simplex server, check out this [tutorial](../privatesimplex-server/index.md)

## **Build From Source**

Now if you're a tinfoil hatter, **you may not trust the binaries being distributed by simplex, and you might want to compile it yourself, which is also possible**. This is fully covered in a [dedicated tutorial](../simplex-forking/index.md#building-the-simplex-client-appimage) on building both SimpleX client and server entirely from source code.

If, in the future, SimpleX team introduces some potentially dangerous feature, it can always be altered by [forking](../simplex-forking/index.md#forking-the-simplex-code-to-your-own-git-server) the codebase, modifying it and building it yourself.

## **Conclusion**

In this article we saw how SimpleX compares to a few other popular instant messengers and some of its unique advantages. We saw how to easily install and start using it. With that knowledge in hand, you can easily make all your chats private! 

