---
author: oxeo0
date: 2025-05-16
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/278"
xmr: 862Sp3N5Y8NByFmPVLTPrJYzwdiiVxkhQgAdt65mpYKJLdVDHyYQ8swLgnVr8D3jKphDUcWUCVK1vZv9u8cvtRJCUBFb8MQ
tags:
  - Anonymity Explained
---

# Anonymity - Why can't I use Signal to chat anonymously?

```
TLDR: you're forced to use a phone number to sign up on Signal, because of that you can't use it anonymously.
```

## Introduction

For over 10 years [Signal](https://signal.org) has been wrongfully praised for its security and privacy amongst cybersecurity experts and privacy enthusiasts.

It supports end-to-end encryption (also in groups), disappearing messages, and client app code is [fully open-source](https://github.com/signalapp).


## History, Ownership and Affiliations

Signal was initially developed as [TextSecure](https://en.wikipedia.org/wiki/TextSecure) and [RedPhone](https://en.wikipedia.org/wiki/RedPhone) by two US based security researchers - [Moxie Marlinspike](https://en.wikipedia.org/wiki/Moxie_Marlinspike) and Stuart Anderson.
Developement started around 2010 under the [Whisper Systems](https://en.wikipedia.org/wiki/Whisper_Systems) organization.
First versions of TextSecure and RedPhone apps were a part of their proprietary enterprise mobile security software.

In 2014 the second version of TextSecure was released which added end-to-end encrypted group chat and instant messaging capabilities.
At the end of the year, the plan of merging TextSecure with RedPhone was announced.
It evolved into the standalone Signal app in early 2015 and 2nd version of TextSecure became the basis for the Signal Protocol.

During this time, the partnership with WhatsApp was announced.
To this day WhatsApp uses the Signal Protocol as well.
However contrary to Signal app, WhatsApp is not open-source. It's still owned by Meta (formerly Facebook).
We have no way of knowing how much metadata WhatsApp shares with Meta (especially with recent push for [Meta AI](https://blog.whatsapp.com/talk-to-meta-ai-on-whatsapp) within the app).

In 2018, Signal gained significant momentum with a $50 million investment from WhatsApp co-founder
Brian Acton, leading to the creation of the non-profit Signal Foundation.
To this day, Signal Foundation remains a registered non-profit 501(c)(3) organization operating mostly on user donations.


## Phone number requirement

One of the most popular criticisms of Signal is that it requires users to provide their phone numbers.
In fact, early version of Signal (called [TextSecure](https://en.wikipedia.org/wiki/TextSecure)) was just a wrapper encrypting SMS messages.
This meant the app was heavily dependent on user's phone number and cell carrier.
The SMS messages were encrypted, but the [metadata](../anonymitymetadata/index.md) was still easily accessible to mobile carriers.

In 2015, Signal [started to phase-out](https://signal.org/blog/goodbye-encrypted-sms/) SMS encryption feature in favor of providing their internet connected infrastructure.
One thing that haven't changed until this day is the requirement for the phone number (which is inherently [not anonymous](../phonenumbers/index.md)).


### Costs

Signal openly states phone number verification is around 50% their [yearly spendings](https://signal.org/blog/signal-is-expensive/#registration-fees).
Despite that, they keep requirement to **prevent spam and abuse**.


### Usernames

In 2024 Signal [introduced usernames](https://signal.org/blog/phone-number-privacy-usernames/) feature.
It is meant to "keep your phone number private", but only from the people you're talking with.
Even after the introduction of usernames, users are still required to provide their phone number during registration.

This feature could've been easily implemented so that no personally identifiable information is tied to a Signal account.
Account would be just username.

In fact nowadays, there are many new secure messaging apps which don't require any personal data to create an account.
For example [Session](https://getsession.org/) generates a unique random identifier during registration while [SimpleX](https://simplex.chat) uses nicknames - both permanent and temporary ones.


## hCaptcha

Another questionable privacy related decision is the use of [hCaptcha](https://hcaptcha.com/) as an anti-abuse measure [implemented](https://github.com/signalapp/Signal-Desktop/issues/6353#issuecomment-1687388838) in Signal clients. While a bit [more private](https://betanews.com/2020/04/13/cloudflare-ditches-google-recaptcha-moves-to-hcaptcha/) than Google's reCAPTCHA, their [privacy policy](https://www.hcaptcha.com/privacy) is also not ideal.


## Centralized Infrastructure

Signal does not have their own datacenter, they rely on Google Cloud Platform, Amazon Web Services and other large cloud providers based in the US.

Server-side code is open source and can be found [here](https://github.com/signalapp/Signal-Server).
In the past users raised some concerns regarding backend code [not being updated](https://linuxreviews.org/Signal_Appears_To_Have_Abandoned_Their_AGPL-licensed_Server_Sourcecode) for over a year.

### Metadata Collection

Signal does not implement any IP address obfuscation or onion routing.
It's possible to use Signal over a VPN, but it's not a standard feature.
Some users [reported](https://www.reddit.com/r/signal/comments/144syye/endless_captcha_human_verification_while_using_vpn/) getting CAPTCHA requests when using Signal desktop app with a VPN.

Signal has a clear [transparency site](https://signal.org/bigbrother) for legal request they responded to.
There is no evidence they hand out user's IP address to law enforcement.
Assuming they're being honest with us, it would still be possible to get an IP address of customer from logs of their cloud providers.

Law enforcement could technically monitor the connections to the Signal servers and determine which user messaged another user in a given time frame. From there, it would be possible to get IP addresses and phone numbers of both messaging parties.

![hypotethical scenario of LE agents monitoring Signal's centralized infrastructure](4.png)

However for now, we have no evidence that Signal servers are being monitored by law enforcement so that scenario remains purely hypotethical.

### Not Self-Hostable

The server-side code is available on GitHub, but it's not designed for easy self-hosting. Code relies heavily on external services (like Firebase Cloud Messaging or Twilio). The list of Signal servers is hard-coded into client apps. 

There's also a lack of documentation on how to set it up. I found a [blog post](https://softwaremill.com/can-you-self-host-the-signal-server/) where someone attempted to compile their own App version and host their own Signal server. Most issues are detailed in there.

While not inherently a flaw, it's also worth noting that as of May 2025 
[several countries](https://explorer.ooni.org/search?until=2025-05-14&since=2024-05-13&test_name=signal&failure=true&only=anomalies) 
including Russia, Iran, UAE, Venezuela, Pakistan and China have successfully blocked Signal within their borders.

![diagram showing blocking Signal at firewall level by some large state](6.png)

If not for the centralized nature of the service, the blockage would have been much harder. Users could just self-host their own servers.

To give back to Signal, following the Iranian blockages in 2021 they created a solution similar to Tor bridges. Volunteers can run a TLS proxy server to [help users connect](https://signal.org/blog/run-a-proxy/) with the Signal servers and message freely even when their government blocks Signal.

### Trust

Recently [the government of Sweden demanded](https://www.infosecurity-magazine.com/news/signal-exit-sweden-government/) a backdoor into E2EE apps like Signal. The CEO refused and told the media Signal would leave Sweden if that mandate were in place.
While Signal has great track record so far, it's not hard to imagine a scenario where the company is forced to comply with some backdoor request (or shutdown).

US national security leaders have been found to use Signal to [discuss military operations](https://en.wikipedia.org/wiki/United_States_government_group_chat_leak) and other strategic topics. Signal is an US made app with all servers located physically within the US, however the app was never meant to serve such purpose. 

## What makes SimpleX Chat better?

### Anonymous Chats

SimpleX supports [anonymous chats](../chats/index.md#anonymous-chat-example) which allow users to plausibly deny their participation in a conversation by using one-time nickname for each conversation.
This reduces the risk of being linked to specific messages or conversations.

![diagram showing how simplex anonymous chats prevent chat correlation](3.png)

There's no such feature in Signal. Usernames can be changed at any time, but they change in each conversation user is a part of.

![diagram showing how signal users can be deanonymized using correlation of their chats](2.png)

### Self-Hostable and Decentralized

SimpleX Chat comes with their SMP and XFTP servers preconfigured in client apps, however it's easy to [host your own](../anonsimplex/index.md) and switch to it. All servers are federated meaning they can talk to each other.

The unofficial list of SMP and XFTP servers is available [here](https://simplex-directory.asriyan.me/#selected-servers=).

Decentralization is important since if someone wanted to monitor SimpleX infrastructure, there's no single place they could go.

![picture showing the federated smp servers and agents wondering who they should ask for data](5.png)

Ease of self-hosting comes handy when someone tries to block the default messaging servers on country-wide firewall. Signal is rather really easy to block because of their centralized infrastructure. If someone self-hosts SimpleX server on their own network within the country, it's much harder to detect and block.

![diagram showing users hosting smp servers within the network of country blocking external encrypted apps](7.png)

### Reduced Metadata

By default, SimpleX Chat implements [message padding](https://simplex.chat/docs/glossary.html#message-padding) which mitigates sidechannel attacks to some level and [one-way SMP queues](https://github.com/simplex-chat/simplexmq/blob/stable/protocol/simplex-messaging.md#simplex-queue) which prevent the client IP being leaked to destination SMP server.

SimpleX tries to keep metadata to the minimum. To learn why that's detrimental to your anonymity, check out [this](../anonymitymetadata/index.md) blog post.

### Onion Only Servers

SimpleX Chat has support for onion only servers. That way both your and SMP server's IP is never leaked. Such servers [can communicate](../anonsimplex/index.md#only-using-your-own-onion-only-simplex-server-doesnt-isolate-you) with clearnet SMP servers without any issue.

There is no client CAPTCHA mechanism that would hurt usability without exposing your IP address (like we saw in Signal).


## Conclusion

While both Signal and SimpleX Chat are good secure open-source messaging apps, for our use-case SimpleX Chat offers the best balance between security, [privacy, anonymity and deniability](../aps/index.md) and usability.

Signal on the other hand only provides security and partial privacy (you're private from your contacts if you use Usernames feature).
It is clearly focused more on usability and user-friendliness. That's what made the app so popular amongst less tech-savvy users.
