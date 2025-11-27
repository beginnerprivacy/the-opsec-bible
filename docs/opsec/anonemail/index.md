---
author: loki_opsec_inc
date: 2025-08-21
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/26"
xmr: 8AaLSmixWFJhgMmrBvqi6827v27YYT6H8C6SjUasHySBKna2JDk1dtEf2ZAUpXue64JDEBxkTL9oZGaoKtcWppWKHLSkTLM
tags:
  - Clientside Anonymity
---
# How to Get an Email Account Anonymously (Emails as a Service)

```
TLDR: you can create and use email accounts anonymously by only using Tor
```

![](../context/anon.png)

## Introduction

Email is one of the most widely used forms of online communication, both for personal and professional interactions. With billions sent daily, you would expect email to be secure, accessible, and readable by only the intended recipient. Unfortunately, email is an old technology, and this is not always the case. With metadata being visible, large email providers scanning emails, as well as potential government surveillance in some parts of the world, it is no surprise that email is hardly considered private. As such, you may want to send an email that is not tied to your real identity. In this article, we will explore how to sign up for an email account anonymously. Specifically, we will explore a freedom-focused email provider, **Cock.li**, and how to sign up using Tor without inputting any additional information whatsoever. 

## Setup

Cock.li does not work when registering over [their onion](http://rurcblzhmdk22kttfkel2zduhyu3r6to7knyc7wiorzrx5gw4c3lftad.onion/), but we can still register through their clearnet site in the Tor Browser.

Go to their main page in Tor Browser and click on Register:

![](./cock-mainpage.png)

Choose your name and a randomized password (put it in your [password manager](../passwordmanagement/index.md)), then click _Register_:

![](./cock-register-form.png)

You should get a success message. You need to click the link to unblock your account:

![](./cock-register-success.png)

You have to solve a Proof-of-Work captcha to get your mail unblocked. It will take several minutes. Javascript needs to be turned on in Tor Browser. Click Start, then once "Running" turns to "Complete", click Unblock.

![](./cock-pow-running.png)

Success message:

![](./cock-pow-success.png)

Cock.li does not currently offer a webmail client as of the writing of this post. Primarily since that client was [hacked at one point](../mail-problem/index.md#hacks-forcing-them-to-remove-the-roundcube-service). So we can use a mail client like [Thunderbird](https://www.thunderbird.net).

After installation, we can open it and immediately configure Thunderbird to use our Tor proxy. Select the menu icon, click on Settings and search for "proxy", then click the result that comes up:

![](./thunder-proxy1.png)

Manually configure the proxy to use our local Socks5 Tor Proxy, and click OK:

![](./thunder-proxy2.png)

Thunderbird should've popped up an "Account Setup" tab when you first opened it. Fill in any name you want, your cockli email address, and the password for it, then click "Configure Manually":

![](./act-setup1.png)

Now fill out the below information, then click Re-test, and a green message box should pop up. When it does, click Done.

![](./act-setup2.png)

Keep in mind, IMAP and POP3 are both protocols used to access email, but they work differently. IMAP allows you to access and manage your emails from multiple devices while keeping them stored on the server, whereas POP3 downloads emails to a single device and typically removes them from the server, making them inaccessible from other devices. So pick which protocol you want based on that.

Success message:

![](./act-setup3.png)

Now it's time to test our new email. We're going to send an email from our new email account to a disposable email address.

In your favorite search engine, just type in "10 minute temp mail" or something similar, or you can go to [this service](https://tempmail.plus/).

Copy the address it gives you. Then go to Thunderbird and compose a new message and make the recipient to be the new temp email address. Write a little message and send it off:

![](./send-testmail-1.png)

Wait a minute and you should see the message on the temp mail service:

![](./send-testmail-2.png)

## Additional Option: Onion-only Email Signup using Morke

Morke is an email service that is quick and easy to sign up for and use, using only an onion-based website. Perfect for easy anonymous use. However of course, don't trust the provider if the contents are sensitive.

You can find Morke's onion by going to one of their clearnet domains, `morke.ru` or `morke.org`, or you can access it directly [here](http://6n5nbusxgyw46juqo3nt5v4zuivdbc7mzm74wlhg7arggetaui4yp4id.onion)

![](./morke-clearnet-site.png)
![](./morke-onion-site.png)

Either way, click Register and in the next screen, put in a user ID, password, and the captcha. Keep in mind, the fields have some constraints too:
- User ID must be lowercase alphanumeric, 3-20 letters.
- Password must be alphanumeric, 8-40 letters.

Once you signup you'll get a success message, then you can login.

![](./morke-signup-form.png)
![](./morke-singup-success.png)
![](./morke-login.png)

After you login you'll get the webmail interface. Congrats, you're done! Super Easy.

![](./morke-webmail.png)

## Conclusion

And your new anonymous email accounts are ready for use! In line with practicing good [OPSEC](../opsec4levels/index.md), these accounts are for use exclusively over the Tor network for activities unrelated to your real identity.

Learn more about our perspective on email [**here**](../mail-problem/index.md)
