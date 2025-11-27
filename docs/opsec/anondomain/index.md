---
author: nihilist
date: 2024-09-05
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/110"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
tags:
  - Serverside Anonymity
---
# How to Rent Remote Domains Anonymously (Registrar Resellers)

```
TLDR: you can rent domains anonymously by accessing registrar resellers and by paying them in monero
```

![](../context/anon_remote.png)

Not many people know that it is possible to operate a clearnet website anonymously. This can be done using a [non-KYC registrar reseller](https://kycnot.me/?t=service&q=domain) that allows you to purchase a domain using Monero. It is crucial to maintain anonymity when you are purchasing the domain, and when you are using it. To do so, you'll need to at least keep Tor between you and the service, as we have explained [previously](../anonclearnetservices/index.md).

![](../anonclearnetservices/0.png)

## _OPSEC Recommendations:_

1. Hardware: (Personal Computer / Laptop)

2. Host OS: [GNU/Linux](../linux/index.md)

3. Hypervisor: [libvirtd QEMU/KVM](../hypervisorsetup/index.md)

4. Virtual Machine: [GNU/Linux](../hypervisorsetup/index.md) or [Whonix](../whonixqemuvms/index.md) or [Tails](../tailsqemuvm/index.md)

## Introduction

In this tutorial, we're going to try out [nicevps](https://nicevps.net/), and as we are operating from within a Whonix VM, we'll use their [onion mirror](https://nicevpsvzo5o6mtvvdiurhkemnv7335f74tjk42rseoj7zdnqy44mnqd.onion/). So first, we register an account there:

![](1.png)

## Ordering the domain

Then we order a domain of our choice:

![](2.png) ![](3.png) ![](4.png)

For example, we order the domain meduzzza.com for a yearly 15 euros, which we will obviously pay in Monero as we want to maintain anonymity:

![](5.png) ![](6.png)

## Domain configuration

Then, once paid, you can access your services from the dashboard:

![](7.png) ![](8.png)

From inside the control panel, you can set the Registered Glue Name Servers as follows, so your domain's primary and secondary domain name servers are the ones of your choice. I recommend having an [anonymously-acquired remote VPS](../anonymousremoteserver/index.md) with a [bind9 service](../dns/index.md) on it.

![](9.png)

## Final testing

Once set, you can check the status of the NS record propagation at [dnschecker.org](https://dnschecker.org). Be warned that the DNS propagation can take up to 48 hours to complete.

![](10.png)

Once the NS DNS record has propagated, your domain should resolve anywhere in the world:

    [ mainpc ] [ /dev/pts/10 ] [~/Nextcloud/the-opsec-bible]
    → ping ns1.yourdoma.in
    PING ns1.yourdoma.in (23.137.250.140) 56(84) bytes of data.
    64 bytes from mail.yourdoma.in (23.137.250.140): icmp_seq=1 ttl=56 time=58.9 ms
    64 bytes from mail.yourdoma.in (23.137.250.140): icmp_seq=2 ttl=56 time=55.8 ms
    64 bytes from mail.yourdoma.in (23.137.250.140): icmp_seq=3 ttl=56 time=56.3 ms

And that's it! You can now have a public website using a domain that you acquired anonymously!
