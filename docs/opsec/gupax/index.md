---
author: odysseus
date: 2025-08-14
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/104"
xmr: 83tvixnZaL5SbN8fWiPAAje4mvdZnfrJUM5H1pnbLTZmT1d6eGC1qCp7aFB7jUpt3wECm33L9quvkAVtJH4GDvYmEuoPgrr
tags:
  - Clientside Anonymity
  - Self-Hosted
  - Contributing to Anonymity
---

# How to mine Monero easily using Gupax

```
TLDR: To help validate Monero transactions and keep Monero's network decentralised, you can use easily mine XMR using Gupax
```

In this guide, we will explain how to mine Monero on the client side using [Gupax](https://gupax.io/). For instructions on server mining, please refer to [this guide](../monerop2pool/index.md).

## Why you should mine Monero

Monero, like all cryptocurrencies, relies on miners to keep the network running. However, unlike other cryptocurrencies, Monero uses [RandomX](http://monerotoruzizulg5ttgat2emf4d6fbmiea25detrmmy7erypseyteyd.onion/resources/moneropedia/randomx.html), which helps prevent the network from becoming centralized by ASICs (machines dedicated to mining). Since RandomX is optimized for CPUs, it allows anyone with a regular computer to participate in mining, promoting decentralization and making it more accessible.

Despite this, there is still the risk of a single pool controlling the majority of the hash rate and potentially launching a [51% attack](https://en.wikipedia.org/wiki/Double-spending#51%_attack). To prevent this, [P2Pool](http://monerotoruzizulg5ttgat2emf4d6fbmiea25detrmmy7erypseyteyd.onion/resources/moneropedia/p2pool.html) was created, a decentralized mining pool with no central authority or servers. By contributing to mining through P2Pool, you help reduce the risk of a 51% attack and further support network decentralization, as well as earn a little bit of Monero.

## _OPSEC Recommendations:_

  1. Hardware: (Personal Computer / Laptop / Server) with a good cpu
  2. Host OS: [GNU/Linux](../linux/index.md)
  3. A [new wallet](../monerowallet/index.md) to recive mining rewards. This wallet should only be used for mining
  4. Although not needed you can run your own [monero](../monero2024/index.md) and [p2pool](../monerop2pool/index.md) node

First, navigate to [gupax.io/downloads](https://gupax.io/downloads/) and download the Linux Bundle.

![](1.png)

Next, extract the bundle and run Gupax as follows:

    user@debian:~/Documents/$ ls
    gupax-v1.3.11-linux-x64-bundle.tar.gz
    user@debian:~/Documents/$ tar -xvzf gupax-v1.3.11-linux-x64-bundle.tar.gz
    gupax-v1.3.11-linux-x64-bundle/
    gupax-v1.3.11-linux-x64-bundle/gupax
    gupax-v1.3.11-linux-x64-bundle/Gupax.AppImage
    gupax-v1.3.11-linux-x64-bundle/xmrig/
    gupax-v1.3.11-linux-x64-bundle/xmrig/xmrig
    gupax-v1.3.11-linux-x64-bundle/xmrig/SHA256SUMS
    gupax-v1.3.11-linux-x64-bundle/xmrig/config.json
    gupax-v1.3.11-linux-x64-bundle/p2pool/
    gupax-v1.3.11-linux-x64-bundle/p2pool/README.md
    gupax-v1.3.11-linux-x64-bundle/p2pool/p2pool
    gupax-v1.3.11-linux-x64-bundle/p2pool/LICENSE
    user@debian:~/Documents/$ ls
    gupax-v1.3.11-linux-x64-bundle  gupax-v1.3.11-linux-x64-bundle.tar.gz
    user@debian:~/Documents/$ cd gupax-v1.3.11-linux-x64-bundle
    user@debian:~/Documents/gupax-v1.3.11-linux-x64-bundle/$ ls
    gupax  Gupax.AppImage  p2pool  xmrig
    user@debian:~/Documents/gupax-v1.3.11-linux-x64-bundle/$ chmod +x gupax
    user@debian:~/Documents/gupax-v1.3.11-linux-x64-bundle/$ ./gupax

Now, take the primary address of the new wallet you created (ensure it starts with a "4") that is designated solely for this purpose, and input it into Gupax.

![](2.png)

You can now connect to a remote node. However, it is recommended to run your own node. To use a remote node, click on "Ping Remote Nodes." This action pings all remote nodes to determine which connection is the fastest. Then, click on "Select Fastest Node" to select and connect to the fastest node. If you prefer to use your own local node, click on "Advanced." Finally, press the start button at the bottom.

![](3.png)

Once P2Pool is online and fully synchronized (indicated by the green color), you can navigate to the XMRig tab.

![](4.png)

On the XMRig tab, you can select the number of threads you wish to dedicate to mining Monero. After making your selection, click on "Start." To choose your own local P2Pool node, click on "Advanced."

![](5.png)

Once XMRig also appears green, you can navigate to the Status tab. There, you can view various metrics, such as your CPU performance and current hashrate.

![](6.png)

To estimate how much XMR you would earn on average, take your hashrate and visit [P2Pool's website](http://p2pool2giz2r5cpqicajwoazjcxkfujxswtk3jolfk2ubilhrkqam2id.onion/). Click on "Average Share Time Calculator" and input your hashrate. Ensure that you select the correct unit.

![](7.png)
