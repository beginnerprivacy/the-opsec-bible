---
author: null
date: 2024-08-25
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/104"
xmr: 46qeUbExxGSLT1pAkssG2LMBnLPsbiTNMcikp1B8PwFnShPkTRxt9c12Tcw2KaAagRTAju5j2NUYYNwCAp54zKMqBpoUZEg
tags:
  - Serverside Anonymity
  - Self-Hosted
  - Contributing to Anonymity
---
# Mine Monero with p2pool and xmrig

```
TLDR: you can setup XMRIG to mine Monero, and p2pool to ensure monero's mining remains decentralised.
```

![](0.png) Figure 4.7 from [Mastering Monero](https://masteringmonero.com/)



## **Introduction**

In this tutorial, I'll outline how to mine Monero on the server side using p2pool. For the simpler client side way of mining Monero using Gupax, refer to [this guide](../gupax/index.md). Monero mining uses the [RandomX](https://www.getmonero.org/resources/moneropedia/randomx.html) algorithm and is CPU bound to prevent ASICs from centralizing the network. 

As with almost all other cryptocurrencies, Monero is best mined in pools. Most pools are centralized, meaning one entity controls the operation of the pool. This is an issue, because if the pool gains at least 51% of the total hashing power of the network, [the network's security can be compromised](https://wikipedia.org/wiki/Double-spending#51%_attack). To prevent this, p2pool was written. 

p2pool is a open source Monero mining pool that provides the best rewards and helps prevent centralization of mining power. The pool is decentralized and is not controlled by any one entity. 

Before you begin, it is important to know that due to the peer to peer nature of p2pool, all nodes connect to each other via forwarded ports and your IP will be visible by the network. There is currently no way to hide your IP, except maybe via VPN which is beyond the scope of this tutorial. [This tutorial](../vpn/index.md) explains how to set one up. 

## **Monero Node**

Before you begin mining, you must first find a node to source block data from. This node must have zmq enabled for p2pool to function. 

I recommend running your own node to reduce strain on the network and to increase your own privacy. You can follow [this tutorial](../monero2024/index.md) to set one up. If you cannot run a Monero node for some reason, pick the fastest node from the list [here](https://xmrvsbeast.com/p2pool/monero_nodes.html) and write down the hostname, RPC_Port, and ZMQ_Port. 

## **p2pool Node Setup**

When using p2pool, you must run your own p2pool node to which the xmrig mining clients will connect. 

To start, install p2pool from the [GitHub downloads page](https://github.com/SChernykh/p2pool/releases/latest): 
    
    
    ~/Downloads 
    ❯ wget "https://github.com/SChernykh/p2pool/releases/download/v4.0/p2pool-v4.0-linux-x64.tar.gz"
    
    ~/Downloads 
    ❯ tar -xf p2pool-v4.0-linux-x64.tar.gz
    
    ~/Downloads 
    ❯ mv p2pool-v4.0-linux-x64/ p2pool/
    
    ~/Downloads 
    ❯ cd p2pool/
    
    ~/Downloads/p2pool 
    ❯ realpath p2pool 
    /home/mcneb10/Downloads/p2pool/p2pool
    
    

You can also compile from source using the `p2pool_source.tar.xz` tarball

Next, make a systemd service for p2pool:
    
    
    ~ 
    ❯ sudo vim /etc/systemd/system/p2pool.service
    
    ~ 
    ❯ cat /etc/systemd/system/p2pool.service 
    [Unit]
    Description=p2pool
    After=network.target
    Wants=network.target
    
    [Service]
    ExecStart=/home/mcneb10/Downloads/p2pool/p2pool --wallet x --host 127.0.0.1 --rpc-port 18081 --zmq-port 18084 --stratum 0.0.0.0:3333 --mini
    Restart=on-failure
    RestartSec=10s
    StandardOutput=journal
    StandardError=journal
    
    [Install]
    WantedBy=multi-user.target
    
    

You'll need to make various changes to this config for your specific configuration: 

  1. Change the path of p2pool in `ExecStart` to the path outputted by `realpath` on your machine. 
  2. Replace the `x` in `--wallet x` with your own wallet address 
     * This is the wallet address that will represent your mining power on p2pool. It MUST be a primary address.
     * I recommend creating a new wallet specifically for mining to protect your privacy, as mining payout transactions are partially transparent to allow auditing of the total Monero supply.
     * **DO NOT** share this address with anyone, as it can be used to obtain the IP address of your p2pool node.
  3. Change the hostname after the `--host` option and the ports after the `--zmq-port` and `--rpc-port` options to the hostname and ports specific to the Monero node you run (or the one wrote down earlier if you are using another node). 
  4. Make sure the stratum interface is configured how you want it 
     * The `--stratum` option sets the address and port p2pool will bind to for accepting stratum connections. These stratum connections are for p2pool to communicate with the computers you will be mining on.
     * The default is fine, but will expose on all interfaces. If you don't want this, change the `0.0.0.0` to a different address.
  5. Remove the `--mini` option if you are running a larger scale mining operation (around 100kH/s or higher) 



You can then enable the service with: 
    
    
    ~ 
    ❯ sudo systemctl enable --now p2pool
    
    ~ 
    ❯ sudo systemctl status p2pool
    ● p2pool.service - p2pool
         Loaded: loaded (/etc/systemd/system/p2pool.service; enabled; preset: enabled)
         Active: active (running) since Wed 2024-08-14 16:38:58 UTC; 2min 54s
    	 
    	 ...
    
    

## **xmrig Setup**

Now that the p2pool node is set up, you can start mining! 

The you can find the xmrig binaries on the [releases page](https://github.com/xmrig/xmrig/releases/latest). Follow these steps to install: 
    
    
    ~/Downloads 
    ❯ wget "https://github.com/xmrig/xmrig/releases/download/v6.21.3/xmrig-6.21.3-linux-static-x64.tar.gz"
    
    ~/Downloads 
    ❯ tar -xf xmrig-6.21.3-linux-static-x64.tar.gz
    
    ~/Downloads 
    ❯ mv xmrig-6.21.3/ xmrig/
    
    ~/Downloads 
    ❯ cd xmrig/
    
    ~/Downloads/xmrig 
    ❯ realpath xmrig 
    /home/mcneb10/Downloads/xmrig/xmrig
    
    

**Please note that** the source code and precompiled xmrig binaries will donate 1% of your hashrate to the developer. You can change the code to prevent this or block the developer's server as it can compromise your privacy. The donation can be blocked by amending your hosts file like so: 
    
    
    ~ 
    ❯ sudo vim /etc/hosts
    
    ~ 
    ❯ cat /etc/hosts
    
    ...
    
    # Block xmrig donation
    0.0.0.0 donate.v2.xmrig.com donate.ssl.xmrig.com
    
    

Be careful mining in apartments, dorms, shared living spaces, public spaces, etc. as many have explicit policies against mining that may result in your punishment. 

With that out of the way, we can setup a systemd service like so: 
    
    
    ~ 
    ❯ sudo vim /etc/systemd/system/xmrig.service
    
    ~ 
    ❯ cat /etc/systemd/system/xmrig.service
    [Unit]
    Description=xmrig
    After=network.target
    Wants=network.target
    
    [Service]
    ExecStart=/home/mcneb10/Downloads/xmrig/xmrig -o 127.0.0.1:3333 -k
    Restart=on-failure
    RestartSec=10s
    StandardOutput=journal
    StandardError=journal
    
    [Install]
    WantedBy=multi-user.target
    
    

Again, you'll have to make some changes to the service config for your configuration: 

  1. Change the path of xmrig in `ExecStart` to the path outputted by the `realpath` command
  2. Replace the `127.0.0.1:3333` with the hostname:port of your p2pool stratum server we just set up relative to your mining rig



Some optimization info: 

  * xmrig relies on bare metal control of a CPU **as root** for optimization, so if you run it in a VM or as a regular user it will get a very bad hash rate. 
  * xmrig also has options to control the amount of threads and resources it uses on your machine. By default it won't use all resources to prevent the computer from becoming unusable. You can force xmrig to use as much computing power as possible by adding the option `--cpu-no-yield` to the command line. 
  * You can also set the number of preferred CPU threads for xmrig to use by adding `-t N`, where N is the number of threads. I don't recommend changing this, as xmrig will chose the optimal settings for you. Cutting down threads will reduce cpu + power usage. 
  * See the full list of optimization options [here](https://xmrig.com/docs/miner/command-line-options#cpu-backend). 



You can then enable the service with: 
    
    
    ~ 
    ❯ sudo systemctl enable --now xmrig
    
    ~ 
    ❯ sudo systemctl status xmrig
    ● xmrig.service - xmrig
         Loaded: loaded (/etc/systemd/system/xmrig.service; enabled; preset: enabled)
         Active: active (running) since Wed 2024-08-14 16:38:58 UTC; 2min 54s
    	 
    	 ...
    
    

Repeat the process for all of your mining rigs. 

## **Maintenance**

Make sure to periodically check for updates on p2pool, as there may be breaking changes that affect mining profitability and security. 

To update the binaries for either p2pool or xmrig, simply download them and overwrite the old version. You can use commands in the installation instructions to overwrite the old one. The systemd services should continue to work fine. 

## **Some Optional (but useful) Extras**

  * You can calculate your estimated revenue with [this calculator](https://mini.p2pool.observer/calculate-share-time). The [xmrig benchmark page](https://xmrig.com/benchmark) shows the hash rate of processors by model. 
    * For example, if you were to mine on an AMD Ryzen 5 7600X non stop for a day, you would make a maximum of 0.0017 XMR at the time of writing.
  * [mini p2pool observer](https://mini.p2pool.observer) ([onion](http://p2pmin25k4ei5bp3l6bpyoap6ogevrc35c3hcfue7zfetjpbhhshxdqd.onion/)) shows your mining stats, such as shares, payouts, daily revenue, etc. 
    * The site also has a service for mining notifications using webhooks.
    * If you removed the `--mini` option the site is at [p2pool observer](https://p2pool.observer/) ([onion](http://p2pool2giz2r5cpqicajwoazjcxkfujxswtk3jolfk2ubilhrkqam2id.onion/)).
    * Simply paste your mining wallet address in the search bar to view. Keep in mind the information will not populate until you get your first share, which might take a few hours.
  * Registering for the [xmrvsbeast](https://xmrvsbeast.com/p2pool/) hash rate raffle can give you even more profitability as a miner. The site explains the rules in depth. 






