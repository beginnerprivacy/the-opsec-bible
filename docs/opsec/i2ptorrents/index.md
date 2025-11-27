---
author: oxeo0
date: 2025-03-14
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/17"
xmr: 862Sp3N5Y8NByFmPVLTPrJYzwdiiVxkhQgAdt65mpYKJLdVDHyYQ8swLgnVr8D3jKphDUcWUCVK1vZv9u8cvtRJCUBFb8MQ
tags:
  - Clientside Anonymity
---
# Peer-to-Peer Large File Sharing (Torrents over I2P)

```
TLDR: you can anonymously share large files using Torrents over the I2P Network.
```

![](0.0.png)



## **Introduction**

Torrenting is a popular way to share large files. It allows users to share them without having to trust the central server.  
However, back in 2004 when [BitTorrent protocol](https://en.wikipedia.org/wiki/BitTorrent) was invented, nobody really thought about making it anonymous or even encrypted. Thus torrenting requires client to share their IP address publicly. This means that torrenting can be used to track people's activities on the Internet. In order to protect your privacy and anonymity, you should use a VPN or anonymizing proxy (like I2P) when sharing files over BitTorrent protocol. 

We already know how to [share files with BitTorrent client over VPN](../p2ptorrents/index.md). While this is secure, fast and convenient, it doesn't make us truly anonymous. 

In this tutorial, we'll configure an I2P router to share files using the I2P bittorrent client. 

Using torrents with I2P has several benefits: 

  * **Full anonymity** \- while VPN masks the IP address of the client, I2P gets rid of IP addresses entirely replacing them with destination tunnel addresses.
  

  * **Decentralization** \- it works without trackers or a central authority.
  

  * **Free** (as in price) - you don't need to buy a VPN service for both Alice and Bob.
  

  * **Traffic obfuscation** \- I2P has transit tunnels which make it harder to fingerprint torrent traffic.
  



But it also comes with several drawbacks: 

  * **Speed** \- I2P is much slower than VPN because it routes the traffic through several hops.
  

  * **Convenience** \- I2P needs to build the tunnels for some time before torrenting. It's best to keep it running in the background to get faster tunnels which may be inconvenient.
  



## **Why I2P, not Tor?**

  
  


Both I2P and Tor are encrypted overlay networks which aim to deliever privacy and anonymity for servers and clients. They use [onion](https://en.wikipedia.org/wiki/Onion_routing) or [garlic](https://en.wikipedia.org/wiki/Garlic_routing) routing to hide originating and destination IP addresses. To discover servers on the network, they both use Distributed Hash Table (DHT).  
However while Tor is designed mostly for client-server applications, I2P takes more [peer-to-peer](https://en.wikipedia.org/wiki/Peer-to-peer) approach. In I2P, every node is encouraged to act as a relay for others. Your I2P client will accept transit tunnels to participate in anonymizing traffic of other nodes. This also has the benefit of obscuring you traffic volume preventing bandwidth correlation attacks. On the other hand, Tor relays are usually ran by volounteers on separate Tor instances, they require high bandwidth and stable internet connection so most of them run in datacenters. 

Another very important aspect is that Tor still doesn't support [UDP](https://en.wikipedia.org/wiki/User_Datagram_Protocol) traffic which torrents require to function. It's possible to do [UDP tunneling over Tor](https://www.whonix.org/wiki/Tunnel_UDP_over_Tor) but it's not very efficient and requires specific configuration.  
The Tor community [discourages](https://blog.torproject.org/bittorrent-over-tor-isnt-good-idea/) usage of Tor for torrenting.  
I2P on the other hand is built on top of UDP and is much better suited for torrenting. Over the years, the torrenting ecosystem in I2P matured to the point where even qBittorrent introduced [experimental I2P support](https://news.itsfoss.com/qbittorrent-4-6-0/).  
However in this guide we'll use the bittorrent client built specifically for I2P - [I2PSnark](https://i2pgit.org/i2p-hackers/i2p.i2p/-/tree/master/apps/i2psnark). 

## **Prerequisites**

  
  


It's assumed Alice and Bob have a working internet connection, a Debian 12 with a desktop environment and root access to their computers.  
They can have firewall or NAT (I2P can do [NAT traversal](https://en.wikipedia.org/wiki/NAT_traversal)) but it would be ideal to have the ability to open one UDP port on the router. It's also possible to run I2P on a separate machine in your LAN (like a NAS or Raspberry PI running Debian). I2P greatly benefits from running constantly since it can discover faster tunnels over time. 

Here's a simplified graph showcasing how the file will be sent over I2P network:  
  
![](0.1.png)   
  


## **I2P Installation** (Alice AND Bob)

  
  


Both Alice and Bob need to install I2P on their computers. The steps listed below are up-to-date as of now, but always check the [official guide](https://geti2p.net/en/download/debian) in case something has changed since this guide was written.  
Install packages used for adding repositories and signing keys: 
    
    
    alice@alicepc:~$ sudo apt update
    alice@alicepc:~$ sudo apt-get install apt-transport-https lsb-release curl
    

Add I2P repository signed by their key: 
    
    
    alice@alicepc:~$ echo "deb [signed-by=/usr/share/keyrings/i2p-archive-keyring.gpg] https://deb.i2p.net/ $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/i2p.list
    

Import signing key: 
    
    
    alice@alicepc:~$ curl -o /tmp/i2p-archive-keyring.gpg https://geti2p.net/_static/i2p-archive-keyring.gpg
    alice@alicepc:~$ sudo cp /tmp/i2p-archive-keyring.gpg /usr/share/keyrings
    

Finally, install I2P: 
    
    
    alice@alicepc:~$ sudo apt-get update
    alice@alicepc:~$ sudo apt-get install i2p i2p-keyring
    

If you decided to go with I2P on separate server, you may need to make Web UI accessible on your local network: 
    
    
    alice@alicepc:~$ sudo sed -i 's/127\.0\.0\.1/0\.0\.0\.0/g' /var/lib/i2p/i2p-config/clients.config.d/00-net.i2p.router.web.RouterConsoleRunner-clients.config
    alice@alicepc:~$ sudo systemctl restart i2p
    

Repeat the **same steps** on Bob's machine. 

## **I2P Setup** (Alice AND Bob)

  
  


By now, Alice and Bob have I2P running in the background on their computers.  
**Both of them** need to do initial configuration of their I2P routers.  
The I2P Console should be accessible at [**http://localhost:7657**](http://localhost:7657). If I2P was installed on a different machine, change **localhost** to the IP address of that machine. 

Navigating to this address, you should be greeted with configuration wizard:  
  
![](1.png)   
  
Select theme (I recommend dark of course):  
  
![](2.png)   
  
Agree to the terms of speedtest service:  
  
![](3.png)   
  
Bandwidth test should now begin:  
  
![](4.png)   
  
It should finish in a few seconds:  
  
![](5.png)   
  
Now you can choose how much bandwidth you want to use for I2P. You also set the transit bandwidth expressed as a percentage of total I2P bandwidth. It's recommended to keep it at 80%:  
  
![](6.png)   
  
Configuring I2P web browsing is a topic for a whole different guide. For now, we will just configure I2P for torrenting so skip this section by clicking **Next** :  
  
![](7.png)   
  
The configuration wizard should be completed, just click **Finished** :  
  
![](8.png)   
  
Now you should be redirected to the **I2P Console**. Here you can find the links to I2P-native apps and services.  
You can also configure your I2P Router settings and see its **uptime** (in green), **bandwidth statistics** (in red) and **network status** (in blue):  
  
![](9.png)   
  
As you can see, my network status is **Firewalled**. I2P should work just fine behind firewalls, however to get faster speeds and better tunnels, we can **open UDP port on your firewall**.  
This is **entirely optional** so if you don't have the ability to expose port to the internet, just skip to the next section.  
In I2P the port is choosen randomly at the time of installation. To check it which port needs to be opened, go to the **configuration page** :  
  
![](10.png)   
  
Select the **Network** tab:  
  
![](11.png)   
  
Scroll down a bit and check which UDP port was chosen. In my case it's **14496**. On your main router or firewall you can forward this UDP port.  
The actual instructions will differ across firewall vendors so I won't show them here. After that, network status should change to **OK**.  
  
![](12.png)   
  


## **I2PSnark Configuration** (Alice AND Bob)

  
  


With I2P up and running, we can now configure the built-in torrent app called **I2PSnark**.  
To do this, we need to navigate back to the **I2P Console** and click on the **Torrents** application:  
  
![](13.png)   
  
I2PSnark also has its own configuration which we need to adjust. Click on the **Configuration** button:  
  
![](14.png)   
  
Take a note of the **Data directory**. By default it's **/var/lib/i2p/i2psnark-config/i2psnark**. Torrents will be stored in there.  
Now change the **bandwidth** to half of that of what we set for I2P.  
The **number of hops** should be left at **3**. It's the number of routers I2P will tunnel your traffic through before reaching the destination (just like [Onion Routing](https://en.wikipedia.org/wiki/Onion_routing) in Tor).  
Lower values usually increase speed and decrease anonymity.  
You can also adjust the **number of tunnels** I2PSnark will use for connections.  
Setting it to **10** will give I2P more choice and potentially increase speed at the expense of higher CPU usage.  
After that's done, click **Save configuration** button:  
  
![](15.png)   
  


## **Creating Torrent** (Alice)

To create and seed files, Alice needs to move them to the **Data directory** we set earlier in I2PSnark configuration.  
Let's assume Alice wants to send a single large file to Bob - [enwik9](https://mattmahoney.net/dc/textdata.html), which contains the first 1 GB from Wikipedia dump.  
It would work the same way for seeding entire directory. Just provide the path to the directory Alice wants to seed.  

    
    
    alice@alicepc:~$ sudo mv -v enwik9 /var/lib/i2p/i2psnark-config/i2psnark
    renamed 'enwik9' -> '/var/lib/i2p/i2psnark-config/i2psnark/enwik9'

While a bit inconvenient, the default directory has the appropriate permissions set so that only **i2p** user can access it on your Linux system.  
It doesn't have read permission on Alice's files under **/home/alice** so if your i2p daemon were ever to be compromised, the files couldn't be read so easily.  


Alice should click **Create Torrent** option in I2PSnark:  
  
![](16.png)   
  
Now she should put the name of file to be seeded in **Data to seed** field and ensure **no trackers are selected** (only DHT will be used to find peers):  
  
![](17.png)   
  
We can safely ignore this warning message since we explicitly selected DHT with no trackers.  
To start seeding, click the play button next to the torrent:  
  
![](18.png)   
  
Now verify the status says **Seeding** and check the details to get the torrent's hash:  
  
![](19.png)   
  
Here's the torrent hash. Anyone who has this hash will be able to download it while Alice is seeding:  
  
![](20.png)   
  


## **Sharing Torrent Hash over Secure Channel** (Alice -> Bob)

If you want to keep the torrent private, it's important not to share torrent hash publicly. Alice will use [SimpleX](https://blog.nowhere.moe/opsec/anonsimplex/index.md) chat to share the torrent hash with Bob:  
  
![](26.png)   
  


## **Downloading The Torrent** (Bob)

To download the torrent, Bob needs to open the I2PSnark torrent client and click on **Add Torrent** :  
  
![](21.png)   
  
After that, Bob will be prompted with a dialog box to enter the torrent hash he got from Alice into the **From URL** field and click **Add torrent** :  
  
![](22.png)   
  
I2PSnark will now look through the DHT and make a connection with Alice. Once a connection has been made, the download will be started:  
  
![](23.png)   
  
As we can see, Bob's client connected to 1 peer (Alice) and downloads with a speed of 75 KB/s.  
Alice knows when someone's connected to her. Here's how it looks on her side:  
  
![](24.png)   
  
On my network it took around 3 hours to send this 1 GB file. It's certainly slower than torrenting over a VPN, but the speed may improve over time when better tunnels are discovered.  
After the download is finished, Bob will have the file in **/var/lib/i2p/i2psnark-config/i2psnark** directory.  
Both Bob and Alice can now click the "Stop" button to disable seeding (so that nobody else can download the file):  
  
![](25.png)   
  


## **Conclusion**

Alice and Bob have successfully shared a file using I2P network. The transfer was fully anonymous and decentralized. 

