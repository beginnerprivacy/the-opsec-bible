---
author: nihilist
date: 2024-01-31
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/103"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
tags:
  - Serverside Anonymity
  - Self-Hosted
  - Contributing to Anonymity
---
# Monero Node Setup 

```
TLDR: Monero is the one and only decentralised privacy coin, it is allowing everyone to freely transact privately and anonymously. It's been battle-tested and remains unbroken to this day. 
```

![](0.png)



In this tutorial we're going to take a look at how to setup a monero node:

![](../context/anon_self.png)

Context: i recommend you to self-host your own monero node, on your home server, because of the disk size the monero blockchain takes, due to that alone it won't be cheap at all to get a VPS to have that much diskspace in the long run.

## Initial Setup

First install monero and tor from the repositories:
    
    
    [ nowhere.moe ] [ /dev/pts/0 ] [/srv/nowhere.moe]
    → apt install monero tor -y
    

Then, create the following systemd service if you want to have a monero node to be publicly accessible via the IP directly:
    
    
    [ nowhere.moe ] [ /dev/pts/0 ] [/srv/nowhere.moe]
    → vim /etc/systemd/system/moneronode.service
    
    [ Wonderland ] [ /dev/pts/9 ] [/srv]
    → cat /etc/systemd/system/moneronode.service
    [Unit]
    Description=monerod
    After=network.target
    Wants=network.target
    
    [Service]
    
    # sync the monero node without going through Tor
    ExecStart=/usr/bin/monerod --zmq-pub tcp://127.0.0.1:18083 --disable-dns-checkpoints --enable-dns-blocklist --data-dir /srv/XMR --block-sync-size=50 --out-peers 100 --prep-blocks-threads=128 --prune-blockchain --sync-pruned-blocks --rpc-bind-port=18081 --rpc-bind-ip=0.0.0.0 --p2p-bind-ip=0.0.0.0 --p2p-bind-port=18080 --confirm-external-bind --non-interactive
    
    
    Restart=on-failure
    RestartSec=10s
    
    StandardOutput=journal
    StandardError=journal
    
    [Install]
    WantedBy=multi-user.target

## Sync over Onion

However if your users are well-educated and are aware that [Chainalysis are running malicious Monero nodes](../chainalysisattempts/index.md), **then they are NOT going to connect to non-onion monero nodes (and neither should you).** Plus if Monero is illegal in your country, you'll also want to synchronize it via Tor instead, so you can use this config instead:
    
    
    [ Wonderland ] [ /dev/pts/9 ] [/mnt/md3]
    → cat /etc/systemd/system/moneronode.service
    [Unit]
    Description=monerod
    After=network.target
    Wants=network.target
    
    [Service]
    
    # sync the monero node while actually going through Tor (in case if Monero is illegal in your country)
    ExecStart=/usr/bin/monerod --zmq-pub tcp://127.0.0.1:18083 --disable-dns-checkpoints --enable-dns-blocklist --data-dir /srv/XMR --block-sync-size=50 --out-peers 100 --prep-blocks-threads=128 --prune-blockchain --sync-pruned-blocks --rpc-bind-port=18081 --rpc-bind-ip=127.0.0.1 --p2p-bind-ip=127.0.0.1 --p2p-bind-port=18080 --non-interactive  --proxy 127.0.0.1:9050 --tx-proxy tor,127.0.0.1:9050
    
    Restart=on-failure
    RestartSec=10s
    
    
    StandardOutput=journal
    StandardError=journal
    
    [Install]
    WantedBy=multi-user.target
    
    
    

Then wait for it to sync after enabling the systemd service:
    
    
    [ nowhere.moe ] [ /dev/pts/0 ] [/srv/nowhere.moe]
    → systemctl daemon-reload
    
    [ nowhere.moe ] [ /dev/pts/0 ] [/srv/nowhere.moe]
    → systemctl enable --now moneronode
    Created symlink /etc/systemd/system/multi-user.target.wants/moneronode.service → /etc/systemd/system/moneronode.service.
    
    [ nowhere.moe ] [ /dev/pts/0 ] [/srv/nowhere.moe]
    → systemctl status moneronode
    ● moneronode.service - monerod
         Loaded: loaded (/etc/systemd/system/moneronode.service; enabled; preset: enabled)
         Active: active (running) since Sun 2023-07-09 15:36:44 CEST; 2min 22s ago
       Main PID: 8410 (monerod)
          Tasks: 30 (limit: 77000)
         Memory: 1.7G
            CPU: 1min 53.681s
         CGroup: /system.slice/moneronode.service
                 └─8410 /usr/bin/monerod --zmq-pub tcp://127.0.0.1:18083 --disable-dns-checkpoints --enable-dns-blocklist --data-dir /srv/XMR --block-sync-size=50 --out-peers 100 --prep-blocks-threads=128 --prune-blockchain --sync-pruned-blocks --rpc-bind-port=18081 --rpc-bind-ip=0.0.0.0 ->
    
    Jul 09 15:39:06 Datura monerod[8410]: 2023-07-09 13:39:06.055        I Synced 88702/2925934 (3%, 2837232 left)
    Jul 09 15:39:06 Datura monerod[8410]: 2023-07-09 13:39:06.188        I Synced 88752/2925934 (3%, 2837182 left)
    Jul 09 15:39:06 Datura monerod[8410]: 2023-07-09 13:39:06.310        I Synced 88802/2925934 (3%, 2837132 left)
    Jul 09 15:39:06 Datura monerod[8410]: 2023-07-09 13:39:06.452        I Synced 88852/2925934 (3%, 2837082 left)
    Jul 09 15:39:06 Datura monerod[8410]: 2023-07-09 13:39:06.576        I Synced 88902/2925934 (3%, 2837032 left)
    Jul 09 15:39:06 Datura monerod[8410]: 2023-07-09 13:39:06.756        I Synced 88952/2925934 (3%, 2836982 left)
    Jul 09 15:39:06 Datura monerod[8410]: 2023-07-09 13:39:06.890        I Synced 89002/2925934 (3%, 2836932 left)
    Jul 09 15:39:07 Datura monerod[8410]: 2023-07-09 13:39:07.060        I Synced 89052/2925934 (3%, 2836882 left)
    Jul 09 15:39:07 Datura monerod[8410]: 2023-07-09 13:39:07.182        I Synced 89088/2925934 (3%, 2836846 left)
    Jul 09 15:39:07 Datura monerod[8410]: 2023-07-09 13:39:07.376        I Synced 89138/2925934 (3%, 2836796 left)
    	
### How long does it take?

On a NVMe SSD it may take 2 days, and weigh approximately 90 gigs at the time of writing this tutorial. The synchronisation is a very disk-intensive process, and so it is required to do it on a nvme disk or ssd at least. If you try to do that on a HDD it will take much, much longer. If you don't have a choice, sync it on a nvme somewhere and then rsync it to a server that has only HDDs.

## Monero Hidden Service

Once your monero node is synchronized, you can allow tor users to access it via a .onion link like so:
    
    
    [ Wonderland ] [ /dev/pts/9 ] [~]
    → apt install tor
    
    [ Wonderland ] [ /dev/pts/9 ] [~]
    → cat /etc/tor/torrc
    HiddenServiceDir /var/lib/tor/monero-service/
    HiddenServicePort 18080 127.0.0.1:18080
    HiddenServicePort 18081 127.0.0.1:18081
    
    
    [ Wonderland ] [ /dev/pts/9 ] [~]
    → systemctl restart tor@default
    
    

Then find your onion link right here:
    
    
    [ Wonderland ] [ /dev/pts/9 ] [~]
    → cat /var/lib/tor/monero-service/hostname
    uyjehlovjudh2wlvkp5a2seme5vgqc4o463atkv2ulsovloqrqw2icyd.onion
    
    

And then you can use it to connect to it via your monero wallet. As shown below:
    
    
    apt install monero -y
    
    monero-wallet-cli
    #follow the instructions to create your wallet
    #synchronize it with this command:
    set_daemon http://uyjehlovjudh2wlvkp5a2seme5vgqc4o463atkv2ulsovloqrqw2icyd.onion:18081 trusted
    #then wait for the daemon to finish synchronizing, and type "refresh" regularly to make sure that it synchronizes with the node, expect to type that command a few times as tor connections are unstable at times.
    refresh
    status
    
    

