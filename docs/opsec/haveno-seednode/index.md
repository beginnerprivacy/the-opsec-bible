---
author: nihilist
date: 2024-10-06
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/18"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
tags:
  - Clientside Anonymity
  - Decentralized Finances
  - Agorism
---
# How to run a Haveno Seed Node 

```
TLDR: you can contribute to keeping Haveno Networks decentralised by running Haveno Seed nodes. Making it more expensive to take down, the more seed nodes there are.
```

![](../haveno-client-f2f/0.png)



In this tutorial we're going to take a look at how you can contribute to an existing Haveno Network, by running a Seed Node, in order to make the Haveno Network of your choice more resillient to potential takedowns. 

_Disclaimer:_ I am not running any seednodes for any Haveno Network, this is only to showcase how it works for whoever wants to run a seednode. **Obviously you don't want to get the TornadoCash treatment by publicly announcing that you are helping with the infrastructure for an exchange with your public identity since this is potentially sensitive use.** Therefore make sure you remain Anonymous (meaning you use a disposable identity) when saying that you are running a haveno seed node (see how to properly segment your internet uses [here](../internetsegmentation/index.md)). See the explanation on where to host sensitive hidden services [here](../sensitiveremotevshome/index.md).



## **Why contribute to a Haveno Network ?**

As explained [previously](../haveno-client-f2f/index.md), for a Haveno Network, the more seed nodes there are, the more resillient the network is to potential takedowns:

![](../haveno-client-f2f/28.png)

For an adversary, they need to find and takedown all of the seed nodes of a Haveno Network. But unlike a regular centralised exchange, these are .onion links, not clearnet ones, hence, finding those seed nodes is meant to be as hard as possible to do for them, not only that, but they also need to find them all, and take them all down at once, to be able to bring down a Haveno Network.

It is possible for anyone out there to create a Haveno Seed Node, for any Haveno Network out there. Or in other words, **Anyone can contribute in making Fiat to Monero transactions unstoppable, by making Haveno Networks more resillient, by running seed nodes for them.**

## **What is required ?**



In short, as detailed in the official documentation [here](https://github.com/haveno-dex/haveno/blob/master/docs/deployment-guide.md#seed-nodes-with-proof-of-work-pow), the requirement is that you have a device or a server (such as a VPS), running 24/7, with a local monero node. (hence requiring storage).
![](../context/sensitive_remote.png)

Before starting, make sure you have a device that is already running a monero node. To do that, follow [this tutorial](../monero2024/index.md) i wrote.
    
    
    [ Datura ] [ /dev/pts/10 ] [~]
    → systemctl status moneronode
    ● moneronode.service - monerod
         Loaded: loaded (/etc/systemd/system/moneronode.service; enabled; preset: enabled)
         Active: active (running) since Sat 2024-09-21 12:14:46 CEST; 2 weeks 0 days ago
       Main PID: 1016 (monerod)
          Tasks: 30 (limit: 77002)
         Memory: 13.6G
            CPU: 3w 2d 11h 42min 2.980s
         CGroup: /system.slice/moneronode.service
                 └─1016 /usr/bin/monerod --disable-dns-checkpoints --enable-dns-blocklist --data-dir /srv/XMR --block-sync-size=50 --out-peers=-1 --in-peers=-1 --prep-blocks-threads=128 --prune-blockchain --sync-pruned-blocks --rpc-bind-port=1>
    
    Oct 06 10:07:57 Datura monerod[1016]: 2024-10-06 08:07:57.625        I Subnet 199.116.84.0/24 blocked.
    Oct 06 10:07:57 Datura monerod[1016]: 2024-10-06 08:07:57.625        I Subnet 209.222.252.0/24 blocked.
    Oct 06 10:07:57 Datura monerod[1016]: 2024-10-06 08:07:57.668        I Subnet 91.198.115.0/24 blocked.
    Oct 06 10:09:41 Datura monerod[1016]: 2024-10-06 08:09:41.840        E Transaction not found in pool
    Oct 06 10:10:52 Datura monerod[1016]: 2024-10-06 08:10:52.143        E mined block failed verification
    Oct 06 10:49:47 Datura monerod[1016]: 2024-10-06 08:49:47.176        E Transaction not found in pool
    Oct 06 11:09:39 Datura monerod[1016]: 2024-10-06 09:09:39.370        E mined block failed verification
    Oct 06 11:10:31 Datura monerod[1016]: 2024-10-06 09:10:31.992        E mined block failed verification
    Oct 06 11:12:08 Datura monerod[1016]: 2024-10-06 09:12:08.311        E mined block failed verification
    Oct 06 11:18:43 Datura monerod[1016]: 2024-10-06 09:18:43.902        E Transaction not found in pool
    
    [ Datura ] [ /dev/pts/10 ] [~]
    → du -hs /srv/XMR
    82G     /srv/XMR
    
    

Once you have your server running a monero node as shown above, (with a pruned monero node of 82Gb, as of october 2024), you can proceed with the installation of the Haveno Seed Node.

## **How to run a Seed Node**

First of all we need to choose a Haveno Network to contribtue to. [Haveno Reto](https://haveno-reto.com) being the only functionnal one available right now, we're going to run a Seed node for them., following the instructions [here](https://github.com/haveno-dex/haveno/blob/master/docs/deployment-guide.md#fork-and-build-haveno).
    
    
    [ Datura ] [ /dev/pts/10 ] [/srv]
    → git clone https://github.com/retoaccess1/haveno-reto
    
    [ Datura ] [ /dev/pts/10 ] [/srv]
    → cd haveno-reto
    
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto]
    → ls
    apitest  build.gradle  common  core    desktop  gpg_keys  gradle.properties  gradlew.bat  LICENSE   media    p2p    README.md  scripts   settings.gradle
    assets   cli           config  daemon  docs     gradle    gradlew            inventory    Makefile  monitor  proto  relay      seednode  statsnode
    	
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto]
    → cd scripts
    
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto/scripts]
    → ls
    deployment  install_java.bat  install_java.sh  install_tails
    
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto/scripts]
    → ./install_java.sh
    
    

First let's install Java using the script provided: 
    
    
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto/scripts]
    → ./install_java.sh
    Reading package lists... Done
    Building dependency tree... Done
    Reading state information... Done
    curl is already the newest version (7.88.1-10+deb12u7).
    0 upgraded, 0 newly installed, 0 to remove and 9 not upgraded.
      % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                     Dload  Upload   Total   Spent    Left  Speed
    100  194M  100  194M    0     0  26.9M      0  0:00:07  0:00:07 --:--:-- 45.7M
    update-alternatives: using /usr/lib/jvm/openjdk-21.0.2/bin/java to provide /usr/bin/java (java) in auto mode
    update-alternatives: using /usr/lib/jvm/openjdk-21.0.2/bin/javac to provide /usr/bin/javac (javac) in auto mode
    openjdk version "21.0.2" 2024-01-16
    OpenJDK Runtime Environment (build 21.0.2+13-58)
    OpenJDK 64-Bit Server VM (build 21.0.2+13-58, mixed mode, sharing)
    	
    

Then, we build the haveno repository:
    
    
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto]
    → make clean && make
    ./gradlew clean
    Downloading https://services.gradle.org/distributions/gradle-8.6-bin.zip
    
    [...] (give it a few minutes to complete)
    
    > Task :relay:compileJava
    Note: /srv/haveno-reto/relay/src/main/java/haveno/relay/RelayMain.java uses or overrides a deprecated API.
    Note: Recompile with -Xlint:deprecation for details.
    
    Deprecated Gradle features were used in this build, making it incompatible with Gradle 9.0.
    
    You can use '--warning-mode all' to show the individual deprecation warnings and determine if they come from your own scripts or plugins.
    
    For more on this, please refer to https://docs.gradle.org/8.6/userguide/command_line_interface.html#sec:command_line_warnings in the Gradle documentation.
    
    BUILD SUCCESSFUL in 4m 1s
    138 actionable tasks: 138 executed
    	
    

once haveno is built, we're going to install Tor as shown in our [previous](../tor/relay/index.md) tutorial:
    
    
    root@Datura:~# apt update -y && apt upgrade -y
    root@Datura:~# apt install curl tmux vim gnupg2 -y
    
    root@Datura:~# cat /etc/apt/sources.list |head -n3
    
    deb     [signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org bookworm main
    deb-src [signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org bookworm main
    
    root@Datura:~# wget -qO- https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --dearmor | tee /usr/share/keyrings/tor-archive-keyring.gpg >/dev/null
    
    apt update -y
    apt install tor nyx
    	
    

Now from here we have what we need: a local monero node, and tor setup. Now it's a matter of configuring torrc for our Haveno Seed Node:
    
    
    #if you have no existing torrc config, overwrite it:
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto]
    → cat seednode/torrc > /etc/tor/torrc
    
    
    #if you have an existing torrc config, append it below the existing torrc you have:
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto]
    → vim /etc/tor/torrc
    
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto]
    → cat seednode/torrc >> /etc/tor/torrc
    	
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto]
    → systemctl restart tor@default
    
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto]
    → systemctl status tor@default
    ● tor@default.service - Anonymizing overlay network for TCP
         Loaded: loaded (/lib/systemd/system/tor@default.service; enabled-runtime; preset: enabled)
         Active: active (running) since Sun 2024-10-06 12:01:18 CEST; 5s ago
        Process: 938459 ExecStartPre=/usr/bin/install -Z -m 02755 -o debian-tor -g debian-tor -d /run/tor (code=exited, status=0/SUCCESS)
        Process: 938460 ExecStartPre=/usr/bin/tor --defaults-torrc /usr/share/tor/tor-service-defaults-torrc -f /etc/tor/torrc --RunAsDaemon 0 --verify-config (code>
       Main PID: 938462 (tor)
          Tasks: 13 (limit: 77002)
         Memory: 190.7M
            CPU: 9.987s
         CGroup: /system.slice/system-tor.slice/tor@default.service
                 └─938462 /usr/bin/tor --defaults-torrc /usr/share/tor/tor-service-defaults-torrc -f /etc/tor/torrc --RunAsDaemon 0
    
    Oct 06 12:01:19 Datura Tor[938462]: Opened Control listener connection (ready) on /run/tor/control
    Oct 06 12:01:19 Datura Tor[938462]: Self-testing indicates your ORPort 65.109.30.253:28710 is reachable from the outside. Excellent. Publishing server descripto>
    Oct 06 12:01:19 Datura Tor[938462]: Bootstrapped 10% (conn_done): Connected to a relay
    Oct 06 12:01:19 Datura Tor[938462]: Bootstrapped 14% (handshake): Handshaking with a relay
    Oct 06 12:01:20 Datura Tor[938462]: Bootstrapped 15% (handshake_done): Handshake with a relay done
    Oct 06 12:01:20 Datura Tor[938462]: Bootstrapped 75% (enough_dirinfo): Loaded enough directory info to build circuits
    Oct 06 12:01:20 Datura Tor[938462]: Bootstrapped 90% (ap_handshake_done): Handshake finished with a relay to build circuits
    Oct 06 12:01:20 Datura Tor[938462]: Bootstrapped 95% (circuit_create): Establishing a Tor circuit
    Oct 06 12:01:20 Datura Tor[938462]: Bootstrapped 100% (done): Done
    Oct 06 12:01:24 Datura Tor[938462]: Your network connection speed appears to have changed. Resetting timeout to 60000ms after 18 timeouts and 1000 buildtimes.
    
    

Now let's take note of the seednode hostnames that tor generated for us:
    
    
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto]
    → cat /var/lib/tor/haveno_seednode/hostname
    5vycrhlbz44bpyvbh25b37joqj433wex7fn2d5hunp2bmxkv7ibk2vqd.onion
    
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto]
    → cat /var/lib/tor/haveno_seednode2/hostname
    tqxmkjprxry7xwf2sdvy55etnkp6eddc4uxj5fd6rwpnc472mpizgqyd.onion
    	
    

Next we copy the haveno-seednode systemd services into the systemd service directory:
    
    
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto]
    → cp scripts/deployment/haveno-seednode.service /etc/systemd/system/
    
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto]
    → cp scripts/deployment/haveno-seednode2.service /etc/systemd/system/
    
    

Then first we mention the 2 seed node onion mirrors in the **core/src/main/resources/xmr_mainnet.seednodes** file:
    
    
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto]
    → vim core/src/main/resources/xmr_mainnet.seednodes
    
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto]
    → cat core/src/main/resources/xmr_mainnet.seednodes
    # nodeaddress.onion:port [(@owner,@backup)]
    k6wctqd5l2nhmietzs6zg4pric3ukeg7lazzz67ttbl75qwfr2q4yvqd.onion:2002(@anon1)
    4gmfgn22tll7ajw3tdp7nru3fvgh5ukt7w53kfv5ymijldivsqtbzdqd.onion:2003(@anon1)
    bugc27z7lqjgpwmhbuu3kuwoq2bhailj573r32jm5ydwrcqrwjtblnid.onion:1002(@anon2)
    xephvvzd3orepnny7lbia4nkwie5t7wjivlvvz5lhbsck7ubavystead.onion:9992(@anon3 ,@s0)
    g4z6oi2wf62nwztwve6qe2hqswj4ezpom6hn7cuy5cxaidey4us76bid.onion:9993(@anon3 ,@s0)
    z47tltuwytd5icqq4hni2ammvlugp6pcwqboeu7ngawruualxjjuu3ad.onion:9992(@anon3 ,@s3)
    hxb5h34hjgyraycrrxlz5ar2q77mjgondzicwzayqwwvuaepssrn5zyd.onion:9993(@anon3 ,@s3)
    u6wwec5ddxswwyrz7rgzuiwowf33llab57y3xzmwwxvsofq2w4m6ihad.onion:1002(@anon4)
    im6hcl7hknvsrsns2newv4orfv3kd2ly5yvqtbfkiyzoohscyp5htgqd.onion:2002(@anon6)
    **5vycrhlbz44bpyvbh25b37joqj433wex7fn2d5hunp2bmxkv7ibk2vqd.onion:2002(@nihilist1)
    tqxmkjprxry7xwf2sdvy55etnkp6eddc4uxj5fd6rwpnc472mpizgqyd.onion:2003(@nihilist1)**
    
    

Then we edit them accordingly by replacing "XMR_STAGENET" to "XMR_MAINNET", editing the xmrNode port to 18081 (the rpc bind port), edit the binary location, and also the user that is running the seed nodes (in my case it is the root user):
    
    
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto]
    → cat /etc/systemd/system/haveno-seednode.service
    [Unit]
    Description=Haveno seednode
    After=network.target
    
    [Service]
    User=root
    Group=root
    SyslogIdentifier=Haveno-Seednode
    
    ExecStart=/bin/sh /srv/haveno-reto/haveno-seednode --baseCurrencyNetwork=XMR_MAINNET\
      --useLocalhostForP2P=false\
      --useDevPrivilegeKeys=false\
    # Uncomment the following line to use external tor
      --hiddenServiceAddress=5vycrhlbz44bpyvbh25b37joqj433wex7fn2d5hunp2bmxkv7ibk2vqd.onion\
      --nodePort=2002\
      --appName=haveno-XMR_MAINNET_Seed_2002\
    #  --logLevel=trace\
      --xmrNode=http://127.0.0.1:18081
    #  --xmrNodeUsername=admin\
    #  --xmrNodePassword=password
    
    ExecStop=/bin/kill ${MAINPID}
    Restart=always
    
    # Hardening
    PrivateTmp=true
    ProtectSystem=full
    NoNewPrivileges=true
    PrivateDevices=true
    MemoryDenyWriteExecute=false
    ProtectControlGroups=true
    ProtectKernelTunables=true
    RestrictSUIDSGID=true
    # limit memory usage to 2gb
    LimitRSS=2000000000
    
    [Install]
    WantedBy=multi-user.target
    
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto]
    → systemctl daemon-reload
    
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto]
    → systemctl enable --now haveno-seednode.service
    Created symlink /etc/systemd/system/multi-user.target.wants/haveno-seednode.service → /etc/systemd/system/haveno-seednode.service.
    
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto]
    → systemctl status haveno-seednode
    ● haveno-seednode.service - Haveno seednode
         Loaded: loaded (/etc/systemd/system/haveno-seednode.service; enabled; preset: enabled)
         Active: active (running) since Sun 2024-10-06 13:35:26 CEST; 4s ago
       Main PID: 1395101 (java)
          Tasks: 46 (limit: 77002)
         Memory: 185.8M
            CPU: 4.432s
         CGroup: /system.slice/haveno-seednode.service
                 └─1395101 java -classpath /srv/haveno-reto/lib/seednode.jar:/srv/haveno-reto/lib/core.jar:/srv/haveno-reto/lib/p2p.jar:/srv/haveno-reto/lib/common.jar:/srv/haveno-reto/lib/proto.jar:/srv/haveno-reto/lib/assets.jar:/srv/haveno-reto/lib/guava-32.1.1-jre.jar:/srv/haveno-reto/lib/logback-classic-1.1.11.jar:/srv>
    
    Oct 06 13:35:28 Datura Haveno-Seednode[1395101]: >> We send a PreliminaryGetDataRequest to peer 4gmfgn22tll7ajw3tdp7nru3fvgh5ukt7w53kfv5ymijldivsqtbzdqd.onion:2003
    Oct 06 13:35:28 Datura Haveno-Seednode[1395101]:
    Oct 06 13:35:28 Datura Haveno-Seednode[1395101]: Oct-06 13:35:28.638 [NetworkNode.connectionExecutor:SendMessage-to-im6hcl7hknvs...] INFO  haveno.network.p2p.network.NetworkNode: Socket creation to peersNodeAddress im6hcl7hknvsrsns2newv4orfv3kd2ly5yvqtbfkiyzoohscyp5htgqd.onion:2002 took 326 ms
    Oct 06 13:35:28 Datura Haveno-Seednode[1395101]: Oct-06 13:35:28.666 [NetworkNode.connectionExecutor:SendMessage-to-im6hcl7hknvs...] INFO  h.n.p.p.g.m.PreliminaryGetDataRequest: Sending a PreliminaryGetDataRequest with 112.838 kB and 5127 excluded key entries. Requesters version=1.0.11
    Oct 06 13:35:28 Datura Haveno-Seednode[1395101]: Oct-06 13:35:28.669 [NetworkNode.connectionExecutor:SendMessage-to-im6hcl7hknvs...] INFO  h.n.p.p.g.m.PreliminaryGetDataRequest: Sending a PreliminaryGetDataRequest with 112.838 kB and 5127 excluded key entries. Requesters version=1.0.11
    Oct 06 13:35:31 Datura Haveno-Seednode[1395101]: Oct-06 13:35:31.307 [SeedNodeMain] WARN  h.core.app.misc.ExecutableForAppWithP2p: We did not find our node address in the seed nodes repository. We use a 24 hour delay after startup as shut down strategy.myAddress=5vycrhlbz44bpyvbh25b37joqj433wex7fn2d5hunp2bmxkv7ibk2vqd.o>
    Oct 06 13:35:31 Datura Haveno-Seednode[1395101]: Oct-06 13:35:31.307 [SeedNodeMain] INFO  haveno.core.app.misc.AppSetupWithP2P: onHiddenServicePublished
    Oct 06 13:35:31 Datura Haveno-Seednode[1395101]: Oct-06 13:35:31.337 [NetworkNode.connectionExecutor:SendMessage-to-4gmfgn22tll7...] INFO  haveno.network.p2p.network.NetworkNode: Socket creation to peersNodeAddress 4gmfgn22tll7ajw3tdp7nru3fvgh5ukt7w53kfv5ymijldivsqtbzdqd.onion:2003 took 2829 ms
    Oct 06 13:35:31 Datura Haveno-Seednode[1395101]: Oct-06 13:35:31.340 [NetworkNode.connectionExecutor:SendMessage-to-4gmfgn22tll7...] INFO  h.n.p.p.g.m.PreliminaryGetDataRequest: Sending a PreliminaryGetDataRequest with 112.833 kB and 5127 excluded key entries. Requesters version=1.0.11
    Oct 06 13:35:31 Datura Haveno-Seednode[1395101]: Oct-06 13:35:31.341 [NetworkNode.connectionExecutor:SendMessage-to-4gmfgn22tll7...] INFO  h.n.p.p.g.m.PreliminaryGetDataRequest: Sending a PreliminaryGetDataRequest with 112.833 kB and 5127 excluded key entries. Requesters version=1.0.11
    
    

then we do the same for the second haveno seednode:
    
    
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto]
    → vim /etc/systemd/system/haveno-seednode2.service
    
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto]
    → cat /etc/systemd/system/haveno-seednode2.service
    [Unit]
    Description=Haveno seednode 2
    After=network.target
    
    [Service]
    User=root
    Group=root
    SyslogIdentifier=Haveno-Seednode2
    
    ExecStart=/bin/sh /srv/haveno-reto/haveno-seednode --baseCurrencyNetwork=XMR_MAINNET\
      --useLocalhostForP2P=false\
      --useDevPrivilegeKeys=false\
    # Uncomment the following line to use external tor
      --hiddenServiceAddress=tqxmkjprxry7xwf2sdvy55etnkp6eddc4uxj5fd6rwpnc472mpizgqyd.onion\
      --nodePort=2003\
      --appName=haveno-XMR_MAINNET_Seed_2003\
    #  --logLevel=trace\
      --xmrNode=http://127.0.0.1:18081\
    #  --xmrNodeUsername=admin\
    #  --xmrNodePassword=password
    
    ExecStop=/bin/kill ${MAINPID}
    Restart=always
    
    # Hardening
    PrivateTmp=true
    ProtectSystem=full
    NoNewPrivileges=true
    PrivateDevices=true
    MemoryDenyWriteExecute=false
    ProtectControlGroups=true
    ProtectKernelTunables=true
    RestrictSUIDSGID=true
    # limit memory usage to 2gb
    LimitRSS=2000000000
    
    [Install]
    WantedBy=multi-user.target
    
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto]
    → systemctl daemon-reload
    
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto]
    → systemctl enable --now haveno-seednode2
    
    [ Datura ] [ /dev/pts/10 ] [/srv/haveno-reto]
    → systemctl status haveno-seednode2
    ● haveno-seednode2.service - Haveno seednode 2
         Loaded: loaded (/etc/systemd/system/haveno-seednode2.service; enabled; preset: enabled)
         Active: active (running) since Sun 2024-10-06 13:39:07 CEST; 5s ago
       Main PID: 1412193 (java)
          Tasks: 48 (limit: 77002)
         Memory: 298.5M
            CPU: 7.303s
         CGroup: /system.slice/haveno-seednode2.service
                 └─1412193 java -classpath /srv/haveno-reto/lib/seednode.jar:/srv/haveno-reto/lib/core.jar:/srv/haveno-reto/lib/p2p.jar:/srv/haveno-reto/lib/common.jar:/srv/haveno-reto/lib/proto.jar:/srv/haveno-reto/lib/assets.jar:/srv/haveno-reto/lib/guava-32.1.1-jre.jar:/srv/haveno-reto/lib/logback-classic-1.1.11.jar:/srv>
    
    Oct 06 13:39:12 Datura Haveno-Seednode2[1412193]: Filter: 7 / 14.044 kB
    Oct 06 13:39:12 Datura Haveno-Seednode2[1412193]: MailboxStoragePayload: 85 / 1.206 MB
    Oct 06 13:39:12 Datura Haveno-Seednode2[1412193]: Alert: 1 / 1.977 kB
    Oct 06 13:39:12 Datura Haveno-Seednode2[1412193]: Arbitrator: 2 / 4.43 kB
    Oct 06 13:39:12 Datura Haveno-Seednode2[1412193]: AccountAgeWitness: 3818 / 115.584 kB
    Oct 06 13:39:12 Datura Haveno-Seednode2[1412193]: OfferPayload: 117 / 318.363 kB
    Oct 06 13:39:12 Datura Haveno-Seednode2[1412193]: SignedWitness: 131 / 218.788 kB
    Oct 06 13:39:12 Datura Haveno-Seednode2[1412193]: TradeStatistics3: 1051 / 60.468 kB
    Oct 06 13:39:12 Datura Haveno-Seednode2[1412193]: #################################################################
    Oct 06 13:39:12 Datura Haveno-Seednode2[1412193]:
    Oct 06 13:39:13 Datura Haveno-Seednode2[1412193]: Oct-06 13:39:13.059 [Connection] INFO  h.network.p2p.storage.P2PDataStorage: Processing 212 protectedStorageEntries took 539 ms.
    	
    

Now from here you can test (from your computer, not from the server) if the haveno seednodes work as intended, by forcing your haveno client to use them:
    
    
    [ mainpc ] [ /dev/pts/19 ] [.local/share/Haveno-reto]
    → /opt/haveno/bin/Haveno --help | grep seedNodes
      --seedNodes=
    
    [ mainpc ] [ /dev/pts/19 ] [.local/share/Haveno-reto]
    → /opt/haveno/bin/Haveno --seedNodes=5vycrhlbz44bpyvbh25b37joqj433wex7fn2d5hunp2bmxkv7ibk2vqd.onion:2002,tqxmkjprxry7xwf2sdvy55etnkp6eddc4uxj5fd6rwpnc472mpizgqyd.onion:2003
    [...]
    
    

Then haveno launches as intended, and when you check into the network tab, you can see that it is bootstraping using your 2 seednodes, instead of the default ones:

![](1.png)

And from there, all you need to do is let the Haveno Network Administrators know that you are running some seed nodes. So as you need to reach out to the Reto network administrators, you can ping them on their [SimpleX chatroom.](https://simplex.chat/contact#/?v=2-4&smp=smp%3A%2F%2FSkIkI6EPd2D63F4xFKfHk7I1UGZVNn6k1QWZ5rcyr6w%3D%40smp9.simplex.im%2FMplYm7uxopKyUOrKqnWySpXQIGxoJWYB%23%2F%3Fv%3D1-2%26dh%3DMCowBQYDK2VuAyEAs8PcRwnf_-H30yXfwV0MSbka9I_xBeVNr4vKJNoReBw%253D%26srv%3Djssqzccmrcws6bhmn77vgmhfjmhwlyr3u7puw4erkyoosywgl67slqqd.onion&data=%7B%22type%22%3A%22group%22%2C%22groupLinkId%22%3A%22YT2t__GnjpZ1W2MjJAz6Sw%3D%3D%22%7D) From there you can ask them if they are willing to put your seed node in their repository, so that upon the next release, everyone that uses the Haveno Network will be able to use your 2 new nodes to bootstrap with.

_Disclaimer:_ i asked them and they aren't taking new seed nodes right now as there's no immediate need. so feel free to save this one for later.

