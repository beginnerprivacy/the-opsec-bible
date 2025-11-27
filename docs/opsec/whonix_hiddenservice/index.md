---
author: Nihilist
date: 2025-05-25
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/324"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
tags:
  - Serverside Anonymity
  - Self-Hosted
  - Core Tutorial
---
# Why should I use Whonix for Self-hosted Hidden services ?
```
TLDR: Whonix by itself provides the following :

- Impossible to leak an IP address
- Discovery and traffic analysis attacks
- TCP ISN CPU INformation Leak Protection
- Time Attack Defenses
```

Since the goal of self-hosting hidden services is to avoid revealing your home IP address, the IP address leak protection that Whonix provides is a paramount requirement. While this is not necessarily a concern when setting up hidden services on remote servers (VPSes) because the actual server's public IP address is not your home IP address anyway, **but when we're self hosting hidden services, IP Leaks becomes a main concern because an actual leak would lead to your home address directly**, hence the serverside Whonix VMs requirement.

## Targeted Setup:

![](../context/anon_self.png)

Our targeted setup depends on a [previous tutorial](../whonixqemuvms/index.md), to setup the whonix QEMU Vms you can follow the same steps as we detailed on the clientside.

![alt text](image.png)

For this targeted setup, we're going to re-use a set of QEMU Whonix VMs on our homeserver, the nginx service with the local website are going to sit on the whonix workstation, meanwhile the actual Tor daemon will remain on the Whonix Gateway. We're going to follow the [official whonix documentation](https://www.whonix.org/wiki/Onion_Services#Hidden_Webserver) to do this setup.

### Whonix Gateway Setup

First in the whonix gateway, we setup the hidden service :

```sh
[gateway user ~]% sudo vim /usr/local/etc/torrc.d/50_user.conf 
[gateway user ~]% sudo cat /usr/local/etc/torrc.d/50_user.conf
# Tor user specific configuration file
#
# Add user modifications below this line:
############################################

HiddenServiceDir /var/lib/tor/hidden_service/
HiddenServicePort 80 10.152.152.11:80
HiddenServiceVersion 3
```
Then, we restart the tor daemon and get the hidden service address:
```sh
[gateway user ~]% sudo systemctl restart tor@default
[gateway user ~]% sudo cat /var/lib/tor/hidden_service/hostname
4fqigk23qhaa47kk7g3yzmi4xiutvbl774dee2in2fdiekxnbyuia6yd.onion
```


### Whonix Workstation Setup

![alt text](image-1.png)

Once in the sysmaint session, we open up a terminal to setup the nginx webserver and configure it:

![alt text](image-2.png)

```sh
[workstation sysmaint ~]% sudo apt update -y ; sudo apt install nginx -y 

[workstation sysmaint ~]% cd /etc/nginx
[workstation sysmaint ~]% rm sites-*/default
[workstation sysmaint ~]% sudo vim sites-available/webservice
[workstation sysmaint ~]% cat sites-available/webservice

server {
        listen 80;
        listen [::]:80;
        server_name 4fqigk23qhaa47kk7g3yzmi4xiutvbl774dee2in2fdiekxnbyuia6yd.onion; 
        root /srv/webservice/;

}

:wq

[workstation sysmaint ~]% sudo ln -s /etc/nginx/sites-available/webservice /etc/nginx/sites-enabled/
[workstation sysmaint ~]% sudo nginx -t
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful

[workstation sysmaint ~]% sudo vim /srv/webservice/index.html
[workstation sysmaint ~]% cat /srv/webservice/index.html
welcome to my self-hosted hidden service!
[workstation sysmaint ~]% sudo systemctl restart nginx
[workstation sysmaint ~]% sudo systemctl enable --now nginx
[workstation sysmaint ~]% curl 127.0.0.1:80
welcome to my self-hosted hidden service!
```
Now that the webservice is functional locally, we need to make sure that the whonix workstation firewall allows the connection from the local IP 10.152.152.11, as otherwise the whonix gateway cant redirect the traffic to the webserver:

```sh
[workstation sysmaint ~]% curl 10.152.152.11:80
curl: (7) Failed to connect to 10.152.152.11 port 80 after 0 ms: Couldn't connect to server
zsh: exit 7 curl 10.152.152.11:80

[workstation sysmaint ~]% sudo -i
[workstation root ~]# mkdir -p /usr/local/etc/whonix_firewall.d
[workstation root ~]# vim /usr/local/etc/whonix_firewall.d/50_user.conf 
[workstation root ~]# cat /usr/local/etc/whonix_firewall.d/50_user.conf 
EXTERNAL_OPEN_PORTS+=" 80 "

[workstation root ~]# whonix_firewall
[workstation root ~]# UWT_DEV_PASSTHROUGH=1 curl 10.152.152.11:80
welcome to my self-hosted hidden service!
```
![alt text](image-3.png)

Now that the firewall has been configured correctly to allow the traffic to arrive on the local IP on port 80, we can test if the hidden service works as intended from the tor browser:
![alt text](image-4.png)

And it works! Now let's reboot the whonix workstation back into user mode since we finished the maintenance, and check if the hidden service still works as intended:

```sh
[workstation root ~]# reboot now
```
![alt text](image-5.png)

![alt text](image-6.png)

After rebooting the whonix workstation we see that it is still accessible as intended!

The point of going back into the regular user mode is that in case if the service were to get hacked, the whonix hardening features are going to make it impossible for the attacker to do anything. For example they can't get the onion hidden service keys because those sit on the Whonix gateway, rather than on the Workstation.

# Bonus: Shared folder on whonix workstation with the Host OS:

Since you can't copy paste from the host OS into the guest OS of the whonix workstation (it's intentional to prevent clipboard attacks), you're going to require to get files in and out of the whonix workstation VM from time to time, to do so, you need a shared folder between the Host and the Guest OS:

First power off the VM and enable shared memory:
![alt text](image-7.png)

Then create the shared folder on the host OS in /home/user/shared/:
```sh
[user ~]% mkdir /home/user/shared
[user ~]% chmod 777 /home/user/shared 
```

Then, click add hardware to add a new "filesystem" in the /home/user/shared folder, using the virtiofs driver:
![alt text](image-8.png)

Then for this example we're going to boot into the sysmaint user session and run the following commands:
![alt text](image-9.png)

From the Host OS:
```sh
[user ~/shared]% vim /home/user/shared/test2  
[user ~/shared]% cat /home/user/shared/test1  
Hello from whonix workstation !
```
From the whonix workstation vm:
```sh
[workstation sysmaint ~]% sudo -i
[workstation root ~]# cat mount.sh
mount -t virtiofs shared /mnt/shared
[workstation root ~]# vim /home/user/shared/test1  
[workstation root ~]# cat /home/user/shared/test1
Hello from Host OS
```

That way you'll be able to share files back and forth from inside the whonix workstation if you ever need it.