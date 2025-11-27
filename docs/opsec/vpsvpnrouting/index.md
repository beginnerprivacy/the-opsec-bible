---
author: Nihilist
date: 2025-06-08
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/320"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
tags:
    - Serverside Privacy
    - Self-Hosting
---

# How to hide your self-hosted service's home IP from the end users 

```
TLDR: When hosting clearnet services you normally deanonymize yourself since the home server is accessed via your home router's public IP. To prevent that you can make your home server connect via VPN to a remote VPS that has nginx installed on it to redirect the traffic to your self-hosted clearnet services.
```

## Why is this setup important ?

Suppose you have a server at home and you have a nginx service on it:

![alt text](image-2.png)

If you intend that local webserver to be a public clearnet service, normally you'd need to port-forward it via your home router to be able to allow remote users to reach it.


## What do we need for this setup ?

You're going to need the following:
- [a home server with a local webserver running](../hypervisor_selfhosted/index.md)
- [A remote server (VPS)](../anonymousremoteserver/index.md)
- [a clearnet domain](../anondomain/index.md)

We recommend using [Monero](../monerowallet/index.md) to pay for your remote servers and domains, to support the [Monero Circular Economy](../monerofirst/index.md) as much as possible.

## Targeted Setup

The setup we are targeting is the following:

![alt text](image-3.png)

We're going to connect the homeserver to the remote VPS via OpenVPN, and we're going to make it so that the remote VPS's nginx is configured to make sure that we can reach our local nginx webserver with it. 

## Serverside Remote Setup : Openvpn server 

First we log on the VPS, to install the openvpn server using agristan's openvpn install script:
```sh
root@remoteserver ~ # curl -O https://raw.githubusercontent.com/angristan/openvpn-install/master/openvpn-install.sh
root@remoteserver ~ # chmod +x openvpn-install.sh

root@remoteserver ~ # ./openvpn-install.sh
Welcome to the OpenVPN installer!
The git repository is available at: https://github.com/angristan/openvpn-install

I need to ask you a few questions before starting the setup.
You can leave the default options and just press enter if you are okay with them.

I need to know the IPv4 address of the network interface you want OpenVPN listening to.
Unless your server is behind NAT, it should be your public IPv4 address.
IP address: 65.199.39.253

Checking for IPv6 connectivity...
```

```sh
Do you want to enable IPv6 support (NAT)? [y/n]: n

What port do you want OpenVPN to listen to?
   1) Default: 1194
   2) Custom
   3) Random [49152-65535]
Port choice [1-3]: 1

What protocol do you want OpenVPN to use?
UDP is faster. Unless it is not available, you shouldn't use TCP.
   1) UDP
   2) TCP
Protocol [1-2]: 1

What DNS resolvers do you want to use with the VPN?
   1) Current system resolvers (from /etc/resolv.conf)
   2) Self-hosted DNS Resolver (Unbound)
   3) Cloudflare (Anycast: worldwide)
   4) Quad9 (Anycast: worldwide)
   5) Quad9 uncensored (Anycast: worldwide)
   6) FDN (France)
   7) DNS.WATCH (Germany)
   8) OpenDNS (Anycast: worldwide)
   9) Google (Anycast: worldwide)
   10) Yandex Basic (Russia)
   11) AdGuard DNS (Anycast: worldwide)
   12) NextDNS (Anycast: worldwide)
   13) Custom
DNS [1-12]: 11

Do you want to use compression? It is not recommended since the VORACLE attack makes use of it.
Enable compression? [y/n]: n

Do you want to customize encryption settings?
Unless you know what you're doing, you should stick with the default parameters provided by the script.
Note that whatever you choose, all the choices presented in the script are safe (unlike OpenVPN's defaults).
See https://github.com/angristan/openvpn-install#security-and-encryption to learn more.

Customize encryption settings? [y/n]: n

Okay, that was all I needed. We are ready to setup your OpenVPN server now.
You will be able to generate a client at the end of the installation.
Press any key to continue...
```

Then let it install the openvpn server as intended, then we need to create the client in the openvpn server directly, where we mention that its for the selfhosted-privatevm client:

```sh
Tell me a name for the client.
The name must consist of alphanumeric character. It may also include an underscore or a dash.
Client name: selfhosted-privatevm

Do you want to protect the configuration file with a password?
(e.g. encrypt the private key with a password)
   1) Add a passwordless client
   2) Use a password for the client
Select an option [1-2]: 1

```

From there the openvpn install script finished the serverside setup, and as we can see it created the openvpn client file for the privatevm in the root directory:

```sh
root@remoteserver ~ # cat selfhosted-privatevm.ovpn
client
proto udp
explicit-exit-notify
remote 65.199.39.253 1194
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name server_vCg0SCcC1z7L5umn name
auth SHA256
auth-nocache
cipher AES-128-GCM
tls-client
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
ignore-unknown-option block-outside-dns
setenv opt block-outside-dns # Prevent Windows 10 DNS leak


verb 3
<ca>
-----BEGIN CERTIFICATE-----
[REDACTED]
---END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
[REDACTED]
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
[REDACTED]
-----END PRIVATE KEY-----
</key>
<tls-crypt>
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
[REDACTED]
-----END OpenVPN Static key V1-----
</tls-crypt>
```

Before we go forward, i recommend to edit it to avoid redirecting all traffic from the client to the server, since it's only a matter of enabling remote accesses, rather than using the openvpn as an actual clientside VPN:

```sh
root@remoteserver ~ # vim selfhosted-privatevm.ovpn
root@remoteserver ~ # cat selfhosted-privatevm.ovpn

[...]

ignore-unknown-option block-outside-dns
setenv opt block-outside-dns # Prevent Windows 10 DNS leak


### DONT REDIRECT ALL TRAFFIC VIA THE VPS ###
pull-filter ignore "redirect-gateway"
#############################################

verb 3

[...]

```

## Serverside Self-hosted PrivateVM Setup : OpenVPN client

Now that the openvpn server is setup properly we can log on the private vm that we [previously](../hypervisor_selfhosted/index.md) setup on our homeserver:
```sh
user@clientside ~ $ ssh privatevm

Linux localhost 6.1.0-34-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.135-1 (2025-04-25) x86_64
Welcome to Kicksecure (TM)!
https://www.kicksecure.com

Kicksecure Copyright (C) 2012 - 2025 ENCRYPTED SUPPORT LLC
Kicksecure is Freedom Software, and you are welcome to redistribute it under
certain conditions; type "kicksecure-license" <enter> for details.
Kicksecure is a compilation of software packages, each under its own copyright and
license. The exact license terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Kicksecure GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law; for details type "kicksecure-disclaimer" <enter>.

Kicksecure is a derivative of Debian GNU/Linux.

Kicksecure is a research project.

default user account: user
default password: No password required. (Passwordless login.)

Type: "kicksecure" <enter> for help.

user@privatevm_selfhosted:~% curl 127.0.0.1
welcome to the privatevm web server!

user@privatevm_selfhosted:~%
```

From there, we install openvpn and import the openvpn client file:

```sh
user@privatevm_selfhosted:~% sudo apt install openvpn
[sudo] password for user: ********************

user@privatevm_selfhosted:~% cat privatevm_selfhosted.ovpn
client
proto udp
explicit-exit-notify
remote 65.199.39.253 1194
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name server_vCg0SCcC1z7L5umn name
auth SHA256
auth-nocache
cipher AES-128-GCM
tls-client
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
ignore-unknown-option block-outside-dns
setenv opt block-outside-dns # Prevent Windows 10 DNS leak

### DONT REDIRECT ALL TRAFFIC VIA THE VPS ###
pull-filter ignore "redirect-gateway"
#############################################

verb 3
<ca>
```

From there, we can create the following systemd service to make sure that the openvpn service stays connected in the background:

```sh
user@privatevm_selfhosted:~% sudo vim /etc/systemd/system/vpn.service
user@privatevm_selfhosted:~% sudo cat /etc/systemd/system/vpn.service

[Unit]
Description=VPN
After=network-online.target
Wants=network-online.target

[Install]
WantedBy=multi-user.target

[Service]
Type=simple
ExecStart=/usr/sbin/openvpn /home/user/privatevm_selfhosted.ovpn
ExecStop=kill -9 $(pidof openvpn)
Restart=always

user@privatevm_selfhosted:~% sudo systemctl daemon-reload
user@privatevm_selfhosted:~% sudo systemctl enable --now
```

From there, you can check if the VPN connection was successful:

```sh
user@privatevm_selfhosted:~% ip a

[...]

3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500
    link/none
    inet 10.8.0.2/24 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::71c7:e80c:740f:7db5/64 scope link stable-privacy
       valid_lft forever preferred_lft forever
```

Here as you can see, the private VM has the 10.8.0.2 IP on the new tun0 interface that was created by openvpn, which indicates that it works as intended. Let's see if we can ping the remote server aswell via the VPN tunnel directly, via it's 10.8.0.1 IP:

```sh
user@privatevm_selfhosted:~% ping 10.8.0.1
PING 10.8.0.1 (10.8.0.1) 56(84) bytes of data.
64 bytes from 10.8.0.1: icmp_seq=1 ttl=64 time=48.5 ms
64 bytes from 10.8.0.1: icmp_seq=2 ttl=64 time=48.2 ms
64 bytes from 10.8.0.1: icmp_seq=3 ttl=64 time=47.6 ms
```

There you go! we just validated that both servers can now communicate with each other.

## Serverside Remote Setup : Nginx reverse proxy

You can also test from the remote server if you can access the openvpn client via it's 10.8.0.2 IP:
```sh
root@remoteserver ~ # curl 10.8.0.2
welcome to the privatevm web server!
```

Now that the connection between the 2 servers has been correctly established via openvpn, we'll setup nginx on the remote server and configure it to act like a reverse proxy to make sure that the self-hosted web service is accessible from the outside, without revealing your home public IP to the end users:

```sh
root@remoteserver ~ # sudo apt install nginx -y
root@remoteserver ~ # cd /etc/nginx
root@remoteserver ~ # rm sites-*/default
root@remoteserver ~ # vim /etc/nginx/sites-available/rproxy-selfhosted-privatevm.conf
root@remoteserver ~ # cat /etc/nginx/sites-available/rproxy-selfhosted-privatevm.conf
server {
    listen 80;
    listen [::]:80;

    server_name test.yourdoma.in;

    location / {
        proxy_pass http://10.8.0.2:80/;
    }
}
root@remoteserver ~ # ln -s /etc/nginx/sites-available/rproxy-selfhosted-privatevm.conf /etc/nginx/sites-enabled/
root@remoteserver ~ #  nginx -t
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful

root@remoteserver ~ # nginx -s reload
```

## Testing from the Clientside

And now that the nginx service has been setup on the remote server to act like a reverse proxy, let's test if we can access the self-hosted web server as intended:

```sh
user@privatevm_clientside:~% curl http://test.yourdoma.in:80
welcome to the privatevm web server!

```

![alt text](image-1.png)

And that's it! Now to highlight why this setup is important, as an end user, when i try to see what the public IP of the service is, i can only see that it is this remote server:

```sh
user@privatevm_clientside:~% ping test.nowhere.moe
PING test.nowhere.moe (65.199.39.253) 56(84) bytes of data.
64 bytes from test.nowhere.moe (65.199.39.253): icmp_seq=1 ttl=56 time=61.8 ms

```

This is ideal because that way you are hiding your home public IP from your end users as intended. Unlike how it would have been in case if you had port-forwarded your self-hosted services via your home router, which would've exposed your house public IP.

