---
author: cynthia
date: 2025-08-14
gitea_url: "http://git.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/nihilist/blog-contributions/issues/404"
xmr: 84ybq68PNqKL2ziGKfkmHqAxu1WpdSFwV3DreM88DfjHVbnCgEhoztM7T9cv5gUUEL7jRaA6LDuLDXuDw24MigbnGqyRfgp
tags:
  - Clientside Anonymity
---

# Disguising Tor traffic with Cloak

```
TLDR: you can use cloak to access the Tor network from authoritarian regimes where VPNs are banned.
```

Tor is a great tool when it comes to bypassing internet restrictions or even being private/anonymous. This has made it very difficult for authoritarian nations to surveil or control their own citizens, so they have resorted to employing DPI infrastructures to sabotage usage of these tools or even catch users trying to use them.

![](0.png)

Luckily, Cloak is there to help! It forwards traffic between a port from a server running Cloak to a client, while disguising it as a regular HTTPS connection to throw off DPI detection.

![](1.png)

Cloak can be used to forward any port (such as from Tor's bridge port, or a WireGuard proxy), so it's not a full proxy solution and requires an underlying proxy program.

## Server Configuration

First of all, we need a VPS to host Cloak and all the other stuff we need to pass through on it. You can buy one from servers.guru or [any good VPS provider](https://kycnot.me/?categories=vps).

Getting and setting up a VPS is not related to this tutorial, so we won't touch on it here. We'll assume you have one with SSH access already working.

Download the latest release of [Cloak server](https://github.com/cbeuw/Cloak/releases) (`ck-server`) for your VPS's architecture. If you don't know what your VPS's CPU architecture is, you can use `uname -a` to check it.

```bash
root@debian-12:~# uname -a
Linux debian-12 6.1.0-37-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.140-1 (2025-05-22) x86_64 GNU/Linux
```

From this `uname -a` output, we can tell that our VPS is running x86_64 Linux (or also referred to as `amd64`). So we'll be downloading `ck-server-linux-amd64`.

```bash
root@debian-12:~# wget https://github.com/cbeuw/Cloak/releases/download/v2.12.0/ck-server-linux-amd64-v2.12.0 -O /usr/local/bin/ck-server
root@debian-12:~# chmod +x /usr/local/bin/ck-server
root@debian-12:~# setcap CAP_NET_BIND_SERVICE=+eip /usr/local/bin/ck-server
```

Create a new, dedicated user for hosting the Cloak server. This is just for security, as we don't need to run the server as a privileged user.

```bash
root@debian-12:~# useradd -M -s /usr/bin/false cloak
```

Create a directory in `/etc` for storing the Cloak configuration file.

```bash
root@debian-12:~# mkdir /etc/cloak
```

Create a `systemd` service file for the Cloak server.

```bash
root@debian-12:~# touch /etc/systemd/system/cloak-server.service
root@debian-12:~# chmod 664 /etc/systemd/system/cloak-server.service
root@debian-12:~# vim /etc/systemd/system/cloak-server.service
```

```ini
[Unit]
Description=Cloak server
After=network.target

[Service]
ExecStart=/usr/local/bin/ck-server -c /etc/cloak/server.json
User=cloak
Group=cloak

[Install]
WantedBy=multi-user.target
```

We can generate a private key by running `ck-server -key`. The public key should be given to the client.

```bash
root@debian-12:~# ck-server -key
Your PUBLIC key is:                      STzQhDyU5HzL8cbE9GyRnZSgoUWrcKbnTxu/QJ7TGDs=
Your PRIVATE key is (keep it secret):    8EXZs+aN24lo4ccRaU/N28ua0jQUKmdNCVfBQ1ynuU8=
```

We can also generate a UID for the client by running `ck-server -uid`

```bash
root@debian-12:~# ck-server -uid
Your UID is: e1leL4TP/cy3TEoWpXzA/A==
```

Now, we can configure the Cloak server by editing `/etc/cloak/server.json` (replace the UID in `BypassUID` and the private key in `PrivateKey` with your own output)

```bash
root@debian-12:~# vim /etc/cloak/server.json
```

```json
{
    "ProxyBook": {
        "tor": [
            "tcp",
            "127.0.0.1:9001"
        ],
        "wireguard": [
            "udp",
            "127.0.0.1:51820"
        ]
    },
    "BindAddr": [
        ":443",
        ":80"
    ],
    "BypassUID": [
        "e1leL4TP/cy3TEoWpXzA/A=="
    ],
    "RedirAddr": "cloudflare.com",
    "PrivateKey": "8EXZs+aN24lo4ccRaU/N28ua0jQUKmdNCVfBQ1ynuU8="
}
```

WireGuard is included here to demonstrate how it would be possible to forward more than one proxy port in Cloak, but we are not going to be showcasing it in this post.

After all this, we can now start the Cloak server.

```bash
root@debian-12:~# systemctl enable --now cloak-server.service
```

## Client Configuration

Download the [Cloak client](https://github.com/cbeuw/Cloak/releases) binary for your client's CPU architecture

```bash
root@client:~# wget https://github.com/cbeuw/Cloak/releases/download/v2.12.0/ck-client-linux-amd64-v2.12.0 -O /usr/local/bin/ck-client
root@client:~# chmod +x /usr/local/bin/ck-client
```

Create a new user for the Cloak client, just like in the server, and make a directory for the Cloak client configuration too.

```bash
root@client:~# useradd -M -s /usr/bin/false cloak
root@client:~# mkdir /etc/cloak
```

Create a systemd service file for the Cloak client. **Set the `<server_ip>` in the service file to your VPS' IP**

```bash
root@client:~# touch /etc/systemd/system/cloak-client.service
root@client:~# chmod 664 /etc/systemd/system/cloak-client.service 
root@client:~# vim /etc/systemd/system/cloak-client.service
```

```ini
[Unit]
Description=Cloak client
After=network.target

[Service]
ExecStart=/usr/local/bin/ck-client -c /etc/cloak/client.json -s <server_ip>
User=cloak
Group=cloak

[Install]
WantedBy=multi-user.target
```

Configure the Cloak client with the server's public key and the client UID we generated before when we set the server up.

```bash
root@client:~# vim /etc/cloak/client.json
```

```json
{
    "UID": "e1leL4TP/cy3TEoWpXzA/A==",
    "ServerName": "cloudflare.com",
    "PublicKey": "STzQhDyU5HzL8cbE9GyRnZSgoUWrcKbnTxu/QJ7TGDs=",
    "EncryptionMethod": "chacha20-poly1305",
    "BrowserSig": "chrome",
    "ProxyMethod": "<set_proxy_name>"
}
```

**Note that `ProxyMethod` is required to be set to one of the entries in the server's `ProxyBook`. The setting determines what port Cloak will forward over. Cloak can only forward one port at a time.**

Enable and activate the Cloak client after all this.

```bash
root@client:~# systemctl enable --now cloak-client.service
```

## Tor

We're gonna host a Tor bridge relay in the server, that will be forwarded through Cloak and used by the client.

### Server

Install Tor on the VPS.

```bash
root@debian-12:~# apt install tor obfs4proxy
```

Configure Tor to host a private bridge.

```bash
root@debian-12:~# vim /etc/tor/torrc
```

```
SocksPort 0 # Optional, This will disable Tor's SOCKS port
BridgeRelay 1
PublishServerDescriptor 0
ORPort 127.0.0.1:9001
```

Restart Tor (if you already have it started and enabled)

```bash
root@debian-12:~# systemctl restart tor
```

Since we've already listed the port in our `server.json` (`ProxyBook`), the bridge port will already be available to clients.

### Client

Set the `ProxyMethod` in `/etc/cloak/client.json` to `tor`. This will configure Cloak to forward over the Tor bridge port

```bash
root@client:~# vim /etc/cloak/client.json
```

```
    "ProxyMethod": "tor"
```

Restart the Cloak client

```bash
root@client:~# systemctl restart cloak-client.service
```

Open up the Tor Browser, you may see this page when it hasn't connected yet.

Click on **Configure Connection...**

![](tor1.png)

Scroll down until you see the **Bridges** section, and click on **Add new bridges...**

![](tor2.png)


Since Cloak listens on port 1984 locally by default, type `127.0.0.1:1984` in the bridge addresses and click **Next**

![](tor3.png)

Click **Connect**

![](tor4.png)

If the Tor Browser managed to connect, congrats! You've managed to bypass DPI blocks using Cloak.

![](tor5.png)
