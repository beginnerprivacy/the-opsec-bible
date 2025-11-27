---
author: cynthia
date: 2025-06-05
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/311"
xmr: 84ybq68PNqKL2ziGKfkmHqAxu1WpdSFwV3DreM88DfjHVbnCgEhoztM7T9cv5gUUEL7jRaA6LDuLDXuDw24MigbnGqyRfgp
tags:
    - Clientside Privacy
---
# DoT, DoH, DNSCrypt, DNS over Tor and Local DNS: What actually protects you?

```
TLDR: DNS is also an important part of your attack surface. 
```

DNS is the most common way to resolve domain names into IP addresses. It's a pretty old protocol that still works, albeit with some shortcomings that have plagued the protocol over the years. The protocol lacks any encryption which allows any 3rd party with access to your connection (such as your ISP, etc.) to easily spy on DNS queries or even intercept and replace DNS responses to sabotage access to certain websites.
Several solutions have popped up over the years to fix these issues, These mostly just act as wrappers around the DNS protocol in a way. This blogpost will measure the advantages and disadvantages of these solutions, and also offer a guide on how to set up each of them.
This blogpost includes: DNS over TLS (DoT), DNS over HTTPS (DoH), DNSCrypt, DNS over Tor/DNS over VPN and Local DNS

## Introductions to all the DNS protocols

**NOTE**: The interceptor in the graphs may not be reflective of a interceptor in a real situation. While we've tried to make the interceptor reflective of most DPIs and situations involving them, there are several factors (such as TLS fingerprint, etc.) that may allow for protocol identification.

### DNS over TLS (DoT)
![](1.png)

DNS over TLS is (one of) the first RFC-standard DNS encryption wrappers, wrapping the protocol around the Transport Layer Security, other than that, it's fairly simple. The problems that it has is that it has its own standard port number, which makes it easy to tell to a 3rd party that you are using DNS over TLS, and that it's slower, since it has to run over TCP rather than UDP.

### DNS over HTTPS (DoH)
![](2.png)

DNS over HTTPS is the more newer RFC-standard DNS encryption wrapper, which wraps the protocol around HTTPS and uses 443 on TCP. The benefits are about the same as DNS over TLS, except that the fact that DNS is transmitted over HTTPS makes the protocol much harder to block than DNS over TLS (DoT) due it blending in with regular HTTPS traffic. ISPs and DPIs have to resort to blocking IPs associated with common DoH servers (which does not block DoH as a whole).

### DNSCrypt
![](3.png)

DNSCrypt is the oldest DNS encryption wrapper protocol, It is more optimized for speed than DoT and DoH and uses 443 on TCP/UDP (same port as HTTPS). The port number helps obfuscate the protocol at a basic level from ISPs and other MiTMs from detecting the usage of the protocol (although it won't help against DPIs). DNSCrypt also has a feature called Anonymized DNS which we will be talking in the next sub-section.

#### Anonymized DNS
![](4.png)

Anonymized DNS is a relay system in DNSCrypt where your DNS queries and responses are relayed through a DNSCrypt relay server, so that the DNSCrypt resolver is not able to tell where the queries came from (granted if the relay and resolver are both not owned or associated with each other). This allows for anonymous, yet still fast DNS queries.

### DNS over Tor
![](5.png)

DNS over Tor is simply the act of routing your DNS queries over Tor. Since Tor does not support UDP (which DNS uses), it's done using a special feature in the Tor daemon which hosts a DNS port locally that resolves domain names over at the exit node's resolver. Although the DNS data is encrypted during transit through the Tor relays, it will most likely end up unencrypted during the transmission between the exit node and the exit node's DNS server, which will allow for any 3rd parties spying on the exit node's traffic to be able to look at (or even tamper with) your DNS query and responses. But, due to the nature of Tor, it may still be anonymous.

### DNS over VPN
![](6.png)

DNS over VPN is the act of routing your DNS queries over a VPN, This has about the same advantages and disadvantages as DNS over Tor (provided that the benefit of anonymity is dependent on the VPN you're using). For the sake of the ratings table below, we'll be referring to both DNS over Tor and DNS over VPN as DNS over Tor/VPN.

### Local DNS
![](7.png)

Local DNS is the act of hosting a DNS server locally rather than using a public one on the Internet, This doesn't provide any privacy or anonymity benefits whatsoever other than the fact that the initial query (and the device who made it) is private inside your LAN.

Since DNS is unencrypted, The recursive queries that the DNS server makes to authoritative DNS servers is visible to any 3rd parties spying over your traffic, which exposes what domain you are looking for.

The only reason you should be doing this is to host a PiHole or a DNS server that blocks away analytics domains, but for the sake of this blogpost, we'll be referring to a regular local DNS (with no blocking capabilities).

## DNS protocol ratings
First of all, if we were to figure out which of these protocols protects us, we'll need some way to measure how well they perform. We will be measuring each of the following abilities:
* Encryption: Whether the DNS queries and responses are fully end-to-end encrypted (from user to the DNS server, including the Tor nodes/VPN node in-between)
* Detectability: Whether a 3rd party adversary (such as the user's ISP) can detect and distinguish usage of the protocol from the rest of the user's traffic.
* Anonymity: Whether the protocol offers anonymity protection for the user.

| Abilities     | DNS over TLS                    | DNS over HTTPS                    | DNSCrypt                        | DNS over Tor/VPN | Local DNS |
|---------------|---------------------------------|-----------------------------------|---------------------------------|------------------|-----------|
| Encryption    | ✅ The protocol uses TLS between the user and the DNS server. | ✅ The protocol uses TLS or SSL between the user and the DNS server. | ✅ The protocol uses a custom encryption protocol between the user and the DNS server. | ✳️ Although the connection between the user and the Tor node/VPN is encrypted, DNS is unencrypted so the exit node or VPN server can see queries and responses |  ❎️ Although a 3rd party adversary cannot intercept a local DNS server, they can look at the authoritative DNS queries that the server makes |
| Detectability | ❎️The protocol has its own standard port (853/TCP) which makes it super easy to detect for a 3rd party | ✅ The protocol blends in with HTTPS traffic, which makes it much harder to detect | ✳️ Although DNSCrypt listens on port 443 (UDP/TCP, the same port as HTTPS) which makes surface-level detection much harder, the use of a custom protocol may allow for detection on DPIs that are written to distinguish DNSCrypt's protocol from TLS/SSL protocol | ✅ A 3rd party adversary would not be able to detect DNS usage from the Tor/VPN traffic | ✅ The traffic from the local DNS server appears just like any other DNS query |
| Anonymity     | ✳️ The protocol does not offer built-in anonymity protection, but it can be used over Tor. | ✳️ The protocol does not offer built-in anonymity protection, but it can be used over Tor. | ✅ DNSCrypt has a feature called Anonymized DNS, where instead of connecting to a DNSCrypt server directly, a user can connect through a relay DNSCrypt server to relay data over to that server. | ✅ Tor offers anonymity protection (maybe same thing for VPN but a little different) | ❎️ Unencrypted authoritative DNS queries (done by the local DNS server) can allow the user to be deanonymized by a 3rd party adversary |

In conclusion:

* If you want speed and privacy, use DNSCrypt
* If you want to be 100% undetectable, use DNS-over-HTTPS
* If you want anonymity, use DNS over Tor or Anonymized DNS in DNSCrypt

## How to set up

### DNS over TLS

For most Debian-like distributions, systemd-resolved may already be used and pre-installed.

1. Install `systemd-resolved`, if not installed already.

    ```bash
    root@localhost:~# apt install systemd-resolved
    ```

2. Enable `systemd-resolved`, if not enabled already.

    ```bash
    root@localhost:~# systemctl enable --now systemd-resolved
    ```

3. Edit `systemd-resolved`'s configuration file to use DNS-over-TLS and a DoT server of your choice.

    ```bash
    root@localhost:~# vim /etc/systemd/resolved.conf
    ```

    This example configuration will use Quad9's DoT server.

    ```ini
    [Resolve]
    DNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net 2620:fe::fe#dns.quad9.net 2620:fe::9#dns.quad9.net
    DNSSEC=yes
    DNSOverTLS=yes
    Domains=~.
    ```

4. Restart `systemd-resolved` to use the new configuration.

    ```bash
    root@localhost:~# systemctl restart systemd-resolved
    ```

### DNS over HTTPS and DNSCrypt

We'll be using `dnscrypt-proxy` for this section of the tutorial, which offers support for both DNS over HTTPS and DNSCrypt.

1. Create a directory for `dnscrypt-proxy`, This can be anywhere from your home directory to a directory in /opt.
    We'll be creating `/opt/dnscrypt-proxy` in this tutorial.

    ```bash
    root@localhost:~# mkdir -p /opt/dnscrypt-proxy
    root@localhost:~# cd /opt/dnscrypt-proxy/
    ```

2. Install `curl`, if not installed already. We will use this to download files.

    ```bash
    root@localhost:/opt/dnscrypt-proxy# apt install curl
    ```

3. Download a prebuilt version of `dnscrypt-proxy`, You can pick which CPU architecture is in your system from [the list of dnscrypt-proxy binaries](https://github.com/jedisct1/dnscrypt-proxy/releases/latest)
    We'll be downloading 2.1.12 for x86_64 in this tutorial.

    Example:

    ```bash
    root@localhost:/opt/dnscrypt-proxy# curl -L -O https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/2.1.12/dnscrypt-proxy-linux_x86_64-2.1.12.tar.gz
    ```
4. (Optional) Download and verify the minisign signature of the tar file

    Install minisign and download the minisig file for the binary you downloaded

    Example:

    ```bash 
    root@localhost:/opt/dnscrypt-proxy# apt install minisign
    root@localhost:/opt/dnscrypt-proxy# curl -L -O https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/2.1.12/dnscrypt-proxy-linux_x86_64-2.1.12.tar.gz.minisig
    ```

    Verify the minisig file with the official `dnscrypt-proxy` public key

    ```bash
    root@localhost:/opt/dnscrypt-proxy# minisign -Vm dnscrypt-proxy-*.tar.gz -P RWTk1xXqcTODeYttYMCMLo0YJHaFEHn7a3akqHlb/7QvIQXHVPxKbjB5
    ```

    If everything is fine, it should say: `Signature and comment signature verified`

5. Extract the tar file. All the files should be in a sub-directory in the tar file, so files have to be moved back to the current directory.

    Example:
    ```bash
    root@localhost:/opt/dnscrypt-proxy# tar -xvf dnscrypt-proxy-linux_x86_64-2.1.12.tar.gz
    root@localhost:/opt/dnscrypt-proxy# mv linux-x86_64/* .
    root@localhost:/opt/dnscrypt-proxy# rmdir linux-x86_64
    ```
6. Disable any other DNS resolvers currently running. You can check with `ss -lp 'sport = :domain'`.
    Our example machine is currently running `systemd-resolved`, so we will disable and stop that.

    ```bash
    root@localhost:/opt/dnscrypt-proxy# systemctl stop systemd-resolved
    root@localhost:/opt/dnscrypt-proxy# systemctl disable systemd-resolved
    ```

7. Copy the example configuration file, and start `dnscrypt-proxy` to see if it works. It should work out of the box.

    ```bash
    root@localhost:/opt/dnscrypt-proxy# cp example-dnscrypt-proxy.toml dnscrypt-proxy.toml
    root@localhost:/opt/dnscrypt-proxy# ./dnscrypt-proxy 
    ```

8. While `dnscrypt-proxy` is running, back up `/etc/resolv.conf` and create a new one using `dnscrypt-proxy`'s DNS port

    ```bash
    root@localhost:/opt/dnscrypt-proxy# mv /etc/resolv.conf /etc/resolv.conf.bak
    root@localhost:/opt/dnscrypt-proxy# vim /etc/resolv.conf
    ```

    The contents of `/etc/resolv.conf` should be written like this:

    ```
    nameserver 127.0.0.1
    options edns0
    ```
    Afterwards, test if `dnscrypt-proxy` is working by resolving `example.com` with it.

    ```bash
    root@localhost:/opt/dnscrypt-proxy# ./dnscrypt-proxy -resolve example.com
    ```

    If it was able to resolve `example.com`, congratulations, `dnscrypt-proxy` is now working.

9. Close the running `dnscrypt-proxy`, install it as a service and start it up!

    ```bash
    root@localhost:/opt/dnscrypt-proxy# ./dnscrypt-proxy -service install
    root@localhost:/opt/dnscrypt-proxy# ./dnscrypt-proxy -service start
    ```

    Now we are onto configuring `dnscrypt-proxy` to use DoH and/or DNSCrypt.

10. (Optional) Tinker with the configuration file. The file is extensively commented, and has a lot of stuff you can mess around with.

    ```bash
    root@localhost:/opt/dnscrypt-proxy# vim dnscrypt-proxy.toml
    ```

    For example, you can enable/disable DoH or DNSCrypt at around line 68-72. By default, they both should be enabled like this:

    ```toml
    # Use servers implementing the DNSCrypt protocol
    dnscrypt_servers = true

    # Use servers implementing the DNS-over-HTTPS protocol
    doh_servers = true
    ```

    Resolvers and relays can also be optionally configured at line 749-773. By default, it uses signed lists downloaded from `dnscrypt-proxy`'s official resolver/relay sources:

    ```toml
    [sources]

    ### An example of a remote source from https://github.com/DNSCrypt/dnscrypt-resolvers

    [sources.public-resolvers]
    urls = [
        'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md',
        'https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md',
    ]
    cache_file = 'public-resolvers.md'
    minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
    refresh_delay = 73
    prefix = ''

    ### Anonymized DNS relays

    [sources.relays]
    urls = [
        'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md',
        'https://download.dnscrypt.info/resolvers-list/v3/relays.md',
    ]
    cache_file = 'relays.md'
    minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
    refresh_delay = 73
    prefix = ''
    ```

11. If any configuration was done, `dnscrypt-proxy` can always be restarted with the following command:

    ```bash
    root@localhost:/opt/dnscrypt-proxy# ./dnscrypt-proxy -service restart
    ```

#### Configuring Anonymized DNS

`dnscrypt-proxy` can be configured to connect through relays to send DNS queries to a resolver.
You can define routes with `routes` in `[anonymized_dns]` in the configuration file (which is located at line 869), which relays to use for a specific server.

You can look at a list of relays and resolvers to use at https://dnscrypt.info/public-servers/

For example, here's an example configuration routing DNS queries through either the `anon-cs-vancouver` or `anon-inconnu` relay to the `cs-ore` resolver.

```toml
[anonymized_dns]
routes = [
    { server_name='cs-ore', via=['anon-cs-vancouver', 'anon-inconnu'] }
]
```

You can define as many routes as you want, with their own set of relays.

```toml
[anonymized_dns]
routes = [
    { server_name='example-server-1', via=['anon-example-1', 'anon-example-2'] },
    { server_name='example-server-2', via=['anon-example-3'] },
    { server_name='example-server-3', via=['anon-example-1'] }
]
```

You can also use wildcards in the `server_name` and/or `via`, to use a random resolver and/or relay for Anonymized DNS (`dnscrypt-proxy` will avoid trying to use a relay and resolver both on the same network).

```toml
[anonymized_dns]
routes = [
    { server_name='example-server-1', via=['*'] },

    # Or this:

    { server_name='*', via=['anon-example-1'] },

    # Or this:

    { server_name='*', via=['*'] }
]
```

### DNS over Tor

1. Install Tor.

    ```bash
    root@localhost:~# apt install tor
    ```

2. Enable Tor, if not enabled already.

    ```bash
    root@localhost:~# systemctl enable --now tor
    ```

3. Edit Tor's configuration file to make it listen locally on a DNS port.

    ```bash
    root@localhost:~# vim /etc/tor/torrc
    ```

    Add this at the end of the file:

    ```
    DNSPort 53
    ```
4. Disable any other DNS resolvers currently running. You can check with `ss -lp 'sport = :domain'`.
    Our example machine is currently running `systemd-resolved`, so we will disable and stop that.

    ```bash
    root@localhost:~# systemctl stop systemd-resolved
    root@localhost:~# systemctl disable systemd-resolved
    ```
5. Backup the existing `resolv.conf`, and make a new one configuring the system to resolve DNS queries through Tor
    ```bash
    root@localhost:~# mv /etc/resolv.conf /etc/resolv.conf.bak
    root@localhost:~# vim /etc/resolv.conf
    ```

    The contents of `/etc/resolv.conf` should be written like this:

    ```
    nameserver 127.0.0.1
    ```

6. Restart Tor.

    ```bash
    root@localhost:~# systemctl restart tor
    ```

7. Now try pinging a site to test out if the Tor DNS works.

    ```bash
    root@localhost:~# ping example.com
    PING example.com (23.192.228.80) 56(84) bytes of data.
    64 bytes from a23-192-228-80.deploy.static.akamaitechnologies.com (23.192.228.80): icmp_seq=1 ttl=255 time=190 ms
    64 bytes from 23.192.228.80 (23.192.228.80): icmp_seq=2 ttl=255 time=190 ms
    ```

    If you get something like the above, then congratulations, Tor's DNS is now working.

    If it doesn't work or says something like `ping: example.com: Temporary failure in name resolution`, try restarting Tor and try again.

### Local DNS

We'll be using `unbound` as our DNS resolver server.

1. Install `unbound`

    ```bash
    root@localhost:~# apt install unbound
    ```

2. Disable any other DNS resolvers currently running. You can check with `ss -lp 'sport = :domain'`.
    Our example machine is currently running `systemd-resolved`, so we will disable and stop that.

    ```bash
    root@localhost:~# systemctl stop systemd-resolved
    root@localhost:~# systemctl disable systemd-resolved
    ```

3. Backup the existing `resolv.conf`, and make a new one configuring the system to resolve DNS queries through Tor
    ```bash
    root@localhost:~# mv /etc/resolv.conf /etc/resolv.conf.bak
    root@localhost:~# vim /etc/resolv.conf
    ```

    The contents of `/etc/resolv.conf` should be written like this:

    ```
    nameserver 127.0.0.1
    ```
4. Start up unbound.

    ```bash
    root@localhost:~# systemctl enable --now unbound
    ```

5. Now try pinging a site to test out if the local DNS works. It may be slow at first for a domain name, but all subsequent queries for the same domain will be much faster.

    ```bash
    root@localhost:~# ping example.com
    PING example.com (96.7.128.175) 56(84) bytes of data.
    64 bytes from a96-7-128-175.deploy.static.akamaitechnologies.com (96.7.128.175): icmp_seq=1 ttl=255 time=198 ms
    64 bytes from a96-7-128-175.deploy.static.akamaitechnologies.com (96.7.128.175): icmp_seq=2 ttl=255 time=197 ms
    ```

    If you get something like the above, then congratulations, unbound is now working.

    If it doesn't work or says something like `ping: example.com: Temporary failure in name resolution`, try restarting unbound and try again.
