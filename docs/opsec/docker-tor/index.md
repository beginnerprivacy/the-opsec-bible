---
author: Anonymous
date: 2025-01-31
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/432"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
---
# How to use Docker containers on the whonix workstation

```
TLDR: you can use also use Docker on Whonix, forcing their connections to go through Tor.
```

## How to install Docker

As usual we install docker according to [this tutorial](../docker-intro/index.md#installation).

## How to make sure that Docker pulls images through Tor

```sh
[workstation user ~]% sudo docker pull alpine
Using default tag: latest
Error response from daemon: Get "https://registry-1.docker.io/v2/": dial tcp: lookup registry-1.docker.io on 10.152.152.10:53: read udp 10.152.152.11:33883->10.152.152.10:53: i/o timeout
zsh: exit 1     sudo docker pull alpine
```
Here as you can see when we try to pull an alpine image, docker can't pull it, to fix that we need to make sure that docker pulls through the localhost tor socks5 proxy on port 9050:

```sh
[workstation user ~]% sudo mkdir /etc/systemd/system/docker.service.d/          
[workstation user ~]% sudo vim /etc/systemd/system/docker.service.d/proxy.conf
[workstation user ~]% cat /etc/systemd/system/docker.service.d/proxy.conf
[Service]
Environment="HTTP_PROXY=socks5://127.0.0.1:9050"
Environment="HTTPS_PROXY=socks5://127.0.0.1:9050"
```

Now that's created, we reload the systemd service and try to pull the alpine docker image again:
```sh
[workstation user ~]% sudo systemctl daemon-reload                            
[workstation user ~]% sudo systemctl restart docker
[workstation user ~]% docker pull alpine
Using default tag: latest
permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Post "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/images/create?fromImage=alpine&tag=latest": dial unix /var/run/docker.sock: connect: permission denied
zsh: exit 1     docker pull alpine
[workstation user ~]% sudo !!                      
[workstation user ~]% sudo docker pull alpine
Using default tag: latest
latest: Pulling from library/alpine
fe07684b16b8: Pull complete 
Digest: sha256:8a1f59ffb675680d47db6337b49d22281a139e9d709335b492be023728e11715
Status: Downloaded newer image for alpine:latest
docker.io/library/alpine:latest
```

And that's it! We managed to pull the alpine image as intended.

## Sidenotes

1) you can't connect to the internet from a docker container that is in a whonix workstation, and the [whonix developers won't bother providing support for it](https://forums.whonix.org/t/how-can-you-make-a-docker-container-inside-whonix-workstation-connect-to-the-internet/21772/2)

2) disabling the whonix firewall does not fix the issue either

3) you cant edit the socsk5 port on whonix workstation by editing /etc/tor/torrc to try and set SOCKSPort to `0.0.0.0:9050`, which would make it easy to access the tor socks port from the docker container.

4) you can make a `docker-compose.yml` image with the docker container set to network_mode: host to be able to access the 9050 socks5 port on the `10.152.152.11` local IP, but it doesnt seem to be able to resolve domains either for some reason.

```
[workstation user ~]% cat docker-compose.yml 
services:
  myalpine:
    image: alpine
    tty: true
    network_mode: host
    environment:
      - 'HTTP_PROXY=socks5://host.docker.internal:9050'
      - 'HTTPS_PROXY=socks5://host.docker.internal:9050'
    extra_hosts:
      - host.docker.internal:host-gateway

[workstation user ~]% sudo docker compose down ; sudo docker compose up -d
Stopping user_myalpine_1 ... done
Removing user_myalpine_1 ... done
Creating user_myalpine_1 ... done

[workstation user ~]% sudo docker container ls                          
CONTAINER ID   IMAGE     COMMAND     CREATED          STATUS          PORTS     NAMES
0752ecb83c6b   alpine    "/bin/sh"   43 seconds ago   Up 42 seconds             user_myalpine_1
[workstation user ~]% sudo docker exec -it 0752 sh

[workstation user ~]% sudo docker exec -it 0752 sh
/ # ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP qlen 1000
    link/ether 52:54:00:e8:c3:50 brd ff:ff:ff:ff:ff:ff
    inet 10.152.152.11/18 brd 10.152.191.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::5054:ff:fee8:c350/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN 
    link/ether 02:42:8c:ad:6a:cd brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:8cff:fead:6acd/64 scope link 
       valid_lft forever preferred_lft forever
15: br-973a58a1c943: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN 
    link/ether 02:42:35:83:6e:bc brd ff:ff:ff:ff:ff:ff
    inet 172.19.0.1/16 brd 172.19.255.255 scope global br-973a58a1c943
       valid_lft forever preferred_lft forever
    inet6 fe80::42:35ff:fe83:6ebc/64 scope link 
       valid_lft forever preferred_lft forever

/ # nc 10.152.152.11 -p 9050
nc: bind: Address in use
```
5) tested with a forgejo container, with the socks5 proxy set onto `10.152.152.11` on port `9050`, it is unable to mirror repositories that are on external clearnet git instances.

TLDR: if you run a docker container inside of a whonix workstation VM, it will remain truly isolated and unable to communicate with the internet.

