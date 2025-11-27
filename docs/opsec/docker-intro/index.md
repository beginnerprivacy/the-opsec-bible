---
author: loki_opsec_inc
date: 2025-08-20
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/476"
xmr: 8AaLSmixWFJhgMmrBvqi6827v27YYT6H8C6SjUasHySBKna2JDk1dtEf2ZAUpXue64JDEBxkTL9oZGaoKtcWppWKHLSkTLM
---

# Docker Intro: Installation, Setup and Basic Operations

```
TLDR: you can setup docker containers to avoid having to setup VMs to spin up new serverside applications
```

Some of our tutorials use [Docker](https://www.docker.com/) as a prerequisite, especially for self-hosting. This tutorial will show you how to install the latest Docker Engine on your machine and set it up for seamless use, as well as some basic docker operations to get you familiar with it.

Even if it you already have Docker installed, it's highly recommended that you go through this anyway to be sure you have the latest Docker Engine installed on your machine, for increased security and to take advantage of [Docker Compose V2](https://docs.docker.com/compose/releases/migrate/).

## Docker Basics

Docker is a way for us to run applications or operating systems in things called containers, which can be thought of as stripped-down Virtual Machines. A container has its own file system and is usually designed to run a single process or application. This way we can keep something like a chat server isolated in its own environment. The difference between docker and a proper virtual machine (like [QEMU/KVM](..//hypervisorsetup/index.md#virtualisation-setup)) is that the containers share the same kernel with host OS.

[Containers](https://www.freecodecamp.org/news/how-docker-containers-work/) are created using a Docker Image, which can thought of as a blueprint, or, the iso file you download before you install Linux onto a computer. A collection of images can be found on the [Docker Hub](https://hub.docker.com/) or other container registries.

[Images](https://docs.docker.com/get-started/docker-concepts/the-basics/what-is-an-image/) are created through the use of a Dockerfile which is a set of instructions on how to build the image. You can commonly see images being built on top of existing Linux distributions, most of them inherit either from [Debian](https://hub.docker.com/_/debian), [Alpine](https://hub.docker.com/_/alpine) or [Ubuntu](https://hub.docker.com/_/ubuntu).

[Volumes](https://docs.docker.com/engine/storage/volumes/) store data for of containers. They can either be mounted onto your filesystem or reside in a special docker directory (`/var/lib/docker`).

A [network](https://docs.docker.com/engine/network/) helps containers to communicate with each other. By putting two containers on the same bridge, they can talk to each other while remaining in separation from other running processes. The container only sees a network interface with an IP address, a gateway, a routing table, DNS services, and other networking details.

By default, when you create or run a container using `docker run`, containers on bridge networks don't expose any ports to the outside world. Use the `-p` flag to make a port available to services outside the bridge network. This creates a firewall rule in the host, mapping a container port to a port on the Docker host to the outside world. 

In docker networking you'll see things like `-p 8080:80`. This means to map port 8080 on the Docker host to TCP port `80` in the container. Or `-p 192.168.1.100:8080:80`, which means to map port 8080 on the Docker host IP `192.168.1.100` to TCP port `80` in the container.

You can also learn more about Docker networking with Tor in [this guide](../docker-tor/index.md).

## Installation

Here we're going to focus on [Debian](https://docs.docker.com/engine/install/debian/) based systems ([whonix](../whonixqemuvms/index.md), [kicksecure](../hypervisorsetup/index.md) and [tails](../tailsqemuvm/index.md) are all Debian based). However, you can find the instructions for your specific distro in the [Docker documentation](https://docs.docker.com/engine/install/). These links will always contain the up-to-date instructions in case the ones in this post become out of date.

**Step 1: Remove any conflicting packages**

If you have previous installed Docker on your system you will want to remove any packages that will conflicting with your new installation.

```
for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do sudo apt-get remove $pkg; done
```

**Step 2: Add Docker's Official GPG key to your system with these commands**

```
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
```

**Step 3: Add Docker's official repository to your system**

```
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```

The update your repos:
```
sudo apt-get update
```

**Step 4: Install the packages**
```
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

Verify that the installation is successful by running a docker command with no errors:
```
$ sudo docker ps
CONTAINER ID   IMAGE   COMMAND   CREATED   STATUS   PORTS   NAMES
```

If this doesn't work, make sure the Docker services are running:
```
sudo systemctl start docker.service
sudo systemctl start containerd.service
```

## Post-installation Setup

> Taken from [Docker documentation](https://docs.docker.com/engine/install/linux-postinstall/).

### Avoid running Docker with `sudo`

We don't wanna constantly run every single `docker` command with `sudo`. So let's fix our permissions to avoid that.

Create the `docker` permissions group. It's likely already created but check to make sure:
```
sudo groupadd docker
```

Add your user to the docker group.
```
sudo usermod -aG docker $USER
```

Activate the group changes. If this doesn't work you'll need to reboot.
```
newgrp docker
```

Verify that you can run docker commands without sudo.
```
$ docker ps
CONTAINER ID   IMAGE   COMMAND   CREATED   STATUS   PORTS   NAMES
```

### Configure Docker to start on boot

If you're using a Debian or Ubuntu based distro the services will likely already be enabled. Regardless, you can do so with:
```
sudo systemctl enable docker.service
sudo systemctl enable containerd.service
```

To stop this behavior, use `disable` instead.
```
sudo systemctl disable docker.service
sudo systemctl disable containerd.service
```
