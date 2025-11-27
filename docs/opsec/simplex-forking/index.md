---
author: loki_opsec_inc
date: 2025-08-23
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/230"
xmr: 8AaLSmixWFJhgMmrBvqi6827v27YYT6H8C6SjUasHySBKna2JDk1dtEf2ZAUpXue64JDEBxkTL9oZGaoKtcWppWKHLSkTLM
tags:
  - Core Tutorial
---
# What if a FOSS Project Turns Malicious? (Building SimpleX from Source)

```
TLDR: Fork the project, remove the bad commits, compile from source, and use your own compiled binaries
```

In this post we're going to discuss the importance of FOSS in an increasingly Orwellian world, and how to build the SimpleX Chat FOSS codebase for ourselves to take advantage of its benefits.

## The importance of FOSS in Communication Software

[As we have discussed before](../closedsource/index.md), closed-source software makes it impossible to achieve privacy. Such is the same for messengers of course.

As an example of this importance, though not directly related to a messenger specifically, one must merely look at a recent piece of news involving pressure from the United Kingdom towards Apple ([The Guardian Onion](https://www.guardian2zotagl6tmjucg3lrhxdk4dw3lhbqnkvvkywawy3oqfoprid.onion/technology/2025/feb/21/apple-removes-advanced-data-protection-tool-uk-government) | [Archive Onion](https://web.archivep75mbjunhxc6x4j5mwjmomyxb573v42baldlqu56ruil2oiad.onion/web/20250723213048/https://www.theguardian.com/technology/2025/feb/21/apple-removes-advanced-data-protection-tool-uk-government)):

![](./apple-uk-news.png)

As you can see, because all Apple software and services are **closed-source and centralised under a corporate entity**, a few powerful people in a government office can suddenly and without warning **declare that your data and activities have no privacy or security**.

## SimpleX is Different

[SimpleX Chat](http://isdb4l77sjqoy2qq7ipum6x3at6hyn3jmxfx4zdhc72ufbmuq4ilwkqd.onion/) is a highly secure messenger that uses a system of relays that is fully open source and can be built and hosted by anyone.

This is different from other popular options, such as [Signal](../signalnoanonymity/index.md), which although has an open source client, does have a centralised server. Even though this server code is open source, it has had issues with not being updated for long periods of time and, actually some parts are closed source like the anti-spam mechanism. And in the end doesn't really matter because you have no choice on where your messages are routed through anyway.

It's also different from something like [Telegram](../telegramnoanonymity/index.md), which also has an open source client but the server is totally centralised and closed source.

![](./chat-apps.png)

Here are a couple good resources for more comparisons between SimpleX and other messengers:

- [PrivacySpreadsheet.com](https://privacyspreadsheet.com/messaging-apps)
- [SecureMessagingApps.com](https://www.securemessagingapps.com/)

## Using FOSS To Our Advantage

Something that many people don't know is the developers of SimpleX are under an entity called **SimpleX Chat Ltd. which is under the jurisdiction of the United Kingdom**. More info on their site [here](http://isdb4l77sjqoy2qq7ipum6x3at6hyn3jmxfx4zdhc72ufbmuq4ilwkqd.onion/transparency/), and their company listing with the UK government can be found online ([Clearweb](https://find-and-update.company-information.service.gov.uk/company/13691484) | [Archive Onion](https://web.archivep75mbjunhxc6x4j5mwjmomyxb573v42baldlqu56ruil2oiad.onion/web/20250820015438/https://find-and-update.company-information.service.gov.uk/company/13691484))

So hypothetically speaking, the UK government could come in at any time and demand that the SimpleX team start putting malicious code into the client application. But of course, as the application is FOSS, we can simply fork the code, remove the malicious commits, then continue on as if nothing happened. No approval or permission is needed.

![](./simplex-git.png)

The same can be said for the servers or server code:

![](./simplex-servers.png)

An additional thing to note, which is described in detail in [this tutorial](../anonsimplex-server/index.md), is that even if we remove the default servers from our client, we can still inter-operate with those default servers if other people talking to us or joining our groups are using them, which we will demonstrate in action later as well

![](../anonsimplex-server/0.png)

## Running Client and Server Entirely from Modified Source Code

### Prerequisites

For this tutorial blogpost we're assuming you're using a Debian-based distro and that you have some basic [Linux command line literacy](../linuxbasics/index.md). 

Install some necessary packages.
```
sudo apt update # update your local package repositories
sudo apt install curl git tor
```

If you have already installed and configured git, you can skip this step, but otherwise you need to set your git user name and email so you can make commits:
```
git config --global user.name "Loki OpSec Inc"
git config --global user.email "loki_opsec_inc@nowhere.jez"
```

If your remote git repo is behind an onion, then set your git config to use the local Tor proxy:
```
git config --global http.proxy socks5h://localhost:9050
git config --global https.proxy socks5h://localhost:9050
```

When we build the SimpleX code, we will be using Docker. You will need to follow the Docker installation instructions at [this guide](../docker-intro/index.md)

Finally, let's make a directory we can use to do all our building activities in:
```
mkdir -p ~/simplex-build
cd ~/simplex-build
```

### Forking the SimpleX Code to your own Git Server

Here we're going to show you how to fork the SimpleX code from Github to your own [Forjego](https://forgejo.org/) or [Gitea](https://about.gitea.com/) instance. If you don't already have one you can follow our [guide here](../forgejo-anon/index.md) to set one up. For this example we're going to use the [Nowhere Collective's own Git Datura](http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/).

**Important**: When you fork from your own remote server, you will need to add a wildcard or add Github domains to your allowed domains. You see how to do that [here](../forgejo-anon/index.md#githubclearnet-repositories-through-tor):
```
# Example, specifically Github
[migrations]
ALLOWED_DOMAINS = *.github.com,github.com
```

Keep in mind we're going to fork two repositories, the client code and the server code, so you'll have to do everything twice:

- <https://github.com/simplex-chat/simplex-chat>
- <https://github.com/simplex-chat/simplexmq>

On any page, click on the "+" at the top right corner and click "New Migration". Then on the subsequent page, select Github.

![](./migrate-1.png)

On the next page we see a form. You'll paste in the link to the repository, and the Repository Name should autofill, but otherwise should be the same name as the Github repo. You can choose to migrate the Wiki optionally. 

You should NOT check the "This repository will be a mirror" option. This will make the repository read-only and also will sync periodically with the Github repo. However, you may actually want this behavior at some time, and if you do, you can always convert the mirror repository to a normal repository (through the repository Settings) that you can push commits to (more info about mirroring [here](../forgejo-anon/index.md#forgejo-mirroring)).

![](./migrate-2.png)

Once you start the migration, you'll see a loading screen, which you should wait for until your repository page pops up, like so:

![](./migrate-3.png)

### Pulling and Modifying the Code

Now we're going to show you **how to make a change and commit and push it**, and also **how to delete a committed change for a scenario in which you want to delete a malicious commit**.

Please keep in mind that we are modifying the client application code but you can use this same process for the server code in the `simplexmq` repository.

Clone the git repository and change directory into it:
```
git clone http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/loki_opsec_inc/simplex-chat.git
cd simplex-chat
```

Make a new branch which we will use to make source code modifications in:
```
git checkout -b forktest
```

Now, we're going to edit one file to show a small UI change in our locally-build client app, in `simplex-chat/apps/multiplatform/common/src/commonMain/resources/MR/base/strings.xml`:

![](./modify-string.png)

Save the changes and commit them to the git repo:
```
git commit -a -m "new fork, test change"
```

Now comes a very important part. When we build our binaries later, we will specify exactly what code to build by a [git tag](https://git-scm.com/book/en/v2/Git-Basics-Tagging) which is basically just a human-readable label that refers to a specific commit. So, we will tag the commit we just made:
```
# this tags the latest commit
git tag fork.v1.0.0 -m 'first fork version!'
# we can also run this to tag a specific commit by including the ID
git tag fork.v1.0.0 -m 'first fork version!' 5a99f8f32b0b5e3af7dcda5bda2cda48e9ae5ab0
```

Run `git log` to see all these changes:

![](./git-log.png)

You can see the new branch, commit, and tag.

For future reference you can list all the tags that have been created with:
```
git tag -n
```

Go back to the `strings.xml` file we edited earlier, and add some more random text somewhere. Then save the file and commit the changes:
```
git commit -a -m "evil commit"
```

See in the `git log`:

![](./git-log-evil-commit.png)

Let's pretend this is some malicious code that perhaps SimpleX was forced to include. We can use a reset to revert back before this commit:
```
# revert to this commit ID. this commit ID will stay intact, but everything after it will be deleted
git reset --hard 5a99f8f32b0b5e3af7dcda5bda2cda48e9ae5ab0
```

You should get an output like:
```
HEAD is now at 5a99f8f32 new fork, test change
```

If this commit was already on your remote as well, you will need to do a force push to get rid of it...
```
git push origin HEAD --force
```

Now run `git log` and see that the evil commit is gone.

In any case, once you are done modifying the code, you can push to your remote Git server. `--tags` will make sure to push any tags you created to your remote as well. Replace `forktest` with whatever your branch is:
```
git push --tags -u origin forktest
```

### Building the SimpleX Client AppImage

Now that we've made our changes and pushed them to the remote git server, we are going to learn how to build an AppImage of the SimpleX chat client from the source code, which we can run on any Linux distro.

Let's leave the client app's git repo and return to our main build directory:
```
cd ~/simplex-build
```

The SimpleX code base includes a script that will do exactly what we want. This script is meant to compare the pre-built binaries released by the SimpleX with the ones build locally as well, so we will have to modify the script slightly to take out that code. Additionally, the script will try to pull from the official Github repo instead of our personal Git server so we will have to change that too.

Copy the script to your build directory:
```
cp ./simplex-chat/scripts/simplex-chat-reproduce-builds.sh ./
```

make the script executable:
```
chmod +x simplex-chat-reproduce-builds.sh
```

Now open the script and make the following changes:

![](./script-mod-1.png)
![](./script-mod-2.png)
![](./script-mod-3.png)

Once you save your changes, you can execute the script like so. You have to specify a tag name as an argument, so if you want to use the tag we made in the example above:
```
./simplex-chat-reproduce-builds.sh 'fork.v1.0.0'
```

The script will then build the client app! This may take up to a few hours depending on your computing power. The script will download and utilize a docker image to download our remote git repo inside of it and build the code to create the client application.

![](./client-build-output.png)

Once the script is complete, you should see a folder in your build directory with several binaries:

![](./client-binaries.png)

### Building the Server Docker Images

There are actually a couple options to building the SimpleX server binaries. One is to use a reproducible script just like the client app. If you want to do this, it's in the `simplexmq` repository under the `scripts` directory. You'll have to make the same modifications as we did earlier to the client script.

However, in this tutorial we're going to be choosing the option to build a set of Docker images for the SMP and XFTP servers, as opposed to the pre-built ones on the [Docker Hub](https://hub.docker.com/u/simplexchat)

Let's clone our forked `simplexmq` git repository:
```
cd ~/simplex-build
git clone http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/loki_opsec_inc/simplexmq.git
cd simplexmq
```

The source code used to build the Docker images is going to be the latest commit of whatever git branch is currently checked out, so checkout the branch you need. For example if you made a new branch to delete some malicious code:
```
git checkout branchname
```

Our file for building the docker images is `Dockerfile` which in the root directory of the git repo. So assuming that's our current directory, we will run these two build commands, one for the SMP and one for the XFTP server. You can run them one after the other or separately in two different terminals:
```
DOCKER_BUILDKIT=1 docker build -t local/smp-server --build-arg APP="smp-server" --build-arg APP_PORT="5223" .
DOCKER_BUILDKIT=1 docker build -t local/xftp-server --build-arg APP="xftp-server" --build-arg APP_PORT="443" .
```

Once they're done, you can see the images by running `docker images`:
![](./docker-images-ls.png)

### Running the Server

At the point you can use your new images to setup your SimpleX server. To do that you will need to follow [**this guide**](../anonsimplex-server/index.md).

In that guide at the beginning of the "SimpleX Server Guide" section, you will see a Docker Compose YAML config file, in which you'll see a couple lines like so:
```
image: simplexchat/smp-server:latest

image: simplexchat/xftp-server:latest
```

These lines tell Docker to pull pre-built images from the Docker Hub. But of course we just built our own, so we will change those lines to these:
```
image: local/smp-server:latest

image: local/xftp-server:latest
```

Other than that just follow the guide exactly as it says.

### Test

Now that we're done with all the building, we can finally test our new client and server.

Once you have the server up and running, open your client AppImage. Once we create our initial profile we can see the little UI change we made:

![](./client-landing.png)

Here I'm turning off all default servers and adding my own newly created SMP and XFTP servers:

![](./smp-server-add.png)
![](./xftp-server-add.png)
![](./your-servers-added.png)
![](./default-servers-disabled.png)

And here I'm making a new group, then joining that group over the clearnet with my phone that uses only the default SimpleX servers, proving that I am not at all isolated from other SimpleX users even when using onion-only servers that only I own and operate:

![](./group-create.png)
![](./group-join-mobile-clearnet.png)
![](./group-both-joined.png)

And here I am inviting a member of the community and interacting with him, from my onion-only client:

![](./nihilist-convo-desktop-1.png)
![](./nihilist-convo-desktop-2.png)

And from my clearnet phone:

![](./nihilist-convo-mobile.png)

## Conclusion

Congrats! You have just built your entire SimpleX ecosystem from source and made it operational.
