---
author: UserSurname
date: 2025-08-26
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/412"
xmr: 82jqKSrZsUQBP8uEbzj23AhTyvh6hsoXRhvg4xsiNH8cajiUwhhqqvS9TCDac5PiAHUEYv9GYGgEKUw6GRngAxjQHSfvMQ7
tags:
  - Serverside Privacy
  - Privacy Frontends
---
# Setting up SafeTwitch to watch Twitch privately

```
TLDR: you can watch Twitch without their invasive tracking using Safetwitch
```

![](../context/anon_remote.png)

## Twitch

Twitch is the one of largest live streaming websites right now.

Twitch is operated by Twitch Interactive, which was acquired by Amazon in 2014. Its main revenue source is advertisements.

It also collects and sells their user data with their parent company Amazon and its subsidiaries.

![](twitch.avif)

Here's what data they collect about their users:

> Examples of such information we automatically collect include Internet Protocol address (“IP Address”), a unique user ID, device and browser types and identifiers, referring and exit page addresses, software and system type, and information about your usage of Twitch Services.

to then share it with 3rd parties:

> Twitch may share personal information with, and receive personal information from, our affiliates (meaning entities controlled by, controlling, or under common control with Twitch), including Amazon.com, Inc. and its subsidiaries that are either subject to this Privacy Notice or follow practices at least as protective as those described in this Privacy Notice.

and with the Law Enforcement:

> Twitch may disclose user information if we believe in good faith that such disclosure is necessary to comply with U.S. state and federal laws or other applicable laws around the world (for example, in the country of your residence), or respond to a court order, judicial or other government request, subpoena, or warrant in the manner legally required.

source: [Twitch.tv - Privacy Notice](https://www.twitch.tv/p/no-no/legal/privacy-notice/)

## SafeTwitch - a privacy-oriented Twitch frontend

Instead, you can watch Twitch streams anonymously using SafeTwitch.

It is a decentralized FOSS frontend for Twitch that lets you watch Twitch live streams without being tracked.

![](safetwitch.avif)

It's also very easy to self-host. We will cover how to set it up using Docker in this tutorial.

## How to setup SafeTwitch

### Requirements

**This tutorial assumes that you had [anonymously rented a VPS](../anonymousremoteserver/index.md) with a Debian-based OS.**

In this tutorial, we will setup a SafeTwitch instance using Docker. You can learn how to use Docker in [this tutorial](../docker-intro/index.md).

1\. Update your system and install Tor:

```
user@nowhere:~$ sudo apt update -y && sudo apt install -y tor
```

2\. Install Docker

Refer to [this tutorial](../docker-intro/index.md#installation) to install Docker.

3\. Create your folder for SafeTwitch:

```
user@nowhere:~$ sudo mkdir /srv/safetwitch && cd $_
```

### Creating .onion Hidden Services for our SafeTwitch instance

1\. Configure Tor

This will create 2 .onion addresses. One for the backend, and one for the frontend.

```
user@nowhere:/srv/safetwitch$ cat /etc/tor/torrc

# SafeTwitch Frontend
HiddenServiceDir /var/lib/tor/safetwitch/
HiddenServicePort 80 127.0.0.1:8280

# SafeTwitch Backend
HiddenServiceDir /var/lib/tor/safetwitch_backend/
HiddenServicePort 7100 127.0.0.1:7100

HiddenServicePoWDefensesEnabled 1
HiddenServicePoWQueueRate 250
HiddenServicePoWQueueBurst 2500
```

You can generate your custom onion addresses for privacy frontends by following [this tutorial](../redlibsetup/index.md#setting-up-a-custom-tor-vanity-v3-address). It is borrowed from [this](../torwebsite/index.md) tutorial, but configured specifically for Privacy frontends.

```
user@nowhere:/srv/safetwitch$ sudo systemctl restart tor.service
```

2\. Get your SafeTwitch instance and SafeTwitch backend onion addresses:

```
user@nowhere:~$ cat /var/lib/tor/onions/safetwitch/hostname

hhfjcipi6qhsfkao6zldatcbuok4vbnb7dl5yxpps4h3ne6mftn3moyd.onion
```

```
user@nowhere:~$ cat /var/lib/tor/onions/safetwitch_backend/hostname

ilja2bohyvz4r3kspiqznyw3prw5o4h452daoe4srnoz3xbiczagzfad.onion
```

### Setting up SafeTwitch using docker

1\. Setup docker-compose.yml

**Don't forget to change the environment variables to match your own generated .onion addresses.**

```
user@nowhere:/srv/safetwitch$ cat docker-compose.yml
version: "3.7"

services:
  safetwitch-frontend:
    container_name: safetwitch-frontend
    hostname: safetwitch-frontend
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - SETGID
      - SETUID
    restart: always
    image: codeberg.org/safetwitch/safetwitch:latest
    ports:
      - "127.0.0.1:8280:8280"
    environment:
      - SAFETWITCH_BACKEND_DOMAIN=ilja2bohyvz4r3kspiqznyw3prw5o4h452daoe4srnoz3xbiczagzfad.onion:7100
      - SAFETWITCH_INSTANCE_DOMAIN=hhfjcipi6qhsfkao6zldatcbuok4vbnb7dl5yxpps4h3ne6mftn3moyd.onion
      - SAFETWITCH_HTTPS=false
      - SAFETWITCH_DEFAULT_LOCALE=en
      - SAFETWITCH_FALLBACK_LOCALE=en

  safetwitch-backend:
    container_name: safetwitch-backend
    hostname: safetwitch-backend
    user: 65534:65534
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    restart: always
    image: codeberg.org/safetwitch/safetwitch-backend:latest
    ports:
      - "127.0.0.1:7100:7000"
    environment:
      - PORT=7000
      - URL=http://ilja2bohyvz4r3kspiqznyw3prw5o4h452daoe4srnoz3xbiczagzfad.onion:7100
```

2\. Setup SafeTwitch with docker-compose

```
user@nowhere:/srv/safetwitch$ docker compose up -d && docker compose logs -f

safetwitch-backend is up-to-date
safetwitch-frontend is up-to-date
Attaching to safetwitch-frontend, safetwitch-backend
safetwitch-backend     | 2025/08/26 16:20:09 Starting Safetwitch...
safetwitch-backend     | 2025/08/26 16:20:09 Safetwitch API running
safetwitch-backend     | 2025/08/26 16:20:10 Connecting to Twitch IRC
safetwitch-backend     | 2025/08/26 16:20:10 Authenticated with Twitch IRC!
```

## Using your SafeTwitch instance

### Notes on using SafeTwitch through Tor

1\. Since SafeTwitch uses Vue, you will have to enable JavaScript for it to work.

**Warning: Turning on JavaScript for untrusted websites is a massive OPSEC risk. Make sure to NOT visit any other website with JavaScript left on.**

2\. Since you're using SafeTwitch through Tor, it will be slow and buffer frequently if you don't lower the resolution.

3\. In some cases, the video may not load, with a "Commercial break in progress" screen. Try refreshing the page.

### Use your SafeTwitch instance

Now, try to visit your SafeTwitch instance through Tor Browser to see if it works.

![](1.avif)

**Since Tor download speeds are slow, I recommend setting the resolution to 360p. That is the biggest resolution that doesn't make the stream buffer too often.**

### Adding your SafeTwitch instance to LibRedirect

To make every Twitch link redirect to your SafeTwitch instance, you can add it to your LibRedirect extension.

You can install LibRedirect in Tor Browser using this [guide](../frontends_explained/index.md#how-to-install-firefox-based-browsers-and-tor-browser).

To add your instance, go to the [LibRedirect settings](../frontends_explained/index.md#post-install-setup), and follow the instructions on the image.

![1. Go to Services 2. Choose Twitch in Service dropdown 3. Toggle "Enable" under the dropdown 4. Paste your instance URL under "Add your favorite instances" 5. Click on the + button to add your instance](2.avif)

## Make your SafeTwitch Instance public

If you want to let other users use your SafeTwitch Instance, you can make it a public one by sharing it with the others. This would be a great contribution to online privacy.

You can do it by adding your instance to the Darknet Lantern, or by adding it to the SafeTwitch repository. In this tutorial, we will add our instance to both of them.

### Adding your SafeTwitch instance to the Darknet Lantern

The Darknet Lantern Project is a search engine for discovering Hidden Services. Because of the undiscoverability of the onions and the huge amount of possible onion v3 addresses, creation of a traditional search engine (like the clearnet Google, DuckDuckGo) for scraping the whole darknet is not feasible. The Darknet Lantern, instead, functions by adding the onions manually to the list and sharing them between the participants of a webring.

1\. Set up a Darknet Lantern instance

Create your Darknet Lantern instance using [this tutorial](../darknetlantern/index.md)

2\. Add your SafeTwitch instance using the `run_lantern.py` script

```
user@nowhere:/srv/darknet-lantern$ python3 run_lantern.py
```

Choose option 1 and add your SafeTwitch instance

```
Select an option? (0-12): 1

Add a new Website entry
Enter entry's category: Privacy front-ends
Enter entry's name: UserSurname's SafeTwitch instance
Enter entry's url: http://hhfjcipi6qhsfkao6zldatcbuok4vbnb7dl5yxpps4h3ne6mftn3moyd.onion
Enter is entry sensitive(YES or NO): NO
Enter entry's description: Private and bloat-free Twitch frontend
Enter entry status(YES or NO): YES
Enter entry's score (0 - 100): 100
Verified and unverified saved successfully
New row added! now writing the csv file
```

3\. Participate in the Nowhere Webring

To have the .onion links you added (including your SafeTwitch instance) display on the other Darknet Lantern instances, you have to participate in a Webring.

You can learn how to participate in the Nowhere Webring [here](../darknetlantern/index.md#how-to-participate-in-the-webring).

### Adding your SafeTwitch instance to the SafeTwitch instances list

The SafeTwitch repository is hosted on Codeberg. The SafeTwitch instance list is managed on the same repository, in the `readme` file. We will create a Codeberg account and create an issue to add our instance to the list.

#### Creating a Codeberg account

1\. Register on [Codeberg](https://codeberg.org/user/sign_up)

![](3.avif)

2\. Click on the link sent to your email

![](4.avif)

3\. Verify your password

![](5.avif)

After this step, you should be automatically logged in.

#### Adding your instance to the SafeTwitch repo

1\. Go to the [SafeTwitch repository](https://codeberg.org/SafeTwitch/safetwitch)

2\. Create a new issue

![Click on Issues under repository name, and click on "New Issue"](6.avif)

3\. Fill in the details and name it "New Instance"

![Fill in the details in following order: URL, country [the instance is hosted in], instance hosting provider, Is cloudflare used (true/false)](7.avif)

4\. Wait until your instance gets added to the list. This may take some time.

## Conclusion

In this tutorial, we created a public SafeTwitch instance to let other users watch Twitch live streams anonymously.

We added our instance to the Darknet Lantern and the SafeTwitch instances list to contribute to online anonymity and decentralization.
