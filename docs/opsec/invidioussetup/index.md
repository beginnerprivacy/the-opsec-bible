---
author: here_I_am
date: 2025-09-07
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/413"
xmr: 83Gv2XibsJgNo6m4zER2jUavLpWscC2v42JEVkbkPF9bRiwMenrnDTRArydjx814PVMs3Q32PTkhvbvePFV1xfboVKRRfTw
tags:
  - Privacy Frontends
  - Serverside Privacy
---

# Setting up Invidious to watch YouTube privately

```
TLDR: block youtube's tracking by using invidious
```

This blog post reuses elements from these other tutorials: 

- [What is Privacy ?](../privacy/index.md)
- [How to rent a server Anonymously](../anonymousremoteserver/index.md)
- [Tor website/hidden service with custom vanity address (mkp224o)](../torwebsite/index.md)
- [How to run your own Darknet Lantern for Visibility and Discoverability](../darknetlantern/index.md)


## **What is the problem**
![](0.png)

Just the mere act of YouTube tracking you has inspired a whole sleek of different programs/projects that want to improve on YouTube, and invidious specifically gives you many advantages.

When comparing invidious to the original, this is where the original falls short:

![](1.png)

Now you have seen on what is already lost, but I want to specify it a little further
Now, this is what data gets collected at least:
- IP Address
- Every watched YouTube video
- Every interaction (e.g. your likes, your comments, and more data that you manually enter like survey data)
- Your Browser Agent
- Your search history

This is what they collect at the very least (if you can trust their word), to their [privacy policy](https://policies.google.com/privacy?hl=en-US), but you still don't know what they really collect!

As you will see in the next section, Google policy now apparently is "Don't be evil, unless you're too big"


## **Who is behind YouTube?**
The ownership of YouTube is as follows:

![](2.png)

Google has been [sued in 2020](https://edition.cnn.com/2024/04/01/tech/google-to-delete-data-records-to-settle-incognito-lawsuit) for collecting browsing data even while in incognito mode.

Now that their trust is broken, how to we reduce the trust required to use YouTube?

## **Why is YouTube hostile against 3-rd party clients (e.g. Invidious, NewPipe)**

YouTube wants to maximize profit at all costs, so they have started to actively start blocking Invidious instances.

Nowhere used to have an Invidious instance (under `iv.datura.network`), that proxied about 300TiB of traffic from YouTube, all without ads, with no money to YouTube.

Now there are other Invidious instances, but they also have a bad time, since they have to use many servers in order to avoid blocking, which make it very expensive for them. But even then they are frequently blocked. In theory YouTube could also just request a video from an Invidious instance, log the IP address and permanently block them.

The goal is that it is getting so expensive, that all instances become dead, Invidious be abandoned, and all users switching to first party clients, so that YouTube can milk them for data, ads and money.

When testing invidious with ipv6 rotator, I got blocked with the default rotation period of 12 hours, then lowered it to 1 minute, and didn't get blocked. This test was performed using the default "dynamic" quality, the "proxy video" option turned on and a single user watching the next recommended video.

However, the community got innovative and made patches to the source code to allow for the selection of multiple servers, as to avoid blocking, an example is seen below, taken from [invidious.nerdvpn.de](https://invidious.nerdvpn.de):

![](3.png)

There is even a [public Grafana dashboard](https://nerdvpn.grafana.net/public-dashboards/13d67f5b62d04e90903a6218ca64e591), listing all available backends (e.g. servers where the instance is hosted) that get rotated through, for this instance. So the setup for them looks something like this:

![](4.png)


## **How do you protect yourself?**

You use an invidious instance to blend in and achieve privacy and anonymity.

Now, when you use an invidious community instance, you are anonymous, because you aren't the only user:

![](5.png)

This anonymity is important, as seen by the downfall of [IntelBroker](../intelbroker/index.md#6-behavioral-correlations).
In short:
Intelbroker (a black hat hacker, now arrested) watched videos on YouTube, and shortly after shared them on BreachForums with the hacker community. This lead the feds to discover his IRL Identity and gather evidence on him, since he had been using plain YouTube and **NOT** invidious.

## **How to install invidious?**
First a quick disclaimer:
Running a public invidious instance is an involved process and quite complex when running at scale.

From now on, we'll start with the installation process, please keep in mind that the VPS should have quite some bandwidth, preferably unmetered, but 20TB is recommended, and IPv6 support, to escape blocking via ipv6 rotator.
First you need a VPS, see [here](../anonymousremoteserver/index.md) on how to acquire one, from there, install docker according to [this](../docker-intro/index.md) tutorial.

Now use can install invidious in various ways, but we'll use docker. Because it is easier to maintain and is beginner-friendly.

1.1. Install dependencies, you'll have to have `git`, `pwgen`, and `cron` installed on your server and the python packages `requests` and `pyroute2`.
```
apt install git pwgen python3-requests python3-pyroute2 cron -y
```

1.2. First, we have to clone the invidious repo and change the directory.
```
git clone https://github.com/iv-org/invidious.git
cd invidious
```
1.3. Edit the docker-compose.yml with this content:
```
services:

  invidious:
    image: quay.io/invidious/invidious:master
    # image: quay.io/invidious/invidious:master-arm64 # ARM64/AArch64 devices
    restart: unless-stopped
    ports:
      - "127.0.0.1:3000:3000"
    environment:
      # Please read the following file for a comprehensive list of all available
      # configuration options and their associated syntax:
      # https://github.com/iv-org/invidious/blob/master/config/config.example.yml
      INVIDIOUS_CONFIG: |
        db:
          dbname: invidious
          user: kemal
          password: kemal
          host: invidious-db
          port: 5432
        check_tables: true
        invidious_companion:
        - private_url: "http://companion:8282"
          public_url: "http://localhost:8282"
        invidious_companion_key: "CHANGE_ME!!"
        statistics_enabled: true
        force_resolve: "ipv6"
        hmac_key: "CHANGE_ME!!"
    healthcheck:
      test: wget -nv --tries=1 --spider http://127.0.0.1:3000/api/v1/trending || exit 1
      interval: 30s
      timeout: 5s
      retries: 2
    logging:
      options:
        max-size: "1G"
        max-file: "4"
    depends_on:
      - invidious-db

  companion:
    image: quay.io/invidious/invidious-companion:latest
    environment:
       - SERVER_SECRET_KEY=CHANGE_ME!!
    restart: unless-stopped
    ports:
      - "127.0.0.1:8282:8282"
    logging:
      options:
        max-size: "1G"
        max-file: "4"
    cap_drop:
      - ALL
    read_only: true
    # cache for youtube library
    volumes:
      - companioncache:/var/tmp/youtubei.js:rw
    security_opt:
      - no-new-privileges:true

  invidious-db:
    image: docker.io/library/postgres:14
    restart: unless-stopped
    volumes:
      - postgresdata:/var/lib/postgresql/data
      - ./config/sql:/config/sql
      - ./docker/init-invidious-db.sh:/docker-entrypoint-initdb.d/init-invidious-db.sh
    environment:
      POSTGRES_DB: invidious
      POSTGRES_USER: kemal
      POSTGRES_PASSWORD: kemal
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $$POSTGRES_USER -d $$POSTGRES_DB"]

volumes:
  postgresdata:
  companioncache:

networks:
  default:
    enable_ipv6: true
    ipam:
      config:
        - subnet: fd12:3456:789a:1::/64
          gateway: fd12:3456:789a:1::1
```
1.4. Now generate keys for the `hmac_key` and the companion key like so:
```
pwgen 16 2
```
NOTE: The first line is your `hmac_key` and the last is the companion key, set them in `invidious_companion_key` and `SERVER_SECRET_KEY` (if you have trouble finding it, it is under the invidious service). You might also want to change the password/user for the database, but it is not publicly reachable, so more a step to mess up than a security gain.

1.5. Add this to `/etc/docker/daemon.json`:
```
{
 "experimental": true,
 "ip6tables": true
}
```

1.6. Restart docker to apply the changes.
```
systemctl restart docker
```

1.7. Start invidious.
```
docker compose up -d
```

1.8. go outside the invidious folder and clone the ipv6 rotator.
```
cd .. && git clone https://github.com/iv-org/smart-ipv6-rotator.git && cd smart-ipv6-rotator
```

1.9. find your ipv6 subnet of the server, doesn't have to be a /64.
```
ip a | grep inet6 | grep global
```
Should there be no output, you don't have a global ipv6 subnet assigned, remove all lines in the docker compose file under `network:`, remove the `/etc/docker/daemon.json` file and restart docker, then you are done.

1.10. Test the ipv6 rotator script.
```
python3 smart-ipv6-rotator.py run --ipv6range=YOURIPV6SUBNET/PREFIXLENGTH
```

1.11. Now set a crontab to rotate twice a day, as per the docs.
```
crontab -u root -e
```
You are now, if you've run `crontab -e` the first time, you are prompted for your editor, choose your favorite one and paste at the end of the file that is opened the following:
```
@reboot sleep 30s && python3 /path/to/the/script/smart-ipv6-rotator.py run --ipv6range=YOURIPV6SUBNET/PREFIXLENGTH
*/1 * * * * python3 /path/to/the/script/smart-ipv6-rotator.py run --ipv6range=YOURIPV6SUBNET/PREFIXLENGTH
```
Be sure to change the path, to get the path, run `pwd` and replace the `/path/to/the/script` with the current directory, since you are in the git repo of the ipv6 rotator.

Note: The IP Address gets changed every minute, with this setup I've avoided blocking, but you can probably get away with less.

1.12. Lastly go out of the directory.
```
cd ..
```


## **Configure Tor**

You have to change the `public_url` to your address of the companion, so just forward it under a subdomain like `companion.invidios.your_onion.onion` or if without a reverse proxy, expose `8282` (the onion side) to `127.0.0.1:8282`.

2.1. follow [this](../torwebsite/index.md) guide on how to set up tor, for the nginx reverse proxy setup (the example is in `Adding subdomain`), invidious is set to listen on `127.0.0.1:3000` and the companion on `127.0.0.1:8282`.

2.2. MAKE A BACKUP OF YOUR PRIVATE KEYS!!!, NOW!

Now, you should be left with a functioning invidious instance on Tor.
To test it, use tor browser, and watch a video:

![](6.png)

**DNS Problems**:

Now you **might** have problems with the thumbnails not loading properly or slow (taking more than 10 seconds), if so, your DNS settings are broken, to set your DNS servers in `/etc/resolv.conf`, write the following (these are the ones from quad9, ipv6 only):
```
nameserver 2620:fe::fe
nameserver 2620:fe::9
```

If the instance worked, we'll now list it on the darknet lantern.

## **Listing it on the Darknet Lantern**

4.1. Set up your Darknet Lantern according to [this](../darknetlantern/index.md)

4.2. Next, change your directory to the Darknet Lantern and add your instance:
```
python3 run_lantern.py
```
And configure it, change the URL and the description
```
Select an option? (0-12): 1

Add a new Website entry
Enter entry's category: Privacy front-ends
Enter entry's name: Alices invidious instance
Enter entry's url: http://your_url.onion
Enter is entry sensitive(YES or NO): NO
Enter entry's description: Alices public invidious instance 
Enter entry status(YES or NO): YES
Enter entry's score (0 - 100): 100
Verified and unverified saved successfully
New row added! now writing the csv file
```

4.3. Now, you'll have to participate in a webring, learn how to participate in the nowhere webring in this [section](../darknetlantern/index.md#how-to-participate-in-the-webring)

## **Conclusion**

This is it, you now have your own invidious instance, but be worry of rate limits, since YouTube is very hostile, and expect to run `docker compose pull && docker compose up -d` once in a while to get the updates when YouTube has blocked invidious again.
