---
author: UserSurname
date: 2025-08-27
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/blog-contributions/issues/415"
xmr: 82jqKSrZsUQBP8uEbzj23AhTyvh6hsoXRhvg4xsiNH8cajiUwhhqqvS9TCDac5PiAHUEYv9GYGgEKUw6GRngAxjQHSfvMQ7
tags:
  - Serverside Privacy
  - Privacy Frontends
---
# Setting up Redlib to browse Reddit privately

```
TLDR: you can use Redlib to browse Reddit minus their invasive tracking
```

![](../context/anon_remote.png)

This tutorial reuses elements from some other posts:

 - [How to run your own Darknet Lantern for Visibility and Discoverability](../darknetlantern/index.md)
 - [Privacy Frontends - Avoiding Centralized Tracking](../frontends_explained/index.md)
 - [Hidden Service with custom .onion Vanity V3 address](../torwebsite/index.md)


## **Reddit, a privacy nightmare**

Most of Reddit's profits comes from selling your data.

There isn't a better example to show this, than [Reddit making a $60M deal with Google to train their AI on user posts](https://www.cbsnews.com/news/google-reddit-60-million-deal-ai-training).

![](reddit.avif)

According to Reddit's privacy policy, they "may automatically log information" including:

- IP address
- User-agent string
- Browser type
- Operating system
- Referral URLs
- Device information (e.g., device IDs)
- Device settings
- Pages visited
- Links clicked
- The requested URL
- Search terms

They also block VPNs to force you to reveal your IP address.

## **Redlib - a private and decentralized Reddit frontend**

To browse Reddit privately, you can use Redlib. It is a decentralized Reddit frontend that lets you browse Reddit without your IP and other information being exposed to Reddit.

It doesn't require JS to function, doesn't log any data, and can be easily self-hosted.

![](redlib.avif)

Redlib is also much faster than Reddit:

| Performance metric | Redlib | Reddit |
| --- | --- | --- |
| Speed Index | 0.6s | 1.9s |
| Performance score | 100% | 64% |
| Time to Interactive | 2.8s | 12.4s |

From Google PageSpeed Insights

## How to set up Redlib?

This tutorial assumes you have rented a remote VPS with a Debian-based OS.

You can learn how to get one anonymously [here](../anonymousremoteserver/index.md).

Note that Redlib doesn't function on Whonix currently, since most of the Tor exit nodes are IP-banned by Reddit.

Be careful when setting up a Redlib instance on a home server, because your home IP will be exposed to reddit.

### Setting up Redlib

1\. Update system and install the needed packages

```
user@nowhere:~$ sudo apt update -y && sudo apt install -y tor
```

2\. Install Docker using [this tutorial](../docker-intro/index.md#installation).

3\. Set up docker-compose.yml

```
user@nowhere:~$ mkdir /srv/redlib && cd $_

user@nowhere:/srv/redlib$ cat docker-compose.yml 

services:
  redlib:
    image: quay.io/redlib/redlib:latest
    restart: always
    container_name: "redlib"
    ports:
      - 127.0.0.1:8080:8080
    user: nobody
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    env_file: .env
    networks:
      - redlib
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "--tries=1", "http://localhost:8080/settings"]
      interval: 5m
      timeout: 3s

networks:
  redlib:
```

4\. Configure .env 

```
user@nowhere:/srv/redlib$ cat .env

REDLIB_PORT=8080
REDLIB_ENABLE_RSS=on

REDLIB_DEFAULT_THEME=dark
```

`REDLIB_DEFAULT_THEME` is the default theme when you don't set it in settings. It can be changed by any user individually.

The default value is "system". I set the dark theme to not flashbang my users at night. You can choose any theme you like from this list:

`["system", "light", "dark", "black", "dracula", "nord", "laserwave", "violet", "gold", "rosebox", "gruvboxdark", "gruvboxlight", "tokyoNight", "icebergDark", "doomone", "libredditBlack", "libredditDark", "libredditLight"]`

5\. Now, you can set up Redlib using Docker:

```
user@nowhere:/srv/redlib$ docker compose up -d

Creating network "redlib_redlib" with the default driver
Pulling redlib (quay.io/redlib/redlib:latest)...
latest: Pulling from redlib/redlib
1747dece9491: Pull complete
b2ef4a1849f0: Pull complete
387a7df3fd34: Pull complete
bba1196852ed: Pull complete
Digest: sha256:3908c592bba4a17d32516277504c42284600bd826cf1c1f9a309fdedc7bdd27a
Status: Downloaded newer image for quay.io/redlib/redlib:latest
Creating redlib ... done
```

Check logs to see if it is working properly:

```
user@nowhere:/srv/redlib$ docker logs -f redlib

Starting Redlib...
Running Redlib v0.36.0 on [::]:8080!
```

**If it spams an oAuth error every 5 seconds, that means you're IP banned by Reddit. Change the IP address of your VPS or change your VPS provider.**

### Setting up a custom Tor vanity v3 address

This tutorial is replicating parts of [this tutorial](../torwebsite/index.md) and configured to be working with Redlib (or any other privacy frontend)

To let the users connect to our Redlib instance anonymously, we will create a Hidden Service (with an .onion address)

Now, if you want to have your .onion address to be recognizable, you can set up a custom .onion vanity address that starts with custom characters (for example, the link to the OPSEC Bible starts with "opbible")

If you dont want to bother with a custom .onion address, you can skip further down until the "Configuring Tor" section.

1\. Download the needed packages

```
user@nowhere:/srv/redlib$ sudo apt install gcc libc6-dev libsodium-dev make autoconf -y
```

2\. Install mkp224o

```
user@nowhere:/srv/redlib$ cd /srv

user@nowhere:/srv$ git clone https://github.com/cathugger/mkp224o && cd mkp224o

Cloning into 'mkp224o'...
remote: Enumerating objects: 1574, done.
remote: Counting objects: 100% (364/364), done.
remote: Compressing objects: 100% (57/57), done.
remote: Total 1574 (delta 335), reused 307 (delta 307), pack-reused 1210 (from 2)
Receiving objects: 100% (1574/1574), 1.89 MiB | 4.27 MiB/s, done.
Resolving deltas: 100% (981/981), done.
```

Compile mkp224o:

```
user@nowhere:/srv/mkp224o$ ./autogen.sh

user@nowhere:/srv/mkp224o$ ./configure

checking for gcc... gcc
checking whether the C compiler works... yes
checking for C compiler default output file name... a.out
checking for suffix of executables... 
checking whether we are cross compiling... no
checking for suffix of object files... o
checking whether the compiler supports GNU C... yes
checking whether gcc accepts -g... yes
checking for gcc option to enable C11 features... none needed
checking whether CC supports -march=native... yes
checking whether CC supports -fomit-frame-pointer... yes
checking whether CC supports -fPIE... yes
checking whether CC supports -std=c99... yes
checking whether CC supports -Wall... yes
checking whether CC supports -Wextra... yes
checking whether CC supports -Wno-maybe-uninitialized... yes
checking whether CC supports and needs -Wno-format -Wno-pedantic-ms-format... no
checking whether CC supports -Wno-unused-function... yes
checking whether CC supports -Wmissing-prototypes... yes
checking whether CC supports -Wstrict-prototypes... yes
checking whether ARGON2ID13 is supported by libsodium... yes
configure: creating ./config.status
config.status: creating GNUmakefile

user@nowhere:/srv/mkp224o$ make
```

3\. Run mkp224o

If you have a small CPU like I do, this will take some time. Dont make the input longer than 6-8 characters, or else you would have to wait a small bit longer (10 million years)

I want my onion address to start with "redlib", so i run:

```
user@nowhere:/srv/mkp224o$ ./mkp224o redlib

sorting filters... done.
filters:
	redlib
in total, 1 filter
using 4 threads
redlibjdijbebprm5gvjro5vyflnxxxyfnj5d4f4jlnht2ni336i4kad.onion
```

It generated a hidden service config in the working directory:

```
user@nowhere:/srv/mkp224o$ ls -lah | grep redlib

drwx------ 2 root root 4.0K Aug  4 16:58 redlibjdijbebprm5gvjro5vyflnxxxyfnj5d4f4jlnht2ni336i4kad.onion

user@nowhere:/srv/mkp224o$ ls -lah redlibjdijbebprm5gvjro5vyflnxxxyfnj5d4f4jlnht2ni336i4kad.onion

total 20K
drwx------ 2 root root 4.0K Aug  4 16:58 .
drwxr-xr-x 8 root root 4.0K Aug  4 16:58 ..
-rw-r--r-- 1 root root   63 Aug  4 16:58 hostname
-rw-r--r-- 1 root root   64 Aug  4 16:58 hs_ed25519_public_key
-rw------- 1 root root   96 Aug  4 16:58 hs_ed25519_secret_key
```

Let's move it to `/var/lib/tor/onions` for convenience

```
user@nowhere:/srv/mkp224o$ sudo mv redlibjdijbebprm5gvjro5vyflnxxxyfnj5d4f4jlnht2ni336i4kad.onion /var/lib/tor/onions/redlibjdijbebprm5gvjro5vyflnxxxyfnj5d4f4jlnht2ni336i4kad.onion

user@nowhere:/srv/mkp224o$ sudo ls -lah /var/lib/tor/onions/

total 12K
drwx------ 3 root       root       4.0K Aug  4 17:09 .
drwx--S--- 4 debian-tor debian-tor 4.0K Aug  4 17:07 ..
drwxr-xr-x 2 root       root       4.0K Aug  4 17:09 redlibjdijbebprm5gvjro5vyflnxxxyfnj5d4f4jlnht2ni336i4kad.onion

user@nowhere:/srv/mkp224o$ sudo ls -lah /var/lib/tor/onions/redlibjdijbebprm5gvjro5vyflnxxxyfnj5d4f4jlnht2ni336i4kad.onion

total 20K
drwxr-xr-x 2 root root 4.0K Aug  4 17:09 .
drwx------ 3 root root 4.0K Aug  4 17:09 ..
-rw-r--r-- 1 root root   63 Aug  4 16:58 hostname
-rw-r--r-- 1 root root   64 Aug  4 16:58 hs_ed25519_public_key
-rw------- 1 root root   96 Aug  4 16:58 hs_ed25519_secret_key
```
Make sure to keep these key files safe. If someone gains access to them, they can hijack your .onion address.

Now, let's give the files the right file permissions:

```
user@nowhere:/srv/mkp224o$ sudo chmod 700 /var/lib/tor/onions/redlibjdijbebprm5gvjro5vyflnxxxyfnj5d4f4jlnht2ni336i4kad.onion

user@nowhere:/srv/mkp224o$ sudo chmod 400 /var/lib/tor/onions/redlibjdijbebprm5gvjro5vyflnxxxyfnj5d4f4jlnht2ni336i4kad.onion/*

user@nowhere:/srv/mkp224o$ sudo chown debian-tor: /var/lib/tor/onions -R
```

### Configuring Tor

Now, that we have our custom onion address, we should configure Tor to make our .onion reachable.

(If you didn't generate a custom address, just set HiddenServiceDir to `/var/lib/tor/onions/redlib/`, the onion link will be auto-generated in the `hostname` file inside the folder)

```
user@nowhere:/srv/mkp224o$ cat /etc/tor/torrc

HiddenServiceDir /var/lib/tor/onions/redlibjdijbebprm5gvjro5vyflnxxxyfnj5d4f4jlnht2ni336i4kad.onion/
HiddenServicePort 80 127.0.0.1:8080

HiddenServicePoWDefensesEnabled 1
HiddenServicePoWQueueRate 250
HiddenServicePoWQueueBurst 2500
```

Make sure your `HiddenServicePort` is configured to match the Redlib port you set in .env file.

To apply changes, restart Tor:

```
user@nowhere:/srv/mkp224o$ sudo systemctl restart tor.service
```

### How to use Redlib

To see if it is working, visit your .onion address. 

![](0.avif)

Now you can browse your favorite privacy laxist subreddits without being tracked.

### Adding instance to LibRedirect

To make every reddit link redirect to Redlib, you can use the LibRedirect extension.

You can set it up in Tor Browser using this [guide](../frontends_explained/index.md).

After installing LibRedirect, you can add your Redlib instance to it like shown below:

![](libredirect_redlib.avif)

**Don't forget to add http:// before your instance's onion address. If you didn't, nothing will happen when you press on + in step 5.**

### Adding your instance to the Redlib Instances list

If you want to have your Redlib instance serving more people, you can add it to the official instance list.

To add your Redlib instance to the official Redlib Instance list, you have to register a GitHub account and make a pull request.

Since Github is salty about single IPs having multiple accounts, they flag most of the Tor exit nodes as spam.

If you get flagged, you cannot make forks or PR's, and you're forced to add 2FA to your account to contact Github support.

Let's go an easier path and just pick a new Tor exit node, so we dont get a flagged account.

1\. Get a new Tor exit node

Go to [the tor nodes list](https://metrics.torproject.org/rs.html#search/flag:exit%20flag:running%20first_seen_days:0-0%20running:true) and click on any of the new nodes. The link is filtered to only show the new nodes.

![](5.avif)

Copy its fingerprint.

![](6.avif)

Run this to add an exit node to your Tor config.

Remember to change the parameter to the fingerprint of your choice.

```
echo 'ExitNodes Y0URF1NG3RPR1N7H3R3' >> /etc/tor/torrc
```
If you use Whonix:
```
echo 'ExitNodes Y0URF1NG3RPR1N7H3R3' >> /usr/local/etc/torrc.d/50_user.conf
```

Apply changes by restarting your Tor daemon

Restart Tor daemon:
```
sudo systemctl restart tor.service
```
If you use Whonix:
```
sudo systemctl restart tor@default.service
```

**Warning: do not forget to revert changes to your tor config after completing the tutorial. Using a single tor exit node can compromise your anonymity.**

Now check if your IP matches the Tor node you chose.

![](7.avif)

2\. Register on GitHub

Register a Github account in Tor browser.

Your safety preset has to be "Safer" to be able to sign up.

![](8.avif)

Complete the captcha. This will require some mental skills.

![](9.avif)

Verify your account with the code sent to your Email.

![](10.avif)

Now, sign in to Github.

![](11.avif)

After signing in, fork the [Redlib Instances repository](https://github.com/redlib-org/redlib-instances).

![](12.avif)

![](13.avif)

Copy the link to your fork and clone it:

```
git clone https://github.com/UserSurname69/redlib-instances.git && cd redlib-instances

Cloning into 'redlib-instances'...
remote: Enumerating objects: 2013, done.
remote: Counting objects: 100% (530/530), done.
remote: Compressing objects: 100% (89/89), done.
remote: Total 2013 (delta 509), reused 451 (delta 441), pack-reused 1483 (from 2)
Receiving objects: 100% (2013/2013), 280.92 KiB | 431.00 KiB/s, done.
Resolving deltas: 100% (1444/1444), done.
```

3\. Create a Personal Access Token

To push the changes to your fork with Git, you have to create a Personal Access Token.

Click on your profile picture on the top right corner.

Then, go to Settings

![](14.avif)

Go to Developer settings

![](15.avif)

Go to Classic tokens, and click on Generate new token

![](16.avif)

Add a note to it and give it `repo` permissions

![](17.avif)

Click on Generate token

![](18.avif)

Save your token somewhere safe, you will need it later in this tutorial.

![](19.avif)

4\. Add your Redlib instance.

Now, there are three files you have to add your instance to:

- `instances.txt`
- `instances.json`
- `instances.md`

You can and should add your instance with the built-in scripts. I do not recommend editing the files yourself.

Add a CSV row to `instances.txt` like that:

```
echo 'http://redlibjdijbebprm5gvjro5vyflnxxxyfnj5d4f4jlnht2ni336i4kad.onion,US,false,"Alices Redlib instance!!!"' >> instances.txt
```

The CSV format is:

1\. url (REQUIRED) - Must be an HTTPS, except if it is an onion service.

2\. country code (REQUIRED) - Two-letter country code in uppercase.

3\. cloudflare enabled (REQUIRED) - True if cloudflare captcha is enabled, false if it is not.

4\. Description (REQUIRED) - A description of the instance; a description can be blank, but one must be provided for the script to parse the CSV correctly. As this description string becomes a JSON value without any transformation, any special characters, including and especially newlines, must be escaped.

Make sure you have Tor daemon running, and have curl and jq installed before you launch this script.

**If you're running this script in Whonix**, replace the line `pidof -q tor` with `true` in `generate-instances-json.sh`. This is because the script checks for a Tor process, which doesnt run in Whonix Workstation, but in the Gateway instead.

Run this to replace the existing `instances.json` with a new one that has your instance:

```
generate-instances-json.sh -i ./instances.txt -o ./instances.json
```

Run this to do the same with `instances.md`:

```
generate-instances-markdown.py --output=./instances.md ./instances.json
```

Now, your instance list is ready. Commit and push it to your fork:

**Paste your Personal Access Token here instead of your password**

```
git commit -a -m "Added Alice's Redlib instance"
git push

Username for 'https://github.com': UserSurname69
Password for 'https://UserSurname69@github.com': 
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Delta compression using up to 2 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 396 bytes | 396.00 KiB/s, done.
Total 3 (delta 2), reused 0 (delta 0), pack-reused 0
remote: Resolving deltas: 100% (2/2), completed with 2 local objects.
To https://github.com/UserSurname69/redlib-instances.git
   8bb8507..bb6449e  main -> main
```
5\. Make a Pull Request

Click on Pull requests tab

![](20.avif)

Create a new pull request

![](21.avif)

Choose your fork

![](22.avif)

Create a pull request and name it "Add \[yourinstancehere.onion\] instance"

Now, you just wait until the pull request is accepted. Be advised that this list is constantly modified, and to stay in the list, you have to keep your Redlib instance up and running.

**Reminder: revert changes to your Tor config. Using a single tor exit node can compromise your anonymity.**

You can use this command to remove the last line of your Tor configuration file, assuming you ran `echo "x" >> torrc` previously.

```
echo $(sed '$d' /etc/tor/torrc) > /etc/tor/torrc
```
Or, if you use Whonix:
```
echo $(sed '$d' /usr/local/etc/torrc.d/50_user.conf) > /usr/local/etc/torrc.d/50_user.conf
```

Check your Tor configuration file to check if the changes have been applied:

```
cat /usr/local/etc/torrc.d/50_user.conf

# Tor user specific configuration file
#
# Add user modifications below this line:
############################################
```

Restart your Tor daemon to apply changes:

```
sudo systemctl restart tor.service
```

If you use Whonix:

```
sudo systemctl restart tor@default.service
```

### Adding your instance to the Darknet Lantern

1\. Setup your Darknet Lantern Instance

Setup your own Darknet Lantern instance using this [guide](../darknetlantern/index.md).

2\. Run the Darknet Lantern script

```
user@nowhere:/srv/darknet-lantern$ python3 run_lantern.py
```

Add your Redlib Instance to the list

```
Select an option? (0-12): 1

Add a new Website entry
Enter entry's category: Privacy front-ends
Enter entry's name: Alices redlib instance
Enter entry's url: http://redlibjdijbebprm5gvjro5vyflnxxxyfnj5d4f4jlnht2ni336i4kad.onion
Enter is entry sensitive(YES or NO): NO
Enter entry's description: Alices public redlib instance 
Enter entry status(YES or NO): YES
Enter entry's score (0 - 100): 100
Verified and unverified saved successfully
New row added! now writing the csv file
```

3\. Participate in a Webring

To get the links you added visible on the other Darknet Lantern instances, you should participate in a webring.

You can learn how to participate in the Nowhere Webring [here](../darknetlantern/index.md#how-to-participate-in-the-webring).

## Conclusion

In this tutorial, we set up a public Redlib instance as a Hidden Service. We added it to LibRedirect in our browser, to make every Reddit link redirect to our Redlib instance.

We also listed it on the Darknet Lantern and on the Redlib Instance List, to contribute to decentralization to let other users browse Reddit privately.
