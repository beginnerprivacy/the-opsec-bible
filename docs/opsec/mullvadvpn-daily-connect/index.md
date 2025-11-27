---
author: loki_opsec_inc
date: 2025-07-17
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/350"
xmr: 8AaLSmixWFJhgMmrBvqi6827v27YYT6H8C6SjUasHySBKna2JDk1dtEf2ZAUpXue64JDEBxkTL9oZGaoKtcWppWKHLSkTLM
---
# Scheduled Automatic Server Randomization with Mullvad VPN CLI

```
You can configure your Mullvad VPN to randomly change the servers it connects to with a simple bashscript and cronjob.
```

In this tutorial we will show you how to increase your VPN OpSec by setting up a scheduled daily `cron` job that will pick a random time once a day and switch your VPN connection to random servers.

## Why would I want this?

As we know, the key to successful anonymity is randomization. TOR uses this as its foundational principle for operation. We can also accomplish this on our own as well! Here you can see the potential added complexity for your network pathway even with just a daily VPN server switch on a 7-day multihop stint:

![](./anon-set.png)

## Pre-Requisites and Setup

This tutorial assumes that you have some basic experience with Linux.

It also assumes you have Mullvad installed and have logged into your account. You can find those details on Mullvad's website: [Clearweb](https://mullvad.net) | [Onion](http://o54hon2e2vj6c7m3aqqu6uyece65by3vgoxxhlqlsvkmacw6a7m7kiad.onion) and also by using our guides to [Install](../vpn/index.md) and to [Prevent Leaks](../vpnqemu/index.md)

Be sure that your cron and Mullvad services are both running and enabled:
```
systemctl status cron # might also be called crond
systemctl status mullvad-daemon
```

There is a utility you'll need to use in this tutorial, `shuf`, which you can check if you have it by running `shuf --version`. Most mainstream linux distros have it, but if you don't, you'll need to install [GNU Core Utilities](https://www.gnu.org/software/coreutils/). It will likely be available to your package manager, so for example, Debian-based systems, you'll install it like so: `sudo apt install coreutils`

Finally, to prevent leaks, be sure to switch Mullvad to Lockdown mode, so that you will never make connections outside of the VPN tunnel:
```
mullvad lockdown-mode set on
```

During any time in this tutorial, you can check the connection status of Mullvad using:
```
mullvad status
```

You can also see what's going on by starting the Mullvad GUI from your launcher, this makes it very easy and updates automatically with whatever you do on the CLI

## Setting Server Constraints

When you connect to Mullvad, you will use the command `mullvad connect` if disconnected or `mullvad reconnect` if already connected. This by default will pick a random server based on whatever the current constraints are set to. Constraints are essentially filters that tell Mullvad which servers you want to use and which to avoid. You can view what your current constraints are by running `mullvad relay get`

If you want to view all the constraints that are available you can run:
```
$ mullvad relay set
Set relay constraints, such as location and port

Usage: mullvad relay set <COMMAND>

Commands:
  location         Select a relay using country, city or hostname. The 'mullvad relay list' command shows the available relays and their geographical location
  custom-list      Set custom list to select relays from. Use the 'custom-lists list' command to show available alternatives
  provider         Set hosting provider(s) to select relays from. The 'list' command shows the available relays and their providers
  ownership        Filter relays based on ownership. The 'list' command shows the available relays and whether they're rented
  tunnel           Set tunnel protocol specific constraints
  tunnel-protocol  Set tunnel protocol to use: 'wireguard', or 'openvpn'
  custom           Set a custom VPN relay to use
  help             Print this message or the help of the given subcommand(s)
```
We're going to show you a few examples of constraints you may want to enable for higher OpSec setups:

```
# Only use wireguard servers
mullvad relay set tunnel-protocol wireguard

# Always use multihop
mullvad relay set tunnel wireguard -m on

# Only use servers whose hardware is owned and controlled by Mullvad:
mullvad relay set ownership owned

# By default the entry server will always be Sweden. You can remove this by running:
mullvad relay set tunnel wireguard entry location any
```

One last consideration is to set a **static entry relay** using the relay constraints. This might be a good move for high OpSec so that your ISP isn't watching you constantly connect to random relays at the same time as your exit relay, in case your exit relays are pinpointed somehow. TOR does the same thing with Guard Nodes. You can set this using the following command (assuming Wireguard):
```
mullvad relay set tunnel wireguard <location>
```

In any case, now let's view all our current constraints:
```
$ mullvad relay get
Generic constraints
    Location:               any
    Tunnel protocol:        WireGuard
    Provider(s):            any
    Ownership:              Mullvad-owned servers
OpenVPN constraints
    Port:                   any
    Transport:              any
WireGuard constraints
    Port:                   any
    IP protocol:            any
    Multihop state:         enabled
    Multihop entry:         any
```
As you can see, in this example we'll only be using Wireguard servers whose hardware are owned by Mullvad, in multihop mode.

Now, assuming you're already connected to the VPN by using `mullvad connect`, try reconnecting a few times and see the servers change each time:

```
$ mullvad reconnect

$ mullvad status
Connected
    Relay:                  fr-par-wg-006 via nl-ams-wg-004
    Features:               Lockdown Mode, Multihop, Quantum Resistance
    Visible location:       France, Paris

$ mullvad reconnect

$ mullvad status
Connected
    Relay:                  se-sto-wg-004 via no-osl-wg-001
    Features:               Lockdown Mode, Multihop, Quantum Resistance
    Visible location:       Sweden, Stockholm
```

## Creating the randomized cronjob

If you don't already know, `cron` is a scheduler system that pretty much every single Linux distro has. However, as it does not have built-in randomization capabilities, we will tell cron to run a custom script that does some randomization for us.

In this tutorial we'll show you how to configure the script to run do once per day at a random time sometime after noon, but also show you how to customize it the way you like.

First, create a new text file in your home directory called `connect_rand.sh`. Or you can call it what you like or place it somewhere else. In this file, you'll paste this script:

```
#!/bin/bash

RANDNUM=$(shuf -i 1-43200 -n 1)
sleep $((RANDNUM))s
mullvad reconnect
```
Let's go through what each line does.

`#!/bin/bash` denotes that the shell program to be used is `bash`. Be sure to include this or it won't work

`RANDNUM=$(shuf -i 1-43200 -n 1)` grabs a random number between the specified number range using the `shuf` command and assigns it to the variable `RANDNUM`. In this case these numbers correspond to a number of seconds between 1 second and 12 hours.

`sleep $((RANDNUM))s` gets that random number and will pause the script for that many seconds before executing the reconnect command.

`mullvad reconnect` will, of course reconnect the VPN tunnel and change the current server(s) to something else. Keep in mind that if the VPN is disconnected, this WON'T establish a new connection. You will just remain disconnected.

Save your file. Now we're going to edit our crontab file. This file tells cron what jobs to run and when, such as running our script we just made. In your terminal open the file with `sudo` privileges (you can use something else if you don't like `nano`)
```
sudo nano /etc/crontab
```
The comments in this file will explain to you how to write a line in the file. You specify the times in which your job should run, under what user, and what the job exactly is.

So at the bottom we'll add this line:
```
0 12 * * * myuser /home/myuser/connect_rand.sh
```
If you don't understand cron scheduler times very well I recommend you check out https://crontab.guru as it will help you understand how they work and let you play around with them. 

For the purpose of this tutorial all you need to know is that `0 12 * * *` says to run the job at exactly 12:00 (noon) each day. When the job runs the script, you see by looking back at our script that it will first sleep for some random amount of hours up to 12 hours. Combined with the cron schedule, this amount will determine that the Mullvad servers will rotate at a random time of the day between 12:00 Noon and 00:00 Midnight.

For example, if the random sleep number chosen was 16200 seconds (4.5 hours), we can say that 12:00 + 4.5 hours = 16:30 (4:30pm).

This is of course totally customizable to you. Let's give another example. Say you want to run the script twice a day. You could give a cron schedule of `0 6,18 * * *` and keep the sleep number range at `1-43200`. So the job would run at 6:00 and also at 18:00, plus whatever the random sleep interval is each time. 

Going back to our crontab file, the next part of the cronjob line, `myuser` you need to replace with the name of your linux user. And the final part is the job, in this case, running the script at the path specified. If your script is somewhere else you need to change the path. Do you not use `~/myuser....` to specify your HOME either, always use absolute paths.

After you save and exit your editor, you are done. You can view the cronjob logs in realtime with this command:
```
journalctl /usr/sbin/cron -f
```

## Conclusion

Congrats, so you have a scheduled script that will always change to random VPN servers at random times!

