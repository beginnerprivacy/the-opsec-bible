---
author: bleak
date: 2025-07-21
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/329"
xmr: 43fPQSRfkorKmDrC7Toqw67yimcV8VKbxYudY1zQp6Z7XiuboXTmnAdifGrsCP5bF8A7qNDedAhEQ3TwCegudmrA1U5bgUp
tags:
    - Serverside Deniability
---

# USB-triggered server shutdowns

```
TLDR: you can trigger emergency shutdowns by detecting USB changes with a simple bashscript.
```

In this guide you will learn how to set up a trigger such that your home server shuts down if any USB devices are added or removed.
This is similar to [USB-triggered shutdowns](../usbdeadmansswitch/index.md). The only difference is that this is server-focused and therefore has a slightly different bash script.

**Note: This guide assumes that you have a [homeserver](../homeserver/index.md) setup on a configuration similar to [sensitivevm](../sensitivevm/index.md).**

## Threat model
- This is an anti-tampering setup.
- You are running a sensitive website or service from your home server.
- You are a high-value target for LE.
- Or you just want to prevent your siblings from tampering with your systems. ;)

---

## Setup
1. Make sure you have `lsusb` installed. Usually the package name would be `usbutils`.
```bash
user ~$ sudo apt install usbutils
user ~$ lsusb
Bus 0xx Device 0xx: ID xxxx:xxxx Logitech Wired Mouse
Bus 0xx Device 0xx: ID xxxx:xxxx HP, Inc USB Flash Drive
.
.
.
```
Once you see a list of USB devices, you're good to proceed to the next step.

2. Make sure you have `reboot.sh` in your home directory. (This isn't mandatory. You'll see why below.)
```bash
user ~$ cat reboot.sh
#!/bin/bash

/usr/bin/sudo /usr/sbin/reboot now
```

3. Copy the following bash script and give it executable permissions.
```bash
#!/bin/bash

# nukeusb.sh
# A script by bleak.

# Variables
INTERVAL=1                        # <-- interval to check the devices in.
TRIGGER="sh /home/user/reboot.sh" # <-- command to run if a USB device was added or removed.

# Get initial list of USB devices
prev_devices=$(lsusb)

echo "Monitoring for any USB device changes..."
echo "Press Ctrl+C to stop."

while true; do
  current_devices=$(lsusb)

  if [[ "$current_devices" != "$prev_devices" ]]; then
    $TRIGGER
    exit
    prev_devices="$current_devices"
  fi

  sleep "$INTERVAL"
done
```

### How it works

![](0.png)

1. Once you run the script, it starts checking for any changes in the output of `lsusb` (list of connected USB devices).
2. If it detects a change, it runs the `$TRIGGER`, whatever you set it to. In this case, it would run `execute /home/user/reboot.sh`, rebooting the system and removing all evidence, given you have a plausibly deniable setup.

---

## Usage

Tweak the variables present at the beginning of the script to whatever you like. 

**Note: Make sure you aren't running any commands that require you to enter a password. If you need to run superuser commands, either set a NOPASSWD rule for that command, or run the script as root. We want everything to be quick and automatic.**
_You can find a guide to setting up a NOPASSWD rule in the sensitivevm guide [here](../sensitivevm/#fine-tuning-the-emergency-reboot-script)._

- Remember that every time you connect or disconnect a device to the server, it executes the `$TRIGGER`. This includes any mouse or keyboard you'd connect while the script is running.
- Remember to run the script after you've completely set your server up. We don't want to have any false positives that might occur while you're setting things up, connecting and disconnecting devices, etc.

---

## What exactly is this for?

In case your house was broken into and the server is being seized, LE might try to connect their own device to the server, to either exfiltrate your data, or to prevent the server from turning off. We're using exactly this against them by having the server poweroff when they connect something. It is essentially a nuke that they themselves will set off.

This reminds me a lot of the GrapheneOS Duress PIN tactic as described [here](../duresspin/index.md#considerations). The following is the relevant text:

> "It might be worthwhile to consider writing your duress PIN on a piece of paper and placing this paper in your phone case. Should anyone find your phone or compel you to give it to them, they may inadvertently enter your duress PIN thinking you were forgetful and had to write down you PIN."

*Note: Entering the duress pin causes GrapheneOS to factory-reset the phone, which is similar to our script which shuts the system down, encrypting the data (If you have FDE).

---

## Optional setup

Manually executing the script every time you reboot server can be a hassle. If the server reboots by itself due to a power outage or kernel panics, most of the time you wouldn't even know it happened. Therefore, we are going to set up a systemd service to start the script automatically.
If you're going to set this up, you don't need to invoke `sudo` in the `$TRIGGER` variable or the `reboot.sh` script, as `nukeusb.sh` would run as root anyways.

1. **Setting up the systemd service**

    Create `/etc/systemd/system/nukeusb.service`.

    ```bash
    user ~$ sudo vim /etc/systemd/system/nukeusb.service
    ```
    Enter the following code:
    ```ini
    [Unit]
    Description=execute nukeusb.sh
    
    [Service]
    Type=oneshot
    ExecStart=/bin/bash /home/user/nukeusb.sh
    RemainAfterExit=yes

    [Install]
    WantedBy=multi-user.target
    ```

    Now we **define a timer unit**.

    ```bash
    user ~$ sudo vim /etc/systemd/system/nukeusb.timer
    ```

    Enter the following code; adjust wherever needed.
    ```ini
    [Unit]
    Description=delay nukeusb.service on boot
    
    [Timer]
    # Waits 3 minutes after boot before executing nukeusb.
    OnBootSec=3min
    Unit=nukeusb.service
    
    [Install]
    WantedBy=timers.target
    ```
    
2. **Enable the service**

    ```bash
    # Reload to recognize new units
    sudo systemctl daemon-reload

    # Enable & start the timer
    sudo systemctl enable --now nukeusb.timer
    ```

3. **Check if the timer is running**

    ```bash
    systemctl list-timers --all
    ```

**Note: Change the `OnBootSec` value as needed. Make sure you actually restart and test if the service is working.**

---

## Conclusion

There you have it! We have now set up a script that turns off the system when a USB device is connected or disconnected. The use cases are infinite.

**DISCLAIMER**: This blog's [stance](../stancesensitive/index.md) is not to endorse sensitive activities and nothing in this article serves as legal advice. You are responsible for whatever you do, unless found not guilty.
