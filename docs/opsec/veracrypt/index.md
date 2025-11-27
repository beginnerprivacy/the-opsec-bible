---
author: nihilist & Oxeo0
date: 2025-04-01
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/255"
xmr: 862Sp3N5Y8NByFmPVLTPrJYzwdiiVxkhQgAdt65mpYKJLdVDHyYQ8swLgnVr8D3jKphDUcWUCVK1vZv9u8cvtRJCUBFb8MQ
tags:
  - Clientside Deniability
  - Core Tutorial
---
# The main source of Plausible Deniability: Deniable Encryption

```
TLDR: Veracrypt protects you against the threat of an adversary forcing you to type a password. Because depending on which password you type you either open the decoy volume or the hidden volume, and there's no way to prove or disprove the existance of the hidden volume. That's where you can safely store your sensitive data.
```

![](0.png)

[zuluCrypt](https://mhogomchungu.github.io/zuluCrypt/) is a free and open-source tool for encrypting files and volumes in a secure way. We already used it for [hiding data in video files](../anonzulucrypt/index.md) using steganography.  
Today, we'll use it as a replacement for VeraCrypt - a free open source disk encryption software for Windows, Mac OSX and Linux. Being based on TrueCrypt, VeraCrypt offers a unique feature called **Hidden Volumes** which can give us **Plausible Deniability**. zuluCrypt supports both TrueCrypt and VeraCrypt volumes while being better integrated in Linux ecosystem. It also comes preinstalled with [kicksecure OS](https://www.kicksecure.com/). 

## But why is Plausible Deniability important first of all?  
From a legal perspective, depending on jurisdictions, you may be forced to type your password into an encrypted drive if requested. **All it takes is for an adversary to be able to prove the existence of an encrypted drive to be able to force you to reveal the password to unlock it**. Hence for example the regular LUKS encryption is not enough, **because you need to be able to deny the existence of the encrypted volume**. If that is the case, we have to use veracrypt encrypted volumes, which is an encryption tool used to provide deniable encryption (which is what gives you Plausible Deniability) against that scenario where you're forced to provide a password.

![](../deniability/5.png)

Using Veracrypt encrypted volumes, you have a decoy volume which is there by default (that spans the entire encrypted volume) **and you CAN have a hidden volume if you choose to, which is hidden in the decoy volume** , it's also known as the "inner volume", and the only way to reveal that the hidden volume exists, is to use the correct secret password to both unlock it. If the encrypted volume doesn't exist, legally speaking you cannot be forced to unlock it, because it doesn't exist to begin with, as far as the adversary's concerned.

**DISCLAIMER: we're using only harddrives (HDDs) here, because using SSDs are not a secure way to have Plausible Deniability, that is due to hidden Volumes being detectable on devices that utilize wear-leveling**
    
    
    source: https://anonymousplanet.org/guide.html#understanding-hdd-vs-ssd
    
    regarding wear leveling:
    "Also as mentioned earlier, disabling Trim will reduce the lifetime of your SSD drive and will significantly impact its performance over time (your laptop will become slower and slower over several months of use until it becomes almost unusable, you will then have to clean the drive and re-install everything). But you must do it to prevent data leaks that could allow forensics to defeat your plausible deniability. The only way around this at the moment is to have a laptop with a classic HDD drive instead."
    
**WARNING: YOU NEED TO IMPLEMENT [LIVE MODE AND RAM-WIPE](../livemode/index.md) ON THE [KICKSECURE HOST OS](../linux/index.md) TO IMPLEMENT THE FOLLOWING SETUP!**

## _OPSEC Recommendations:_

  1. Hardware : (Personal Computer / Laptop)

  2. System Harddrive: not LUKS encrypted [[1]](https://www.kicksecure.com/wiki/Ram-wipe)

  3. Non-System Harddrive: 500Gb (used to contain our VeraCrypt encrypted volumes)

  4. Host OS: [KickSecure](../linux/index.md)

  5. Hypervisor: [QEMU/KVM](../hypervisorsetup/index.md)

  6. Packages: [grub-live and ram-wipe](../livemode/index.md)

![](../context/sensitive.png)


In this tutorial requires you to have implemented the following setup:

![](20.png)

As we have explained [previously](../livemode/index.md) the Host OS being in live mode is a crucial requirement to be able to maintain deniability, on top of erasing the contents of the RAM upon rebooting the Host OS, because we need to make sure that the adversary is not able to see what we were doing on the computer before they manage to get their hands on it. **The Veracrypt encrypted volumes are now going to enable us to store sensitive data that can be accessed again after rebooting.** To do so, _we need to save the veracrypt encrypted volume on a non-system drive_ , because if we were to store it on the system drive, it'd disappear when we reboot the computer to exit live mode !



## **Using Zulucrypt to create Hidden Veracrypt volumes**

Since we are using Kicksecure as a Host OS, we can install zulucrypt via apt:  

```
sudo apt update -y 
sudo apt install zulucrypt-cli zulucrypt-gui exfat-fuse -y
```

then we open it:

![](1.png)

So now you have zuluCrypt on your system. **However before you start to use it, make sure that your Host OS is in live mode, as otherwise you wouldn't be able to maintain your deniability regarding the existence of the veracrypt hidden volume**

![](../livemode/3.png)

By default, your host OS directly writes into the system drive all sorts of potential forensic evidence that an adversary may use against you, such as system logs, kernel logs, non-standard logs, etc, and unless if you remove each of those manually, you're never sure of whether or not the Host OS saved proof of the existence of the hidden volume onto the system drive. **That's why when you use zulucrypt to handle veracrypt hidden volumes (creating them or opening them) you absolutely need to use the Host OS in[live mode](../livemode/index.md) ONLY! **

![](../livemode/4.png)

When the Host OS is in live mode, you're loading the entire host OS in the RAM, meaning that you are not writing anything on the system drive anymore, **but rather you are only writing all that potential forensic evidence of the veracrypt hidden volume _in RAM alone_ , which can be easily erased with a simple shutdown thanks to both live mode and ram-wipe**.

So if you didn't do it already, reboot the Host OS into live mode:

![](../livemode/12.png)

**And only now once we are in live mode, we can use zuluCrypt to create hidden encrypted volumes and unlock them.** But be aware that everything you write into the system drive will be wiped upon shutting down, **if you want to store something persistent accross reboots from live mode, you need to save it in a non-system drive.**
    
    
    [user /run/media/private/user]% lsblk
    NAME                                          MAJ:MIN RM  SIZE RO TYPE  MOUNTPOINTS
    sr0                                            11:0    1 1024M  0 rom   
    vda                                           253:0    0  200G  0 disk  
    ├─vda1                                        253:1    0    4G  0 part  /boot
    └─vda2                                        253:2    0  196G  0 part  
      └─luks-24351c83-3657-4142-82d2-8f8a5787f406 254:0    0  196G  0 crypt /live/image
    vdb                                           253:16   0   20G  0 disk  
    └─vdb1                                        253:17   0   20G  0 part  
    
    

Here as you can see we have a non-system drive called /dev/vdb1, which, for our current testing purposes is only 20 GB big. Before we start encrypting it, let's format the harddrive using gparted to make sure the vdb1 partition is available for us to use:

![](31.png) ![](32.png) ![](33.png) ![](34.png) ![](35.png) ![](36.png)

Now that the /dev/vdb1 partition is available for us to use, let's create the veracrypt encrypted volume which will span the entire non-system drive:  
![](2.png) ![](37.png) ![](38.png) ![](39.png) ![](40.png)

Here is the important part: you need to mention **Password A for the decoy volume** (which is the outer volume, it will span the entire disk), and you need to mention **Password B for the hidden volume** (which is the hidden veracrypt volume where we'll be able to store our sensitive files)

**WARNING (11/05/2025): Do not use the default ext4 filesystem type for veracrypt volumes, as writing in an ext4 decoy volume may overwrite the hidden volume at random (i tested it by writing a random 100mb file in a 300mb ext4 decoy volume, and it started overwriting the hidden volume, unlike with an exfat filesystem), therefore we need to use the exfat filesystem, to prevent this problem:**


(Special thanks to VioletSentiment for finding this btw, since i overlooked it initially)

![](41.png)

Here click create, then wait for the volume to be created (it takes some time because it needs to write random data on the disk initially)

![](42.png) 

![](43.png)

And that's it! We have successfully created the veracrypt volume, so now let's mount each one:

## **Mounting the Decoy and Hidden Volumes**

First let's mount the decoy volume (which we'll later use to store non-sensitive files, that would make sense for an adversary to keep in an encrypted drive):

![](44.png) 

![](45.png) 

![](46.png) 

![](47.png) 

![](52.png)

Here as you can see, the decoy volume once mounted spans the entire non-system drive (in this case 20GB). **So if you were forced to open it for an adversary, they would only find non-sensitive files** (for example pirated movies or adult content) that are stored in it. And since the volume spans the entire drive, **you can deny the existance of any other encrypted volume in there, and the adversary would be unable to prove otherwise.** This means that our deniability is maintained.

![](48.png)

Next we'll unmount the decoy volume to mount the hidden volume instead:

![](49.png)

At this step you need to make sure that noone is watching you type this second password, **as this second volume needs to remain a secret at all costs, it's existance is only to be known by you.**

![](50.png)

![](51.png)

And now after unlocking the hidden volume (and revealing it at the same time), we see that it is 10GB big, as intended. **And it is only in that hidden volume, that you can safely store your sensitive files which are meant to remain secret at all costs.**

![](53.png)

if there were to be any emergency where someone would be close to discovering that there is a hidden volume (meaning the adversary is busting down your door and is almost next to your monitor) **all you need is to press Right Control to immediately reboot the host OS, to be able to erase all forensic proof that the hidden volume exists.**

