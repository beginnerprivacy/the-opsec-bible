---
author: nihilist
date: 2025-04-01
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/160"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
tags:
  - Clientside Deniability
  - Core Tutorial
---
# Using the Host-OS in live-mode to enable Sensitive Use 

```
TLDR: To be able to deny the existance of veracrypt hidden volumes, you need the Host OS to be in Live mode.
```

![](0.png)

In this tutorial we're going to cover how to use livemode and ram-wipe from inside Kicksecure to enable long-term Sensitive use.

**WARNING: YOU NEED TO HAVE [KICKSECURE AS A HOST OS](../linux/index.md) TO IMPLEMENT THIS SETUP !**

## **What is the usecase ?**

The main usecase of using your Host OS in live mode, is that you want to use it for long term sensitive activities (meaning, you want to save sensitive files on a harddrive). **As you're going to see, using the Host OS in live mode is effectively a hard requirement for deniability**.

When we are talking sensitive use, we are talking about our need of Deniability. Which means that we need to use deniable encryption using [Veracrypt's hidden volumes](../veracrypt/index.md):

![](../deniability/5.png)

In theory it is impossible to prove the existence of the hidden volume by itself once it is closed, **and if there is no proof of it's existence our deniability is maintained.**

But the issue is that we have more variables that we also need to keep under control, on the Host OS side you have **system logs, kernel logs** , the various other **non-standard log files** that software is writing on the disk, and even **the content of the RAM itself** can be used to prove the existence of a hidden volume.

![](3.png)

Now when you are using your computer for regular public, private and anonymous activities, normally you don't need to care about those things. But the Host OS is a potential goldmine of forensic evidence to be used against you if the device were to be seized, **so for sensitive use specifically we need to take care of it.**

Now you could start to manually erase all logs, all kernel logs, all non-standard system logs, manually overwrite the RAM contents, but this is going to be way too tedious and you're likely to miss something. So we have one simple solution: **use the Host OS in live mode**.

Thanks to live mode, **we are able to load the entire Host OS in RAM directly** , allowing us to avoid writing anything on the system disk (no system logs, no kernel logs, no non-standard logs, **only ram contents to worry about**)

And since everything is loaded inside the RAM, **all we need is to reboot the computer to wipe all of the RAM contents** , effectively **erase all forensic evidence (and all potential forensic evidence) of the existence of the hidden volume in one simple action.**

## **Using Live Mode from the System Drive**

⚠️ _Deniability Disclaimer:_ **This setup is only suitable if the adversary can be told that you are using Kicksecure, without it being a reason to throw you in jail. Do not proceed if that's the case.** ⚠️

![](4.png)

If you have followed the ["How to install Kicksecure as a Host OS"](../linux/index.md) tutorial, you already have the correct base to work on, since the operating system comes with the capability to enter Live mode from the grub boot menu: 

![](11.png)

To enter live mode, we simply restart the computer, and select the following boot entry:

![](12.png)

Then as ususal, enter your passphrase to unlock your encrypted system drive:

![](../linux/53.png)

And then once you boot back into your Host OS, you can run **lsblk** from a terminal to confirm that you are in live mode:

![](13.png)
    
    
    [user ~]% lsblk
    NAME                                          MAJ:MIN RM  SIZE RO TYPE  MOUNTPOINTS
    sr0                                            11:0    1 1024M  0 rom   
    vda                                           253:0    0  200G  0 disk  
    ├─vda1                                        253:1    0    4G  0 part  /boot
    └─vda2                                        253:2    0  196G  0 part  
      └─luks-24351c83-3657-4142-82d2-8f8a5787f406 254:0    0  196G  0 crypt /live/image
    vdb                                           253:16   0   20G  0 disk  
    └─vdb1                                        253:17   0   20G  0 part  
    
    

As you can see, **the system drive /dev/vda is mounted in the /live/image mountpoint** , which confirms that we are now in live mode!

## **Testing Live Mode**

The main point of using live mode is that everything you write onto the system disk gets wiped upon reboot, so let's test the following:

![](14.png)

We'll write the Test A.txt file into the system drive, and the Test B.txt file in a non-system drive:
    
    
    [user ~]% vim /home/user/TestA.txt
    [user ~]% cat /home/user/TestA.txt
    this is Test A: this file should no longer exist upon rebooting.
    (because it sits on the system drive, while in livemode, meaning it's loaded in RAM)
    
    [user ~]% sudo mkdir /mnt/externaldisk
    [user ~]% sudo mount /dev/vdb1 /mnt/externaldisk
    
    [user ~]% sudo vim /mnt/externaldisk/TestB.txt
    [user ~]% cat /mnt/externaldisk/TestB.txt
    This is test B: the file should remain after rebooting, because it sits on a non-system drive
    
    

**The test will pass if upon rebooting, if TestA.txt no longer exists, and TestB.txt still does, because one sits on the system drive, and not the other.** So let's reboot the host OS to test that:
    
    
    [user ~]% sudo reboot now 
    	
    

![](15.png) ![](../linux/53.png)

And once booted in we check if TestA.txt has indeed disappeared, and if TestB.txt is still there:

![]()
    
    
    [user ~]% cat TestA.txt
    cat: TestA.txt: No such file or directory
    
    [user ~]% mount /dev/vdb1 /mnt/externaldisk
    [user ~]% sudo mkdir /mnt/externaldisk
    [user ~]% sudo mount /dev/vdb1 /mnt/externaldisk 
    [user ~]% cat /mnt/externaldisk/TestB.txt 
    This is test B: the file should remain after rebooting, because it sits on a non-system drive
    	
    

And that's it! We have now validated that the TestA.txt file that was on the system drive while on live mode no longer exists after rebooting, and that the TestB.txt file on the non-system drive still exists, which validates that live mode works as intended.

## **Wiping RAM upon reboots**

Now to make sure that the data doesn't sit in the memory sticks when the computer is rebooting (meaning to prevent cold-boot attacks), we make sure that the RAM gets wiped upon reboot, thanks to Kicksecure's [ram-wipe](https://www.kicksecure.com/wiki/Ram-wipe) package:
    
    
    [user ~]% sudo apt install ram-wipe -y 
    
    

once installed, upon rebooting you can see it in action:
    
    
    [user ~]% sudo reboot now 
    
    

![](16.png)

Here as you can see the TTY outputs tells us that the RAM contents are being wiped off. It also mentions that it is OK upon the boot sequence when it asks you to unlock your system drive: 

![](17.png)

Cold boot attacks (freezing memory sticks to make sure the data remains intact, and then attempting to boot into the OS from the data contained in those ramsticks alone) is a very unlikely attack that could happen when an adversary busts down your door to try and seize your devices:

![](../cloud_provider_adversary/7.png)

But thanks to the ram-wipe mechanism we just implemented, as long as you make the host OS reboot before the adversary manages to put their hands on the computer, you are protecting against that scenario aswell. 

## **Emergency Reboot Shortcut**

However there's a problem. Right now to reboot you need to click the desktop menu, click log out, and then click restart:

![](11.png)

Obviously, when you have an adversary busting down your door, you don't have time to aim with your mouse and click 3 times to reboot your computer. Therefore, **To speed up the process of rebooting, we implement a simple reboot bashscript that we'll trigger using a single keystroke, thanks to a shortcut we configure:**
    
    
    [user ~]% vim reboot.sh
    [user ~]% cat reboot.sh
    #!/bin/bash
    
    /usr/bin/sudo /usr/sbin/reboot now
    
    [user ~]% chmod +x ./reboot.sh
    

And we make sure that we can trigger it by pressing a single keystroke (right control):
    
```
xfconf-query -c xfce4-keyboard-shortcuts -n -t 'string' -p '/commands/custom/Control_R' -s "sh /home/user/reboot.sh"
```
    
And then to ensure that it doesnt need the sudo password to be ran, you add the following line *at the end* of visudo file:

```sh hl_lines="8"
[user ~]% sudo visudo

[...]
# See sudoers(5) for more infomation on "@include" directives:

@includedir /etc/sudoers.d

user  ALL=(ALL) NOPASSWD:/usr/bin/systemctl, /usr/bin/zuluCrypt-cli, /usr/sbin/reboot, /usr/bin/virsh
```

## Conclusion

And that's it!

**Now thanks to that setup, pressing the Right Control key is all you need** to reboot your Host OS, to effectively exit live mode, wipe off all the temporary disk writes that have been made on the system drive, AND also wipe off the RAM contents, **effectively making sure that there cannot be any trace left of what you were doing, while in live mode.**

