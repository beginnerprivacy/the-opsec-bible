---
author: nihilist
date: 2025-08-26
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/441"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
tags:
  - Clientside Deniability
  - Core Tutorial
---
# Sensitive Critical Data Backup Procedure 

```
TLDR: save your critical sensitive data (keepass, ssh keys, pgp keys) (which is stored inside your sensitive VM), inside of a small veracrypt hidden volume, updating the decoy volume contents each time. And that small VC volume can then be stored on usb keys, or on deniably-rented VPSes.
```

![](../context/sensitive.png)

![](31.png)

In this tutorial we're going to cover how to backup the critical data that you would normally store inside of your [Sensitive use VM](../sensitivevm/index.md), in order to make sure that your critical data (meaning your keepass .kdbx file, your SSH keys, your PGP keys, your Monero seed files) can still be accessed and reused, even if the adversary were to seize and destroy your devices in multiple takedowns. 



## **Why is this setup important ?**

As we have covered [previously](../sensitivevm/index.md), we need a specific setup in order to be able to maintain deniability regarding the sensitive activies that are conducted from inside the Sensitive VM. Due to the nature of those activities, you need to be ready for the worst, including having your main computer being seized and destroyed by the adversaries.

![](../sensitivevm/0.png)

The problem here is that if the adversary were to seize and destroy your laptop, including the non-system harddrive, **you'd permanently loose your critical sensitive data (which includes your PGP key, your SSH key, your monero wallet seed phrase, and your accesses that were stored in your Keepass .KDBX file)**

![](30.png)

**Therefore we need a way to backup the critical data from your sensitive VM, while still maintaining deniability about what it contains if ever found by the adversary.**

## **What is the Critical Data backup procedure ?**

From inside the Sensitive Use Whonix Workstation VM, we'll need a small veracrypt volume (which is 10Mb big) to simultaneously store a decoy volume containing some textfiles, and to store a small hidden volume (which is 5Mb big) which will contain your critical data:

![](32.png)

This small veracrypt volume will be called "diary" and it's decoy partition will simply contain a text-based diary of yours. However we need to be careful as we're going to save that file in places that the adversary may access, **We need to make sure that the decoy volume data changes, every time the hidden volume changes.** This is because otherwise we wouldn't have a way to justify why the overall veracrypt volume changed while the decoy volume didn't change (which would then prove the existance of the hidden volume).

![](31.png)

Therefore, to meet the deniability requirements, we have the following backup procedure:
    
    
    1) open the diary Veracrypt hidden volume to save the critical data in it
    2) after saving the critical data in it, close the hidden volume
    3) open the diary veracrypt decoy volume to write a new diary text file in it. (as otherwise you wouldnt be able to justify why the overall VC volume changed)
    4) close the decoy volume (ONLY NOW the overall veracrypt volume is ready to be backed up elsewhere)
    5) backup the veracrypt diary volume on a cheap remote VPS that was rented anonymously (accessed via SSH, via the .onion domain only)
    6) backup the VC volume in USB keys that are scattered in physical locations that you can access easily, and that can hide USB keys.
    	
    

So let's see how this looks like in action:

## **How to perform the Backup Procedure**

First, boot the Host OS in live mode:

![](../livemode/12.png)

Then open up the non-system veracrypt hidden volume:

![](../sensitivevm/109.png) ![](../sensitivevm/110.png) ![](../sensitivevm/111.png)

Then run script.sh (using the **Super+S** shortcut) to setup your sensitive whonix VMs:

![](../sensitivevm/113.png)

Before starting the Workstation however, make sure that the VM's USB controller is set to "USB 2" mode by editing the settings like so in the XML directly:
    
    
    [user ~]% cd /run/media/private/user/sda
    [user /run/media/private/user/sda]% vim Whonix-Workstation.xml    
    [user /run/media/private/user/sda]% cat Whonix-Workstation.xml    
    
    [...]
    
    <__controller type="usb" index="0" model="ich9-ehci1">
    
    [...]

Once done, you can create the "diary" veracrypt volume inside the sensitive VM, (we'll use it to backup our critical data into it's hidden volume):

![](36.png) ![](37.png) ![](38.png) ![](39.png)

Now that the diary veracrypt volume has been created we can start to use it to backup our important data into it: 

## **How to perform the Backup Procedure**

First, plug in your 3 usb keys into your computer and then make sure that they are attached to the Whonix Workstation VM:

![](33.png) ![](34.png) ![](35.png)

Then once you verified that the USB sticks are detected from the VM, you can start to backup your critical data inside the veracrypt volumes:

![](40.png)

And then after backing up your critical data, you can unmount the hidden volume, to mount the decoy volume instead, where you'll write a diary entry (that way you'll be able to justify why the overall veracrypt volume changed):

![](41.png)

Now that's done, unmount the decoy volume, and use the following backup.sh script to backup your diary veracrypt volume to the 3 usb sticks:
    
    
    [user ~]% vim backup.sh 
    [user ~]% cat backup.sh 
    
    #!/bin/bash
    
    echo 'creating all 3 usb mount directories...'
    sudo mkdir /mnt/usb1
    sudo mkdir /mnt/usb2
    sudo mkdir /mnt/usb3
    
    echo 'mounting all 3 usb sticks...'
    sudo mount /dev/sda1 /mnt/usb1
    sudo mount /dev/sdb1 /mnt/usb2
    sudo mount /dev/sdc1 /mnt/usb3
    
    echo 'copying the diary file on all 3 usb sticks...'
    sudo cp -r  /home/user/diary /mnt/usb1/diary
    sudo cp -r  /home/user/diary /mnt/usb2/diary
    sudo cp -r  /home/user/diary /mnt/usb3/diary
    
    echo 'copying completed, hence unmounting all 3 usb sticks...'
    sudo umount /mnt/usb1
    sudo umount /mnt/usb2
    sudo umount /mnt/usb3
    
    echo 'remote backup to a VPS rented anonymously...'
    torsocks scp /home/user/diary user@yourremotevpsaddress.onion:/root/diary:
    
    [user ~]% chmod +x backup.sh 
    [user ~]% ./backup.sh 
    
    

Run the script, and you'll now have your critical data backed up on your Remote VPS, and it's on the 3 usb keys.

> Update (2025-08-26): If you want to also hide contents of decoy volume from a VPS provider you're backing up the data to, check out our [Borg Backup](../borgbackup/index.md) tutorial. It allows making client-side encrypted backups which so the VPS provider can't see your files.

And now you can unplug the 3 usb keys, and scatter them in 3 different places that you can easily access. **You can hide them in your bag, in your car, and bury one in your garden for example.** Get creative, but make sure that you can easily retrieve those usb keys back for next week's backup.

![](42.png) ![](43.png) ![](44.png)

However be careful if you intend to hide those usb keys in public places that are not yours (where you normally never go to either), you need to make sure that you are going there without a cellphone on you. **As otherwise the adversary would see that your phone has gone to a novel place that you have never been to before, And that gives them hints regarding where you might've hidden the usb keys.**

![](45.png)

Here for instance, the adversary wouldn't see your movements in pink, the only clues they'd have are the movements in red that they can anyway see from their dashboards. However it doesn't stop there, **if you actually are a high value target you should instead backup to remote VPSes exclusively, as the authorities will most likely find every physical clues you might leave behind** , (you might need to take into account satellite and public covert surveillance too)

If you don't want to leave any physical clues behind and stick to digital backups alone, you're going to need to rent 3 cheap remote VPSes in 3 different datacenter locations, from 3 different cloud providers, by using 3 different non-KYC cloud reseller accounts. To know how to rent a VPS anonymously, [check out this tutorial](../anonymousremoteserver/index.md):

![](48.png)

Hence your backup.sh script would look like so:
    
    
    [user ~]% vim backup.sh 
    [user ~]% cat backup.sh 
    
    #!/bin/bash
    
    echo 'remote backup to VPSes rented anonymously...'
    torsocks scp /home/user/diary user@remotevpsaddressA:/root/diary:
    torsocks scp /home/user/diary user@remotevpsaddressB:/root/diary:
    torsocks scp /home/user/diary user@remotevpsaddressC:/root/diary:
    
    [user ~]% chmod +x backup.sh 
    [user ~]% ./backup.sh 
    
    

With this second approach, the adversary will only be able to find your laptop, and they'll get the impression that you didn't try to make any backups.



## **Emergency Scenario**

So now let's suppose the following emergency scenario: You made an opsec mistake somewhere along the way, and the chinese authorities are now aware that you've been playing video games after 7 PM, and they are now raiding your appartment again:

![](../sensitivevm/119.png)

You manage to hit the correct key combination (**right Alt to focus out of the VM, and right CTRL to trigger the emergency reboot script**) Which closes the sensitive VM and reboots your computer just in time.

![](46.png)

Then they seize your devices, keep you in custody for just 1 month, and due to not having any further incriminating evidence on you **(they only found the non-sensitive files in the non-system drive, and the diary textfiles in the usb keys they seized)** , you avoid the concentration camp life sentence, and thus they release you. **But they're not giving back your devices because they destroyed them.**

![](47.png)

So your primary data source has been destroyed (including the sensitive VMs and the main diary VC volume), you also realize that they seized and destroyed the usb key you had in your backpack, and in your car. **However upon checking further you realize that they didn't get the USB key that you hid in your garden.**

![](44.png)

Too bad for them, because they didn't find that one usb key you had buried in your garden, so you dig it up, retrieve it, you purchase a new laptop, [you set up your sensitive VMs once again](../sensitivevm/index.md), and then you simply plug the usb back in the sensitive VM, **and with it you can restore your critical sensitive data (which includes your Keepass accesses, your pgp keys, your ssh keys and monero wallet seed) by copying the files back into your new sensitive use VM.**

![](49.png)

In a worse scenario, you could've had all physical backups being seized and destroyed, leaving you with only the remote VPSes that you rented to retrieve your backups. In this usecase **All you need to remember is how to access those VPSes via SSH** , you need to remember the IP addresses, the username, and the password to SSH back into the VPSes:
    
```    
[user ~]% scp root@256.51.123.1 :/root/diary ~/diary
``` 
    

to make it easier to remember the addresses of the remote VPSes (since remembering IP addresses off the top of your head isn't trivial) you could also use a [clearnet domain alias (that you also rent anonymously)](../anondomain/index.md) to easily access those VPSes again.
    
```
[user ~]% scp root@your.clearnetdoma.in :/root/diary ~/diary
``` 
    

And once restored you can resume your sensitive activities as usual, minus the opsec mistakes you made that led up to your arrest obviously.


### Ensuring you remember the emergency backup VPS IP address

In case if you don't want to pay for a clearnet domain to make it easier to remember a VPS you rented deniably, you'll need to remember it's IP address. To do so i recommend using the following script to make sure you test yourself to remember the IP of your emergency backup VPS everytime you try to backup your sensitive critical data on it:


```sh
[user /run/media/private/user/sda/emergency_backups]% vim vpsbackup.sh
[user /run/media/private/user/sda/emergency_backups]% cat vpsbackup.sh 
#!/bin/sh

# Declare the four unique numbers directly
num1=5
num2=12
num3=200
num4=19
correct_numbers="$num1 $num2 $num3 $num4"
guesses=""

echo "To backup your critical data to the deniably rented VPS, you need to remember the IP of the VPS, type the 4 numbers of the ip one by one (ex: 202 102 10 59)"

# Set up an array of the numbers for easier iteration
numbers="$num1 $num2 $num3 $num4"
index=0

# Loop until all numbers are guessed correctly
while [ $index -lt 4 ]; do
    read -p "Enter a number (0-255): " guess
    
    # Check if the guess is a valid number between 0 and 255
    if echo "$guess" | grep -qE '^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'; then
        # Check if the guess matches the current number
        current_number=$(echo $numbers | cut -d' ' -f$((index + 1)))
        
        if [ "$guess" -eq "$current_number" ]; then
            echo "Correct ! $current_number."
            index=$((index + 1))  # Move to the next number
        else
            if [ "$guess" -lt "$current_number" ]; then
                echo "Too low."
            else
                echo "Too high."
            fi
        fi
    else
        echo "Please enter a valid number between 0 and 255."
    fi
done

# Final congratulatory message after all numbers have been found
echo "Congratulations! You found all the numbers of the VPS IP: $num1.$num2.$num3.$num4"
echo "scp /run/media/private/user/sda/emergency_backups/file root@$num1.$num2.$num3.$num4:/diary"
torsocks scp /run/media/private/user/sda/emergency_backups/diary root@$num1.$num2.$num3.$num4:/diary
```

Here it is in action:
```
[user /run/media/private/user/sda/emergency_backups]% sh vpsbackup.sh
To backup your critical data to the deniably rented VPS, you need to remember the IP of the VPS, type the 4 numbers of the ip one by one (ex: 202 102 10 59)
Enter a number (0-255): 4
Too low.
Enter a number (0-255): 6
Too high.
Enter a number (0-255): 5
Correct ! 5.
Enter a number (0-255): 11
Too low.
Enter a number (0-255): 13
Too high.
Enter a number (0-255): 12
Correct ! 12.
Enter a number (0-255): 199
Too low.
Enter a number (0-255): 201
Too high.
Enter a number (0-255): 200
Correct ! 200.
Enter a number (0-255): 18
Too low.
Enter a number (0-255): 20
Too high.
Enter a number (0-255): 19
Correct ! 19.
Congratulations! You found all the numbers of the VPS IP: 5.12.200.19

torsocks scp /run/media/private/user/sda/emergency_backups/diary root@5.12.200.19:/diary
```

Thanks to this, you're going to test yourself at least once a week whenever you backup your critical data to know if you still remember the public IP of your VPS, and especially when the time comes when you effectively need to remember the VPS IP you'll be able to instinctively type it to retrieve your emergency backup:

```
torsocks scp root@5.12.200.19:/diary /run/media/private/user/sda/emergency_backups/diary 
```