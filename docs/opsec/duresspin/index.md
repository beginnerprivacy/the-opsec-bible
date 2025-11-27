---
author: XMRonly
date: 2025-06-22
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/331"
xmr: 8AHNGepbz9844kfCqR4aVTCSyJvEKZhtxdyz6Qn8yhP2gLj5u541BqwXR7VTwYwMqbGc8ZGNj3RWMNQuboxnb1X4HobhSv3

---
# Mobile Duress Mechanism (GrapheneOS Duress PIN)

```
TLDR: When forced to type a password to unlock your phone, you can type a special password that destroys everything stored on your phone, preserving deniability.
```

![](0.png)

## Introduction

As discussed previously on this blog, using a VeraCrypt hidden volume is an ideal way to [plausibly deny](../veracrypt/index.md) the existence of certain materials. On mobile phones, however, this is not possible since VeraCrypt does not (yet) support mobile platforms. We must therefore seek an alternative tool to have plausible deniability over any materials we do not wish to expose in case of an emergency. One such alternative is the Duress PIN feature on GrapheneOS. Quoting from [https://grapheneos.org](https://grapheneos.org/features#duress):

>GrapheneOS provides users with the ability to set a duress PIN/Password that will irreversibly wipe the device (along with any installed eSIMs) once entered anywhere where the device credentials are requested (on the lockscreen, along with any such prompt in the OS).

The Duress PIN feature works seamlessly and as expected: upon entering the Duress PIN, the device is immediately wiped and the process is uninterruptible. There is no phone reset required nor any fumbling around with the bootloader in order for this to work. In this tutorial, we will explore how to set up and use the GrapheneOS Duress PIN feature, and how possible scenarios may play out when forced to unlock your phone against your will.

## Setup

Before setting up a Duress PIN, we will first need to set a PIN code for unlocking the phone. This is found under **Settings > Security & privacy > Device unlock > Screen lock**. Assuming this has already been set up, we can move to setting up a Duress PIN. Navigate to **Settings > Security & privacy > Device unlock > Duress password**. You will be prompted to enter your lock screen PIN to authenticate.

![](1.png)

We are now presented with a screen detailing the features of the Duress password. Click on "+ Add duress PIN and password". As noted in the text on screen, we will be entering both a numeric duress PIN and an alphanumeric duress password. Entering either one of these when prompted will trigger the duress feature wiping all data from the device.


![](2.png)

We now proceed to fill out the duress PIN and duress password on screen and then click Add to finalize our input.

![](3.png)

We proceed past the final warning and our setup is complete.

![](4.png)

We can always update or remove our duress PIN and password by navigating back to **Settings > Security & privacy > Device unlock > Duress password**.

![](5.png)

To use the duress PIN, you simply enter it on any screen where the device credentials are requested by the GrapheneOS operating system. This will work from the lock screen, which most users would be familiar with, but also from other functions such as setting the Fingerprint Unlock function under **Settings > Security & privacy > Device unlock > Fingerpint Unlock** (remember how we were prompted to first authenticate before being able to set a Duress PIN? It's the same procedure here). 

If you were to set your duress PIN the same as the lock screen PIN code for unlocking the phone, you don't need to worry about accidentally wiping your device because the PIN code takes priority over the duress PIN. Entering it would only unlock the phone as normal.

## Considerations

Using your duress PIN in a confrontational scenario with law enforcement (LE) may have negative consequences based on your jurisdiction. It is therefore important to carefully assess the circumstances of the situation. 

Depending on your jurisdiction, inputting a duress PIN may be seen as tampering with evidence, destroying evidence or contempt of court, which could carry fines or prison sentences. This is clearly undesirable, although it may potential be a lesser offense then the offenses brought about by LE actually finding the materials concealed on your phone.

As a general precaution, using a long and difficult to guess PIN code is recommended over using your fingerprint. This is because in the United States, the [Electronic Frontier Foundation](https://www.eff.org/deeplinks/2020/06/protecting-your-privacy-if-your-phone-taken-away) has noted that:

>Some courts have found that you can be forced to unlock a phone protected with a biometric such as face or fingerprint identification without your consent, so it is advised to not enable either option. 

The EFF additionally [notes](https://www.eff.org/deeplinks/2020/06/surveillance-self-defense-attending-protests-age-covid-19) that:

>Under current U.S. law—which is still in flux—using a memorized passcode generally provides a stronger legal footing to push back in court against compelled device unlocking/decryption.

It might be worthwhile to consider **writing your duress PIN on a piece of paper and placing this paper in your phone case**. Should anyone find your phone or compel you to give it to them, they may inadvertedly enter your duress PIN thinking you were forgetful and had to write down you PIN.

## Scenario

You're at home minding your own business, when the adversary suddenly breaks down your door, arresting you and seizing all of your electronic devices. You are then taken to the police station. If you are in a jurisdiction that allows for it, [don't talk to the police](https://youtu.be/d-7o9xYp7eE), ask for a lawyer, then [shut the fuck up](https://files.catbox.moe/h7kpp5.mp4).

If you are not in such a jurisdiction, you may be forced to unlock your phone under threats of physical violence. 

>LE: What's the code to your phone?!

>You: I think my phone's on the fritz officer, it's not really working lately...

>LE: Shut up! Open it NOW!!

>You: OK, whatever you say officer...

You enter the duress PIN. The screen briefly displays a message saying "Wrong PIN" then powers off the device. 

![](6.png)

>LE: What the fuck?

>You: Yeah officer, I told you it's been acting up lately...

Powering the phone back on will cause it to boot as normal before finally arriving at the GrapheneOS Recovery screen.

![](7.png)

The irreversible wipe has just occurred and all data and eSIMS are unrecoverable. The only thing that can be done is a factory reset. This can be done by navigating down to "Factory data reset" using the volume keys on the phone and clicking the power button to select that option. After allowing some time for the installation to complete, the phone is loaded with a fresh install of GrapheneOS.

## Conclusion

We've seen how to set up and use the GrapheneOS duress PIN feature. Due to the possible consequences of using the duress PIN for tampering with or destroying evidence in an adversarial scenario, this should be reserved as a last resort option if you have no other choice.

##### Disclaimer

This blog's [stance](../stancesensitive/index.md) is to not endorse sensitive activities and nothing in this article serves as legal advice.
