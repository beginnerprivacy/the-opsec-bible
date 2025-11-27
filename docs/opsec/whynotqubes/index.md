---
author: Nihilist
date: 2025-08-03
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/434"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
---

# Why are we not recommending Qubes OS yet ?

```
TLDR: it's because of the lack of live-mode and ram-wipe features on the Host OS layer, which makes it unsuitable for our deniability-related tutorials for long-term sensitive use.
```

## What is Qubes OS ?

Qubes OS is an operating system aimed at providing security through compartmentalization, and if you're looking carefully you'll see alot of similarities with our recommendations:

![alt text](image.png)

The main differences are that the hypervisor is XEN-based instead of being based on Libvirtd KVM/QEMU, and the host OS is based on fedora instead of debian, and their internet use segmentation model is slightly more advanced (for instance they isolate the usb devices, the networking stack, the firewall rules, the display manager, and the system management in separate vms, rather than our recommendation of keeping those on the Host OS directly.) They simply have a Different threat model.

## What are we recommending Qubes OS for exactly ?

Don't get us wrong, we could easily recommend Qubes OS for 2 thirds of our opsec recommendations, being that it is suitable for private use (lack of closed-source software), and suitable for anonymous use (use of Tor and Whonix and vm-based segmentation for multi-identity work).

## What are we not recommending Qubes OS for ?

Sadly, **Qubes OS is not suitable as a Host OS for our long-term [Deniability tutorials](../../opsec/deniability/index.md) because it lacks the [live mode and ram-wipe](../../opsec/livemode/index.md) feature** (which is actually a hard requirement), therefore we consider Qubes OS as suitable for Private and Anonymous uses at best, but as far as i'm concerned, **IT CANNOT be used for long-term sensitive use** unlike with our main [Kicksecure Host OS](../../opsec/linux/index.md) recommendation, which has the live-mode + ram wipe feature.

![alt text](image-1.png)

([related forum thread](https://forum.qubes-os.org/t/what-is-the-consensus-on-running-vms-in-a-hidden-veracrypt-volume/28721/9)) In this thread the qubes forum moderator basically explains that the host OS lacks the amnesiac / live mode feature, meaning that if you attempted to replicate our [Sensitive VM setup](../sensitivevm/index.md) but with having Qubes OS as a Host OS, **you would be unable to open the veracrypt hidden volume without leaving forensic evidence of it's existance on the system drive,** effectively making it unsuitable for our deniability opsec need.

To summarize, if an adversary were to bust down your door right now, you would:
1) be forced to unlock every encrypted volume (LUKS) it contains (since you cannot deny their existance)
2) **be unable to deny the existance of the veracrypt hidden volume you may have stored on the Qubes Host OS**
3) be forced to unlock the veracrypt hidden volume aswell (since you're unable to deny its existance)
4) reveal all of the sensitive contents that you may have tried to store inside the veracrypt hidden volume, in our case, it would be the actual sensitive VM.

In conclusion: we may change our stance once they implement both live-mode and ram-wipe just like how kicksecure team implemented it for their OS, but until then we'll stick to our kicksecure host OS recommendations.