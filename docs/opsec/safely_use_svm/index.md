---
author: Nihilist
date: 2025-09-14
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/503"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
---
# How to safely use the Sensitive VM

```
TLDR: Deniability requires privacy to be intact in the first place.
And it also requires you to trigger the emergency shutdown procedure on time.
```

This is probably going to sound obvious and trivial, but i think it's worth explaining just in case if this isn't common sense to you yet.

## Reminder: Deniability requires Anonymity, which requires Privacy

Deniability isn't possible without Anonymity, and Anonymity isn't possible without Privacy. 

So even though the Sensitive VM setup provides Privacy (FOSS), Anonymity (use of Whonix VMs), and Deniability (making use of Veracrypt hidden volumes), **you need to ensure your privacy is intact IRL aswell**.

## Who can see your monitor ?

First of all, since the Sensitive VM is meant to remain secret at all costs, you need to take into account who can see your monitor.

If you think you can use this Sensitive VM outdoors, in public spaces, where people can see what you're doing on your screen, you should know that this is not an option:

![alt text](image-2.png)

Same thing as how [Ross Ulbircht got arrested](../silk_road/index.md) while performing sensitive activities from his laptop, he was in a public library, which means that undercover agents could easily storm in to take his laptop away from him, due to being a public space:

![](../silk_road/7.png)

It is the same as trying to use the Sensitive VM while a camera is pointed at you from behind, for example in an office workplace:

![alt text](image-1.png)

And obviously if you have a surveillance system at home like in this example, you should know that this is also a potential way for you to ruin the deniability you have.

![alt text](image.png)

On the other hand, you can have a setup like the one above, where the monitor is not visible from the camera, but you need to constantly remember to never turn the monitor to face the camera while the Sensitive VM is active.

However obviously the simplest option is to have an office room at home with no windows (to prevent any neighbor from looking in), nor any cameras, that you can safely use privately whenever you want to use the sensitive VM.

![alt text](image-3.png)

## How can I react on time to an emergency scenario ?

As explained previously in the [Sensitive VM tutorial](../sensitivevm/index.md), in case of an emergency happening (which means the adversary busting down your door), you need enough time to react to the fact that there's an emergency and enough time to press the emergency reboot shortcut, for which i'd say 5 seconds should be enough.

### Stay next to your computer if the Sensitive VM is opened

Have you ever heard of the basic IT rule of "Lock it if you leave it" ? It refers to when you leave your computer, you should lock it, to prevent anyone else from physically accessing your computer while you were away from it.

![alt text](image-9.png)

The same concept applies here. Suppose you were working on the sensitive VM and you had to go to the toilet to make a modern piece of art, what if the cops were to bust down your door right then ? **The problem is that you wouldn't have enough time to get back to your computer to trigger the emergency shutdown**, simply due the distance between you and your computer when the emergency occurs, and in that scenario the adversary would manage to get to your computer before you.

Therefore if you have to leave your desk for any reason whatsoever, to take a leak, to grab some soda, to go take a shower or to go out to get the groceries, you HAVE to power off your computer the moment you leave your desk, as the door could be busted open at any moment while  the sensitive VM is opened.

### Not listening to loud music

![alt text](image-5.png)

If you're using high quality noise-cancelling headphones, and blasting some loud music into your ears with it, then it may be possible that you won't hear the door being busted open, nor the cops storming your apartment, until it's too late when they pin you to the ground and effectively prevent you from triggering the emergency reboot shortcut.

### Reinforcing the front door

First of all, since the main threat vector is with cops busting down your front door, you could reinforce it.

Check out those examples of front-door busting: [link to the video](https://www.youtube.com/watch?v=9v34zHuW_uQ)

![alt text](image-6.png)

![alt text](image-7.png)

![alt text](image-8.png)

If you want to include that into your own threat model, know that there are ways to ensure that your front door is much harder to bust open from the outside, such as with going with full-steel front-doors like the third example just above. 

### Correctly placing your home office

That's why you need to take into account how long it would take for an adversary to bust down the door and for them to get to see your monitor like in the example below. If you don't place your office well, you might have less than 1 second to react to an adversary busting down your front door to arrest you:

![alt text](image-4.png)

Instead, I recommend you to place your home office as far from the entry door as possible, to ensure that in case a raid, that from the time the adversary starts to bust down your front door, to the time they actually get to your home office, you have enough time (at least 5 seconds) to press the emergency reboot script.

### Getting used to triggering the emergency reboot

It may sound stupid simple but this should be muscle memory for you to trigger the emergency reboot sequence. Hence i recommend that you should test yourself at random at least once every few days. ***"What if an adversary was busting down my door right now ?"** 

Randomly start counting down from 5 to 0, if you manage to trigger the emergency reboot shortcut before the countdown hits 0, you win, otherwise, you'd would have gone to jail potentially for a long time.

## Conclusion

If you have some sensitive activities to perform, don't do those in a public space, make sure that you're performing those from a confined space within your full control, and make sure that you're always ready to react to an emergency scenario.

Instead of having obstacles that could potentially prevent you from triggering the emergency reboot shortcut in time, rather put obstacles to make it significantly harder for the adversary to get to your computer, those may seem like trivial measures to take but when we're talking about sensitive activities where you potentially risk jailtime, i think those are definitely worth having.