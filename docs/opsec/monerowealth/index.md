---
author: nihilist
date: 2025-04-20
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/167"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
tags:
  - Clientside Deniability
  - Decentralized Finances
  - Agorism
  - Core Tutorial
---
# Where to hide your Monero Wealth ? 

```
TLDR: if you're found to be in posession of more monero than the legal amount of cash you are allowed to carry, the state is going to LEGALLY seize it from you. So instead, store that monero wealth in your sensitive VM, that way you're able to deny that it even exists in the first place. 
```

![](../context/sensitive.png)

Have you ever asked yourself **what you would do if you were to recieve 9000 moneros (which is worth approx 1.6M euros currently) to your wallet right now ?** Do you know where could you even store it safely in the long run? We're going to explore exactly that in this tutorial.
    
    
    Legal Disclaimer: as usual, i don't actually recommend you do anything illegal, this is strictly educational.
    
## **Why is this important ?**

First of all, you cannot appear to be rich without being able to justify where the money comes from:

![](9.png)

So if you can't officially spend that unofficial money, where do you even store it then ? 

![](0.png)

Statist thieves are everywhere. They are integral parts of governments, and their belief in the State dictates that the rich needs to serve the government one way or the other, So if you are getting rich without giving back to the state, to them you are stealing from the state, **which means that you are going into sensitive use territory** , so if you are recieving money income that you can't officially justify, you need to tread this path extra-carefully. **You need to make sure that you keep the access to your money, while at the same time make it impossible for thieves to seize it.**

In most modern societies nowadays you have a legal maximum amount of cash you can carry on yourself. **If you are found to be in possession of one extra dollar above that maximum legal amount you are allowed to carry, the state can legally steal it from you.**
    
    
    When flying within the United States, there is no legal limit on the amount of carrying Cash or monetary instruments you can carry. However, if you are traveling internationally to or from the U.S., you must declare amounts exceeding $10,000 USD to the customs authorities.
    
    

` ![](1.png)

Of course, given the context, carrying entire barrels of cash with you while going anywhere is incredibly stupid, because if it gets found at the airport, at home, in the desert, it will get seized no matter what. **Monero by itself solves that problem partially,** who's going to guess that a usb key can contain a monero wallet seed phrase worth 1.6M euros ? If storing your entire wealth on a usb stick sounds safe to you, you need to understand how badly this can end like in [this case](https://cryptonews.com.au/news/usb-stick-with-ethereum-worth-9-5-million-seized-by-uk-police-91763/):

![](2.png)

Thing is, we are aiming for deniability here. You need to be able to deny having that amount of monero in your posession. Because if you can't deny having it in your possession, you're going to get it stolen from you by the state, all because the setup you have is not suitable for sensitive use.

If the adversary suspects that you are recieving monero one way or the other, they're going to look at every harddrive, every usb key of yours, **and if there are any encrypted volumes found you'll be forced to type a password to unlock them.** That's why you need to prepare for the worst, if you are going to actually recieve alot of money on a monero wallet.

![](../logos/de2.png)In short, **if you store your monero wallet seed phrase outside of a veracrypt hidden volume (meaning outside of deniable encryption), IT CAN BE SEIZED!**

## **Where to store the seed phrases?**

Your monero seed phrase is what you need to be able to access your wallet, it is a string of 25 words. **If you lose it, you lose access to your monero wallet.** If someone else gets access to it, they can drain your wallet, that's why you should never keep your monero on centralised exchanges, because the exchange admins hold the keys to your crypto, so they can drain it. **ALWAYS SELF-CUSTODY YOUR OWN CRYPTO! if it's not your keys, then it's not your crypto!**
    
    
    yellow exhibit skill bracket venture tail snack deny push direct kitten canyon pulse fiscal ladder release door guitar mix addict crucial aspect wreck salmon velvet
    
    

If this is the seed phrase to your wallet, you absolutely need to keep access to it if you want to be able to keep accessing it, while at the same time make it impossible for others to seize it. Now you can try to remember it by heart, but good luck at that, because i certainly can't.

Realisticly, to securely store our monero seed phrase, we're going to store it inside of a Keepass KDBX file, **which makes it accessible to us by simply remembering the master password of that passwords KDBX file.**

![](4.png)

Now the question is, where do we store that keepass Passwords.kdbx file ? And how many monero wallets do we need ?

## **Deniability Context**

First of all, you need to remain aware of where your deniability starts and where it ends:

![](3.png)

Following our general recommendations on [VM-based internet use segmentation](../internetsegmentation/index.md), we have our usual Public, Private, Anonymous and Sensitive use VMs.

  * ![](../logos/de2.png)Public use VM: **you cannot deny the existance of a monero wallet in it**

  * ![](../logos/de2.png)Private use VM: **you cannot deny the existance of a monero wallet in it**

  * ![](../logos/de2.png)[Anonymous use VM](../whonixqemuvms/index.md): **you cannot deny the existance of a monero wallet in it**

  * ![](../logos/de0.png)[Sensitive use VM](../sensitivevm/index.md): _ONLY HERE You can deny the existance of a monero wallet_!




As we have explained previously, you may use [Haveno](../haveno-client-f2f/index.md) to anonymously trade Peer to Peer direct Monero for fiat and Fiat for Monero. On the surface it looks private, because you are conducting the monero transaction from your (anonymous use) whonix VM:

![](5.png)

But the other factor to consider here is that you may not be able to deny that the [Haveno Fiat -> XMR transaction](../haveno-sepa/index.md) took place in case if you just transacted with a malicious peer (that just snitched that you just traded with them):

![](6.png)

If you conduct a trade with a malicious peer that intends to tell big daddy government that you just bought monero, who knows, maybe the government would want to steal that monero from you. Since this is actually a possible scenario, let's suppose that it actually happens:

You recieve a knock on the door, and the statist law enforcement just seizes your devices and they ask you how much monero you own. You may pretend that you lost it in a boating accident, **but if your anonymous VM monero wallet contains more than 10000 Euros-worth of monero, the thieves, upon forcing you to unlock your computer, and your keepass Passwords.kdbx file, are going to simply legally steal it from you.**

![](8.png)

Therefore, **That's why we need to cap the total amount of monero stored in wallets that we carry to the maximum legal amount of cash we are allowed to carry wherever we cannot deny it's existance**. We have the sum of the private and anonymous monero wallets that cannot go beyond 10000 euros (legally) because we cannot deny their existance, and meanwhile we can store an indefinite amount of monero on the sensitive monero wallet, that is stored inside the Sensitive use VM.

## **Storing Monero Wealth, in action**

Let's consider the following scenario, let's say you have 
    
    
    -Private Monero wallet: 2 XMR
    -Anonymous Monero wallet: 3 XMR
    -Sensitive Monero wallet: 7 XMR
    
    The official amount of Monero you officially have is: 2+3 XMR, totaling at around 943 euros
    

Therefore if you were to recieve 9999 XMR on your Anonymous Monero wallet right now, your total wealth would look like so:
    
    
    -Private Monero wallet: 2 XMR
    -Anonymous Monero wallet: 3 + 9999 XMR
    -Sensitive Monero wallet: 7 XMR
    
    The official amount of Monero you officially have is: 5+9999 XMR, totaling at around 1.9M euros
    (Meaning if the adversary sees you possess that amount, they can legally take it from you)
    	
    

Obviously, if the authorities were to find you in posession of 1.9M euros worth of monero, they'll simply say that you are found in the posession of more value than you are allowed to carry on yourself (legally speaking 10,000 euros in france for example), **and then they legally seize it all from you.**

If you don't want that to happen you can either declare it and let them tax the f*ck out of it, **or you can officially donate it all to that one anonymous dude online that is running Tor Nodes:**

![](7.png)

[...] Officially speaking at least. **In reality it all lands into your Sensitive use Monero wallet** , free of tax, free from thieves, safely stored where it's existance cannot be proven. 
    
    
    -Private Monero wallet: 2 XMR
    -Anonymous Monero wallet: 3 XMR
    -Sensitive Monero wallet: 7 + 9999 XMR
    
    The official amount of Monero you officially have is: 5 XMR, totaling at around 943 euros
    (while in reality you secretely have an extra 10006 XMR, totaling at around 1.8M euros)
    	
    

Now if the adversary were to seize and destroy your devices, you'd lose access to your monero seed phrase, **so don't forget to make backups of your critical sensitive data** as shown [in this tutorial](../plausiblydeniabledataprotection/index.md). That way you can keep the access to your money even if your data were to be destroyed.

And that's it! You now know where to store your Monero wealth safely.

