---
author: Nihilist
date: 2025-09-14
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/222"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
---
# Sensitive Remote Servers Organization 

```
TLDR: One non-KYC cloud reseller account for each deniably-rented VPS. 
Because when each VPS gets taken down, you don't want the adversary to take down the other VPSes of your highly-available hidden service.
```

In the context of running a [sensitive service remotely](../cloud_provider_adversary/index.md), as previously explained, we need [high availability](../high_availability/index.md), however as you'll see it's not only on the application level, it is also on the level of the accounts you have on those non-KYC cloud resellers:

![alt text](image-1.png)

Here as you can see, we are [deniably renting 3 remote servers](../vps-deniability/index.md) on 3 separate [non-KYC cloud resellers](https://kycnot.me/?categories=vps), this is because we want to ensure that **any takedown of any sensitive service node** shouldn't give any trails to allow the adversary to take down any other sensitive node.

For example, let's assume that a cloud provider just realized that one of their rented servers was being used to do something sensitive (which is of course not allowed in their ToS):


![alt text](image-2.png)

In this example, cloud provider C just realized that server C was being used to rent a sensitive service on it, so since it's against their ToS, they immediately shut down the server. Then afterward they close the cloud reseller C's account and **they send the cops to them**. Then the cloud reseller C has to explain to the cops that they are only reselling the server to another customer (you), **so they give everything they have regarding your Account C to the cops before deleting it.**

And lastly, if you correctly maintained your anonymity from the account creation to the actual use of the rented server C, the cops would've had nothing that could possibly lead them to you. Therefore they'd be left empty handed.

And very important detail, strictly operationally speaking, the cops don't have any lead to any of your other sensitive servers that you rented thanks to using separate accounts A and B on cloud reseller A and B respectively.

![alt text](image-3.png)

From there all that's left for you to do is to simply setup a new account D on the non-KYC cloud reseller D to rent the new server D, to setup the sensitive service node D to restore the health of your Highly available sensitive service back to 3 out of 3 nodes. 