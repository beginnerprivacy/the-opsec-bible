---
author: UserSurname
date: 2025-10-13
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/495"
xmr: 82jqKSrZsUQBP8uEbzj23AhTyvh6hsoXRhvg4xsiNH8cajiUwhhqqvS9TCDac5PiAHUEYv9GYGgEKUw6GRngAxjQHSfvMQ7
tags:
    - Deniability
---
# The Dangers of ordering Drugs online

```
TLDR: when ordering drugs, even if you have perfect opsec, you can't mitigate the risk of a controlled / monitored delivery, since you have to physically go get the package, which makes it easy for LE to find you in posession of said illegal substance. Not worth the risks imo, just live a sober life instead
```

### **Disclaimer**

**This is NOT a tutorial to order drugs!** DO NOT replicate the steps in this blogpost.

This blogpost only serves an informational purpose. We do not recommend the usage of any illegal substances, in fact any substances at all. The best way to live your life is to [live it sober](../../productivity/opus-nihil/index.md).

## Introduction

Let's say that Jesse wants to buy a small amount of coke for personal use.

Jesse uses a perfect OPSEC setup, runs [Tails](../tailsqemuvm/index.md), connects from a public WiFi, and wears a cool hacker mask to achieve complete anonymity.

![](0.png)

However there are more threats that can't be mitigated just by using the right software. We will go step by step and showcase what can happen to Jesse during the process of buying.

## The process

The logos and links were censored to not advertise the markets/vendors.

**Again, this is not a tutorial.** Do not try to replicate the steps yourself.

### 1. Finding a market

Jesse goes on a website with darknet links and finds a DNM (Darknet Market).

After waiting in a queue for a short time, he tries to complete the captcha.

![](1.png)

Then, completing the captcha after a few failed attempts, Jesse is met with a registration form:

![](2.png)

Jesse registers and deposits some XMR to his account:

![](3.png)

### 2. Placing the order

Now Jesse goes to the page with the products. Since he lives in the Netherlands, he chose a vendor from the Netherlands. [Later in this article](index.md#domestic-shipping) we'll cover on why is it so important.

Jesse also paid attention to user reviews for the vendor on the market and on Dread, and chose the one with the best [stealth](index.md#what-is-stealth).

![](4.png)

He clicks on the "Order" button, and is met with a checkout screen.

![](5.png)

To mail the product to Jesse, the vendor needs his address. Jesse will type it in the Vendor Note field, and **will get the EVIDENCE of drugs ordered to his address saved PERMANENTLY on the market.**

![](6.png)

#### **WARNING: ALWAYS encrypt your real life address with PGP!!!**

Jesse's address **will be hosted on the market in plaintext**, and could be accessed by the market itself or by the Law Enforcement if the market's server is seized. To make the address visible only to the vendor, Jesse can use [PGP](../pgp/index.md) encryption. You can learn how to use it in [this tutorial](../pgp/index.md).

![](7.png)

Jesse **will encrypt his address with PGP** so the feds wont knock on his door if the market is busted.

Jesse pastes the vendor's public PGP key to `vendor.pubkey` file and imports it:

```
$ vim vendor.pubkey
$ gpg --import vendor.pubkey
gpg: key 0x27C3E5466C204773: public key "MarketVendor" imported
gpg: Total number processed: 1
gpg:               imported: 1
```

Jesse encrypts the address with his PGP key:

```
$ echo "Deliver to address: NL/Amsterdam, 123 St..." | gpg -u jesse@nowhere.moe -r MarketVendor --encrypt --armor

gpg: 0xFF8C9786A3850A90: There is no assurance this key belongs to the named user

sub  rsa4096/0xFF8C9786A3850A90 2020-10-14 MarketVendor
 Primary key fingerprint: 94CC E4FD E276 9FF6 9BA8  CB09 27C3 E546 6C20 4773
      Subkey fingerprint: 0FBA 0548 02FA 2CD9 11D3  9FB8 FF8C 9786 A385 0A90

It is NOT certain that the key belongs to the person named
in the user ID.  If you *really* know what you are doing,
you may answer the next question with yes.

Use this key anyway? (y/N) y
```

The key's fingerprint matches the vendor's fingerprint, so he accepts it.

```
-----BEGIN PGP MESSAGE-----

hQIMA/+Ml4ajhQqQAQ//dQcdTdIHDfYrmQIWda1tlSUJG5bb9JQbjEXKADS1K1Ni
5+kd7bb7uYjFJ4byfVQO4F2/TIsEk9qSimX/DOUyHtmSaEib5FGcohI3RUulQK0r
M3PWM6DyyWvFaVqnqPQoWGExbpz+ocrKviJnRwW9iKaVrmQtm1x1giCC6w5pFVfz
W4ZLLCyBJH+fpXxV/oGodRr4V0ZYWpF7gz4jP+7eYKM5gmI+vyZ5PRYiUErXCbSr
cKu9l9+vYcyyiDJ1zYF0cuX3fpk6tBExITdFqMY59nJS/L/2kaHfHCVIg3GP5dVw
MVsBzYo/R7FbycyWR1ZJ6Emp/Q0Pu7qPaysn2Hbvi9CfnRzO4Bfiffy5qoUWVjZQ
2ubfBYRHEmeFNnEi1BTDWfIMKd/T/0hWZ366/8J1DHqfzPkvLQTa3lipBwRmmIwi
8ys10lZuctqt6/sPyv7Gzho6FW82qDQFej5MoRgkSgDswUp6uW9RVwwZY5fBhljM
4b3ktzxsy6TdTFmTZ6/AvYGWy++KLWgh1tiHiPXB3wl49C/aK5siyEHk3S1e5WCP
2XosMkcYzFeDreSO+xCh7K29r3tWJESzELQDdXOV9WE1d6aF8PTwrvNloFzEvdJ3
x3YmXiYpACPeyT+28S6kKHe2dP1Zb/uuXqg1wlZLkX6H93sw9eGDp2F40zMUMvPS
6QEjlgl8+1fb5h5/NRbGRx1k0ZR0Cdsr2Gn610py3AiUvfQtLuTWryUUoKI49lh5
evTBpjIiBjFSCab3xP2lxSjnx+vUQrYpMeKZc6p5QTcuW0mUySL+XOCAoOJRoaFg
T/Cs7DsRuQhbBrgwT+9jUMoXETS6OOkZP4kl/b5G5+AoXShDtveHAj2xnSkRMFF/
Ym0vmZSpq1lGuoAIQbK5TzFa8HWCtGJuUl5G3VYmIb7YV0gwyF7XV1W+SCg9GhuL
RzExpyHycgZHXLs0Yrlj6CWtr+7j8BTvZSwNQ4J+8U9wHia6mUy6VjuKoUr3yfaD
ouJ9F9fJ/6pUXQjIuBAWDaVnVJCZkWmvDYcTIbr3thJvJlzVWlNemKNE5hemPFDF
JXWZFlf7TiBqp/tLoS5Xm7LNvud3mjekjpraUEQCcFZs+BTsAoz0G0uUu+dZwE7S
RKOVLjGs8CPFzGToxcFe8BtczKejabhZMD1H1pUzh6O6PAmdJSZLre5cadjWpaxm
dPmiG1SUS2q7dddjqwOk9ZIWz2LjJbJvwBgSNewaXxIkAEY1ZMpbZR+l2YrVZ/Xf
VQOe8m8N+ObOo7pObKbj869CunwNpgDerHmey2Tfx8w7IfoqMa6DxgrNhQI1dPLh
GGWfgMBJq5nYV5B1nHj46bYjvWbYSAaqov/ca04PWQIRpAVVtec/zFOepmkYBsJE
0u4kK5UWjHePVaTM27xSuXpArz793l4xLBKRCxEYi6lfO/+5HrrTPaVm8BVjVmLB
r1w0l+nbQMkKhVIh+xFinvbxE27l+va/q52YBtNq4bHZowbBhOvG8/VFvBi4eJzv
5Ximd77ObiVkbAwU9TtECKe7VudWfTHn0r2EHIRM4Jxa1M7B1QMN/qiz4hgkd47x
fePjkFYr
=EAgw
-----END PGP MESSAGE-----
```

Jesse pastes the encrypted message to the `Vendor Note` field.

![](8.png)

The Market also offers a convenient feature to encrypt your address with PGP. But there's one caveat:

#### **WARNING: DO NOT TRUST SERVER-SIDE ENCRYPTION!**

IF you choose to use the built-in PGP encryption, your address will be sent to and processed on the market's server **in plaintext**. Since the plaintext version of your address is sent to the server out of your control, **you cannot be fully sure** if the market doesn't store the unencrypted address or isn't seized by feds.

![](9.png)

Finally, he clicks on the **Order** button. Some XMR is taken from his wallet to the escrow (the market).

### 3. The delivery

**For further information on narcotics delivery, you can check out our article: [The postal system explained](../thepostalsystemexplained/index.md)**

From now on, the situation is out of Jesse's control.

There can be two variants:

#### Variant A: The vendor is a fed

Rare but is not impossible. 

A good example of this is the [2018 Operation Dark Gold](http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/post/3ccb618ac55784da205c) (credit: [u/Electric-Kool-Aid-Drinker](http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/u/Electric-Kool-Aid-Drinker))

> Special agents of the U.S. Immigration and Customs Enforcement’s Homeland Security Investigations (HSI) New York Field Office posed as a money launderer on darknet market sites, exchanging U.S. currency for virtual currency.

Basically, LE created a fake vendor account on the Dream Market, which offered cash-by-mail in exchange for BTC. The account had a significant amount of positive reviews.

![](10.png)

This shows that Anonymity can also benefit the Adversary, and highlights the problem of decentralized trust. **LE can always trade a 100 times with a fake account (or a seized one), and you will have no way of knowing that**.

In this case, Jesse orders a small amount, so in most cases the LE won't bother with prosecuting a small, low-hanging fruit like Jesse but instead send a [**love letter**](index.md#outcome-b-love-letter) to the address sent by him. (see what is it later in this post)

But if Jesse ordered an amount slightly more than what can be considered an amount for personal use, it would lead into an investigation opened on Jesse, which will then lead to prosecution.

#### Variant B: The vendor is legitimate

From now on, we will switch to the vendor's perspective. Let's call him Walter.

Walter receives the order on the market and Monero is put in an escrow:

![](11.png)

Then, Walter decrypts Jesse's PGP-encrypted message:

```
$ gpg -d address.txt

Deliver to address: 123 St...
```

Now he writes the destination address on the parcel, and before sending the package, he wraps it in stealth:

#### What is stealth?

Stealth is a DN term for the concealment of drugs in a shipping package. Stealth is used to make the package appear as normal as possible and also conceal the smell of the substances inside. This will help to attract less attention if the package is checked at the post office, opened or ripped.

Walter will wrap the package tightly, and put it in a coffee bag. He will also put some more coffee bags without substance, to serve as decoys if they are opened too.

Finally, Walter goes to a random mailbox without camera surveillance far away from his home, and puts the parcel in it.

#### Domestic shipping

Usually, if the package is shipped domestically (destination is the same as the origin country), it's far less likely to be checked than when it's shipped internationally.

> The first rule is: stick to domestic whenever possible. Mail that does not cross any country border will get far less checked than all other mail. This reduces the risk of you not getting your package or even getting in legal trouble.

source: [Origin Countries | DNM Bible](http://biblemeowimkh3utujmhm6oh2oeb3ubjw2lpgeq3lahrfr2l6ev6zgyd.onion/content/bible/shipping/origin_countries/index.html)

However, there may be a disadvantage in pricing compared to internationally shipping vendors. Though, the safety of domestic shipping outweighs the price difference.

#### International shipping

Now, if the package is shipped internationally, chances are, **it will be searched at least 2 times** (by the origin country customs, the destination country customs, and countries which the package goes through). This highly increases the risks of the package getting [seized](index.md#outcome-b-love-letter).

##### Hot Origin Countries

Hot origin countries are countries which are known for manufacturing/exporting drugs. Packages from these countries will get checked extensively by the customs.

![source: The Business Insider](drugorigin.png)

> If you order international, it is strongly discouraged to order from the following “hot countries” because mail coming from these countries will usually get checked extensively.
>
> - The Netherlands (NL) - notorious origin country for all drugs
> - Colombia (CO) - notorious cocaine and heroin origin country
> - Peru (PE) - notorious cocaine origin country
> - Bolivia (BO) - notorious cocaine origin country
> - Venezuela (VE) - significant but marginal cocaine origin country with possibly rising market share
> - Ecuador (EC) - significant but marginal cocaine origin country
> - Canada (CA) is on Israel’s drug origin country watch list, and, specifically, XpressPost (express mail) from - Canada is often opened by US Customs indiscriminately. Note: Mail that is not XpressPost from Canada is usually not cause for extra concern.
> - Spain (ES) is on Israel’s drug origin country watch list. This affects imports into Israel.
> - France (FR) is on Israel’s drug origin country watch list. This affects imports into Israel.

source: [Origin Countries | DNM Bible](http://biblemeowimkh3utujmhm6oh2oeb3ubjw2lpgeq3lahrfr2l6ev6zgyd.onion/content/bible/shipping/origin_countries/index.html)

##### Countries with strict Customs agencies

These countries are known for extensive checks on incoming or outcoming packages. It is not recommended to order from these countries:

- Israel
- Australia
- New Zealand
- Sweden
- Finland
- Japan
- China
- Saudi Arabia
- UAE
- Mexico
- Russia
- India
- Pakistan

## The outcome

Now, Jesse had waited long enough for the goodies to arrive. It took some weeks to arrive. Now he may face a few different outcomes.

We will go in order from the best to the worst-case scenario.

### Outcome A: success!

Jesse opens the package, removes the stealth, gets the drugs out, but is not yet ready to indulge into his new addiction.

A common tactic in drug trade investigations is to inspect the suspect's trash, so he goes to a trash can far away from his home, and disposes of the packaging and stealth.

**He doesn't store it anywhere near the locations he's associated to**, like his house, workplace, or his car. Instead, he hides it in a quiet place away from public places like kindergartens, schools or hospitals.

This is done in case a police raid or search was to happen at Jesse's house, so he can deny being in possession of said substances.

Jesse also leaves a 5-star review to support the vendor he bought from.

### Outcome B: love letter

Jesse opens the mail box, but instead of his package, he finds a paper from the LE (the love letter), saying:

> We seized the illegal substances in one of your packages. We won't prosecute you now, but if we find them again, we will. 
>
> Sincerely, your local LE Office

This happens when you have ordered too small of an amount for LE to care and actually go and knock on your door. You can consider the address burned and **should never order to it again** from now, or else it might result in a controlled delivery:

### Outcome C: controlled delivery (CD)

Jesse opens the door, and takes the package from the mail man, then 3 police officers come out from hiding and conduct a search in Jesse's house.

What happened: LE delivered the package to try and make Jesse accept it (so he can't say that someone else delivered drugs to his house), to then have a plausible reason (suspect knew about the incoming package) to search Jesse's house.

![](12.png)

If Jesse would have any suspicious things present at his house (ex. usb tails stick, drugs, a bong), this would lead to an investigation, otherwise the LE will leave empty-handed (**this is why you shouldn't store it at home!**).

The list of suspicious things also includes Tor traffic coming from your home, so make sure to hide it using a [vpn](../torthroughvpn/index.md#first-goal-hiding-tor-usage-from-your-isp), [v2ray](../v2ray/index.md) or [Cloak](../cloak/index.md).

However a controlled delivery scenario occurs mainly when one orders drugs frequently or in big amounts, and is more common when shipped internationally. It is very rare to get CD'd when ordering small amounts domestically.

This shows that **Jesse has absolutely no control over the situation**, and even with all precautions taken, **Jesse has to rely on sheer luck**, which is inacceptable in a sensitive scenario.

### Outcome D: monitored delivery

This is a much rarer scenario that mainly occurs for vendors/distributors, but should not be disregarded.

Jesse has been ordering stuff and reselling it to local crackheads for a few months now. 

He got a lot of money from it, and bought even more product to resell, but at some point the feds break in his house and arrest him.

Turns out, the LE found a large amount of substances in a package a few months ago, but **kept knowingly delivering the packages to build up evidence on Jesse**, to make his [prison sentence](../solitaryconfinement/index.md) as long and worse as possible.

![](13.png)

Since Jesse had no control over the supply chain (that has total control over his package) **he had no way to know if his package was opened by LE or not**, but he still **put himself at risk** and had to face the consequences.

## Conclusion

The process of ordering drugs is very tedious, requires solid OPSEC and deniability, but even with the perfect OPSEC, **most of the process is out of your control**, and if shit hits the fan, the consequences are irreversible.

![](14.png)

Still, **the only way of mitigating risks would be ordering only small amounts domestically**, which **doesn't guarantee** it not going wrong.

We do not recommend the usage of addictive substances, or even having any addictions. It may be drugs, alcohol, gaming, gambling, and the list only goes on and on.

If you are addicted to anything, you should read our articles about [strategies of unwinding addictions](../../productivity/unwinding_addiction_strategies/index.md) and practicing [Nihilism](../../productivity/nihilism-intro/index.md).
