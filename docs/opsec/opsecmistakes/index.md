---
author: Mulligan Security
date: 2025-05-22
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/312"
xmr: 86NCojqYmjwim4NGZzaoLS2ozbLkMaQTnd3VVa9MdW1jVpQbseigSfiCqYGrM1c5rmZ173mrp8RmvPsvspG8jGr99yK3PSs
tags:
    - OPSEC Mistakes
---

# Realistic OPSEC Mistakes and Threat Scenarios

![loose lips sink ships](opsec.jpg)

## OPSEC: the name of the game
When running any kind of clandestine operation, if you want to remain anonymous, you have
to follow OPSEC (operational security) rules and procedures.


More often than not, as we will see here, when an operation (or individual operators) are compromised
it is through OPSEC mistakes.

## Why OPSEC matters

![attack cycle diagram](attack_cycle.png)

From the adversary's point of view, repression requires the following broad steps:

- Initial detection: someone is doing something we don't like
- Identification: who those "someones" are
- Neutralization: make sure they stop doing whatever they set out to do

## Initial detection

![protest](protest.jpg)

Depending on your organization and activities (eg: [protests](../anonprotest/index.md)), this initial detection phase can come as soon as you get started
(if you are staging protests, then identification is inevitable).

### What good OPSEC looks like

If your activities themselves must remain clandestine, OPSEC rules and procedures can help reduce your profile
and make it less likely that your activity will be identified properly.

A simple example:

- sabotage during ww2 ([source](https://www.cia.gov/static/5c875f3ec660e092cf893f60b4a288df/SimpleSabotage.pdf))
  - choose acts for which many people could be responsible, and it's even better if it can be credibly blamed on an accident
  (such as an insecurely fastened hydro-turbine cover leading to a flooding of the facility)


### What bad OPSEC looks like


![smugglers](smugglers.jpg)

## Smugglers

The quicker you are identified, the faster your other lines of defense must come into play.
If you are a novice in clandestine ops, it is likely that you still have stuff to learn in
order to be safe. If your activities are quickly identified, that's even less time available to you
to actually get better at survival.

## Extortionists

### Zeekill
Julius "zeekill" Kivimaki extorted a Finnish online psychotherapy service, threatening them with the release of patient data (therapy notes among them).
While preparing a data package for release he mistyped the tar command and instead of only releasing the pilfered data also released the entire content
of his home directory, helping investigators identifying him. That way he managed to speedrun both initial detection and identification, what a champ!

### USDoD
USDoD made several OPSEC mistakes, allowing investigators to link his public and clandestine personas.


- same bio on public and clandestine Twitter accounts, shared with an Instagram account as well
- Instagram account mentioned by
  - a tattoo artist
  - a SoundCloud profile with his public identity and pictures of his face
    - the pictures were the same used on a medium blog, allowing for trivial linking
- The medium blog contained a post about an alien vault pulse (a cyber threat intelligence report) mentioning the same pseudonym used for his Instagram account
- Associated gravatar account with the Instagram pseudonym and pictures of his face
- Gravatar linked email publicly associated with
  - registered domains
  - github accounts
  - tvtime
  - leaked data from HackForum (linked to user name LLTV), itself associated with the publication of leaked data
  - Shared pseudonym with reddit (user LLTV), mentioned in his medium blog

## Darknet Markets Administrators

Honorable Mention to Pharoah (see [indictement](https://www.justice.gov/archives/opa/media/1352571/dl) for details), for troubleshooting his servers after they went down (FBI seizure)
using google with his personal email account (page 30 of the document), he used the same account to also conduct development research.

~~~
On or about July 20, 2022, at approximately 00:18 UTC,
00:19 UTC, 00:20 UTC, and 00:23 UTC, the user of the Lin Personal Email Account-1 searched
Google for “pm2 crashed,” “view pm2 daemon logs,” “pm2 daemon logs,” and “pm2 changelog,”
respectively.
~~~

#### How it plays out

- [drug smuggling](https://www.upi.com/Archives/1984/11/21/British-boat-loaded-with-marijuana/3929469861200/)
  - OPSEC Mistakes
    - bungling the weight and balance of a smuggling ship so much that its course became erratic and attracted attention
  - Outcome
    - Seizure of the ship, and it's $32M worth of cargo, arrest of the crew members
- zeekill
  - OPSEC Mistakes
    - lack of operational segregation: there is no valid reason for having PII on the same machine as the one you use to manipulate operational data, at least use a different user created only for this purpose
  - Outcome
    - Arrest and conviction (6 years)
- USDoD
  - OPSEC Mistakes:
    - too many to count in this section, see above
  - Outcome
    - Arrest
- Pharoah
  - OPSEC Mistakes
    - use of a personal account to conduct research and operational activities
  - Outcome
    - [Arrest](https://www.ice.gov/news/releases/incognito-market-owner-arrested-operating-one-largest-online-narcotics-marketplaces)

## Identification

![radar dish](detection.jpg)

After initial detection, your adversary will start collecting data to identify you. This will be from traces you left during operations.

### What good OPSEC looks like

![checklist](checklist.jpg)

Standardized Operating procedures for your organization providing a framework for:

- general operations
  - what communication channels to use
  - the use of encryption, codewords, passphrases
  - Channel structure
    - full mesh = more danger if any one participant is compromised
    - clandestine celle structure = more resilient but also makes communication more costly
  - Communication plan for each member ([PACE](https://en.wikipedia.org/wiki/PACE_(communication_methodology)) model)
    - if one communication channel is cut or compromised, then there are fallback solutions that have already been investigated and whose risks level have been deemed acceptable
- Specific action SOPS (eg: a protest)
  - initial assembly point
  - time, date
  - means of transportation (ingress and egress)
  - materials required
    - initial sourcing
    - purchase
    - storage and delivery
    - disposal

### What bad OPSEC looks like

![cabincr3w](cabincr3w.jpg)

In 2012, Ochoa, a member of the hacktivist group CabinCr3w (an offshoot of Anonymous), conducted unauthorized intrusions into U.S. law enforcement websites. He defaced these sites and published personal information of police officers, including phone numbers and home addresses, as part of an operation dubbed "Operation Pig Roast."

Critical Mistake: Ochoa posted a photograph on one of the defaced websites showing a woman holding a sign with a message mocking law enforcement.


The picture's [metadata](../anonymitymetadata/index.md#file-data) contained GPS coordinates, which led authorities to identify and locate Ochoa.

#### How it plays out
- The FBI arrested Ochoa on March 20, 2012, in Galveston, Texas.
- He was charged with unauthorized access of a computer and, in June 2012, pleaded guilty to the charges. Ochoa was sentenced to 27 months in federal prison and ordered to pay restitution.

## Neutralization


![swat](swat.jpg)

That's when it's time to start running. If your adversary has gathered enough data to actively start neutralizing your operation you need to be prepared for it.


Such preparation has two required components:

- Detection: the more advance warning you have that the adversary is moving against you, the better
- Avoidance: neutralization actions can't be directly thwarted (unless you are a nation state and then this discussion becomes one about military tactics), so you will want to minimize the damage

### Detection
Your general operations rules should have built-in detection capacities: either a way for operators to give advance warning or for the organization to detect when one has been turned or captured.

- An easy to use counterintelligence tool is the [baryum meal test](https://en.wikipedia.org/wiki/Canary_trap) or canary trap.  By detecting leaks you can use them in anti-surveillance operations or as a warning system.
- another one is a simple canary (example: [warrant canary](https://en.wikipedia.org/wiki/Warrant_canary)) where the cessation of an innocuous action is used to send a message

#### What good OPSEC looks like

Let's talk about [Operation Delego](https://en.wikipedia.org/wiki/Operation_Delego), a major CSAM-sharing and production group was infiltrated in a joint operation conducted by 19 countries. This group counted more than 600 members and had strict operational security:

- Periodic platform change (new hidden service)
- With each platform change, all users would change pseudonyms and receive new, randomly generated ones
- Required use of GnuPG for encrypting communications
- Never share PII
- Strict metadata scrubbing policy for all shared media
- Only share media over the trusted website channels

#### The neutralization operation
After infiltrating the group, Leo managed to trick several users into directly sharing media and personal information other unsanctioned channels, without encryption.

#### Final Tally
- 72 charges (out of 600+ active members)
- 57 arrests


OPSEC works, even for the scum of the earth: 9.5% neutralization rate after being infiltrated by a joint effort between 12 countries is pretty impressive.

#### What bad OPSEC looks like

![lulzsec](lulzsec.jpg)

Now let's take a look at LulzSec. We have pretty much every OPSEC mistake rolled into one burrito of disappointment. We will use the analysis framework we've worked with so far

LulzSec (Lulz Security) was a high-profile hacker group active in 2011, known for brazen cyberattacks on corporations, governments, and media.


One of their members (Sabu) was identified, turned and then used to compromise the rest of the group.


#### Detection
That one's easy: between the defacement and bragging all over the web about their hacks, the operations were **meant** to be visible

#### Identification
- Sabu was identified after logging into IRC from his home IP instead of through Tor: it only happened once, but it was enough
- Members reused online aliases across multiple platforms. For example, some had past activity linked to now-doxxed identities.
- Email addresses used for domains or accounts were linked to real-life identities.
- Boasting about hacks and providing technical details exposed them.
- There was minimal effort to isolate real identities from online personas or separate operations between different members.
- Many used the same machines for both personal and hacking activities.
- The group let in new members quickly, including undercover agents or individuals who later cooperated with law enforcement.
- They issued press releases and taunted their targets on Twitter, which increased media attention and pressure on authorities to catch them.
- This also gave law enforcement leads to correlate timing between attacks and online activity.
- Use of non-anonymized IRC clients, known VPN services, and unencrypted communication channels made traffic analysis easier.

### Neutralization

By mid-2012, most core members were arrested and charged.


# Threat Modeling: choosing the right tool for the job

![threat modeling](threat_model.jpg)

We now have a simple framework (detection, identification, neutralization), that's actually called an attack cycle model. This will help us think our OPSEC procedures in a way that is methodical and grounded in rationality.


As we have seen, depending on the situation you might need higher or lower security measures. Usually, when you crank up the security, communication slows down and becomes harder. When you want easier and faster communication, you often have to lower your security requirements.


## What is a threat model

In order to decide which OPSEC practices to adopt you have to know what you are defending against. Gun running, protest organization against private corporations and civil disobedience are activities that can bring the wrong kind of attention, but they all have wildly different threat models.


A threat model is a description of your adversaries with:

- their goals
- capabilities
- targets


The more powerful and well-funded the adversary, the more dangerous it is (States being at the top of the food chain).

### Quick Example
Alice wants to organize a protest against Evil Corp evil practices of experimenting broccoli based diets on kittens. Evil Corp has been known to intimidate would-be protesters by hiring private detectives and thugs.

![evil corp logo](ecorp.png)

#### Evil Corp threat model
- goals
  - preventing disruption of their operations by protesters
  - preventing PR fallout from their evil experimentation becoming public knowledge
- capabilities
  - technologically low, as they use tried and true methods of physically tailing people and throwing bricks through their windows
- targets
  - protest organizers and their assets

## Risk Analysis

The next step is to run a risk analysis: you want to list all your assets that are in play in your clandestine Ops, define how critical they are on three axes:
- Confidentiality
- Integrity
- Availability


### Example
Alice determines that her group of protesters has the following asset

- Member list and contact info
  - Confidentiality requirement: **High**
  - Integrity requirement: **High** (we don't want someone infiltrating the mailing list)
  - Availability requirement: **Medium** (even if the list is destroyed, core members have copies and can reconstruct it together)

Given her threat model, she determines the following plausible attack scenario:

- Getting tailed after a protest and having her laptop stolen from her home with the list on it: **High likelihood, fits the MO and threat model**
- Someone grabbing her laptop from her while she's planning her next big anti-corporate protest while sipping from a triple latte double macchiato at Starbucks **Medium likelihood**
- someone hacking the mailing list server to read all the protest prep exchanges **Low likelihood**

## OPSEC Standards and procedures

Armed with her risk analysis, Alice's now knows which assets are most likely to be targeted. Thanks to the threat modeling exercise she has several attack scenarios. Based on their likelihood, her OPSEC efforts will be prioritized the following way:

- Anti-surveillance and Counter-surveillance techniques to identify whether members are getting tailed after meetings or protests
- Encryption on her laptop, automatic shutdown if someone grabs it
- Hardening of the email server

![stop sign](stop.jpg)

## Know when to stop
Why isn't she preparing for a large scale hacking campaign against her identities, followed with a 0-day barrage of all her servers and a complete compromise of her household appliances down to the lowliest airtag?


**Because it does not fit the threat model, and it would be easier and more cost-effective to break into her house and grab her stuff, especially if her machine is unencrypted**


# Now what?

A threat model is a living thing, like any GRC (Governance, Risk and Compliance) document. Your adversaries will change in capabilities, motivations, methods as time passes. Your organization will change too, adopting new tools, forsaking old ones. In order to stay safe, you need to keep your threat model and risk analysis up to date, so you security level is always where it needs to be.


- To be effective you need to be able to communicate with the highest bandwidth possible with the rest of your organization. Perfect OPSEC is useless if it makes you unable to function.
- To be resilient you must have enough security to thwart your adversary and a defense in depth mindset to ensure that even in case of a successful attack your whole operation isn't toast.


Threat modeling and risk analysis are skills that are highly sought for by companies themselves in order to protect their assets, cybersecurity professionals spend years cultivating them. This was a primer, I invite you to read more on the subject or get in touch if you need coaching or help doing this for your own operations.
