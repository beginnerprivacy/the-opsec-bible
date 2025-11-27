---
author: cyclonus
date: 2025-10-05
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/478"
xmr: 835jmkN5kuE9123zERTG919u2UKRRqhNkKCPYFy55skC8EFdMQip9cyGPzjXPc4gyuL4uUQqRn7HVBbenDbC95AyDU5heFR
tags:
  - Opsec Mistakes
  - Bad Identity Segmentation
  - Not Using SimpleX
  - Clearnet Sensitive Activity
---

# **LAPSUS$ OPSEC Mistakes**

This post focuses specifically on the **operational security (OPSEC) mistakes made by LAPSUS$**. It does not aim to detail the group's attack techniques or expose the identities of its members.

For those who are interested in deeper investigations and background material, see the following external resources:

- **[CISA review](https://www.cisa.gov/sites/default/files/2023-08/CSRB_Lapsus%24_508c.pdf)** (U.S. government analysis of LAPSUS$ activity)

- **[Intrinsec review](https://www.intrinsec.com/wp-content/uploads/2022/03/INTRINSEC-LAPSUS-Intrusion-Set-20220324.pdf)** (private sector insights into the group's operations)

- **[Sekoia post on LAPSUS$](https://web.archivep75mbjunhxc6x4j5mwjmomyxb573v42baldlqu56ruil2oiad.onion/web/20240927064617/https://blog.sekoia.io/lapsus-when-kiddies-play-in-the-big-league/)** (research and threat intelligence reporting)

- **[ViLE dump](https://vile.sh/data/text/white.txt)** (leaked material from the considered leader of LAPSUS$)

- **[Kerbs on Security](https://krebsonsecurity.com/2022/03/a-closer-look-at-the-lapsus-data-extortion-group/)** (further analysis of the LAPSUS$ extortion model)

- **[Microsoft DEV-0537 report](https://www.microsoft.com/en-us/security/blog/2022/03/22/dev-0537-criminal-actor-targeting-organizations-for-data-exfiltration-and-destruction/)** (Microsoft's threat intelligence write-up on LAPSUS$)

## **What is LAPSUS$?**

**[LAPSUS$](https://en.wikipedia.org/wiki/Lapsus$)** is an **international hacker group** focused on **financially motivated extortion**. Unlike ransomware crews that encrypt files, LAPSUS$ often stole highly confidential data and then threatened to leak or delete it unless paid. 

To gain access, the group used a mix of techniques:

- **SIM swapping** to hijack accounts tied to phone numbers.

- **Social Engineering** to trick employees or support staff.

- **Exploiting unpatched vulnerabilities and CVEs** to break into systems.

Once inside, LAPSUS$ often targeted collaboration and development platforms like Slack, Skype, GitLab, and Jira. These footholds gave them opportunities to escalate privileges, move laterally, and increase the pressure of their extortion campaigns.

## **OPSEC Mistakes that were made by LAPSUS$**

### Early handle reuse

The individual believed to be LAPSUS$'s leader, often referred to as *white*, had already left a digital trail long before the group became active. In his early days, he exploited Minecraft bugs on PvP servers under the handle *shadowarion4384*. Later, he reused similar usernames in the hacker group **[CyberTeam](https://pica.zhimg.com/v2-9f9c9f7260c6e94233395f1342e3ae82_1440w.jpg)**, which he joined with close friends. This careless reuse of handles tied together different stages of his online life. When he purchased **Doxbin** in 2021, he [admitted](https://vile.sh/white/oeNaM.png) to the previous owner that he had once been [doxxed](http://archiveiya74codqgiixo33q62qlrqtkgmcitqx5u2oeqnmn5bpcbiyd.onion/9AYRt) via an old Pastebin post. He even conceded that his name was correct while much of the leaked information was wrong. That same paste indicates that *shadowarion4384* had been used to target him. At this point, law enforcement had not yet connected *white* to LAPSUS$.

![RealNameRevealed](Same_Username.png)

### Reusing cryptocurrency addresses

Roughly six months before LAPSUS$ rose to prominence, *white* hacked **Electronic Arts (EA)**. EA's investigation through **EE Enterprise** noted the XMR (Monero) wallet addresses included in the ransom note. Later, as LAPSUS$ ramped up attacks and extortion against multiple companies and services, *white* bought **Doxbin** and updated its admin contact to *doxbin@protonmail.com*, linking it with a Telegram username called *whitedoxbin*. Investigators confirmed that the XMR address used in the earlier EA ransom note was the same as one later tied to LAPSUS$'s late attacks ransom note, directly linking *white* to the group's operations. 

![XMRConfirmation](XMR_addresses.png)

### Translation watermark slip

Investigartors noticed that *white*, posting under the alias *doxbinwh1ite*, had used [DeepL](https://www.intrinsec.com/wp-content/uploads/2022/03/INTRINSEC-LAPSUS-Intrusion-Set-20220324.pdf) to translate one of his post. The translation watermark remained visible in the post, where he was attempting to sell stolen data from **EA**, **LG**, and other companies to a wider audience, and to join other hacker team. By providing both English and Russian versions of the message in a single post, he inadvertently exposed patterns that allowed law enforcement to narrow down his possible location. 

![DeepL_Watermark](DeepL_WM.png)

### Reliance on centralized services

LAPSUS$ often relied on centralized, closed-source services for both operations and communications. Telegram was used both as a coordination hub and as a public platform for leaking or selling stolen data. They also relied on mainstream VPS providers like **AWS** and **[OVH Cloud](https://krebsonsecurity.com/wp-content/uploads/2022/04/somuchillegalshit.png)** to store stolen information and used file-sharing sites such as **filetransfer.io** to download stolen information to VPSes. This gave law enforcement an advantage, centralized services could be compelled to share phone numbers, IP addresses, and logs. Producing evidence that takes away the anonymity and denial abilities of LAPSUS$.

![KYC](KYC.png)

### Doxbin conflicts and exposure

The decision to buy **Doxbin**, a notorious site used for sharing doxxes, backfired. *White* failed to manage the community effectively and eventually returned ownership of the sire to its prior owner, *kt*. This enraged the community, which retaliated by **doxxing** *white* **himself**. The resulting leaks contained sensitive details, including his real name, address, and ties to LAPSUS$. Law enforcement gained access to this dump, which gave them even more evidence against him.

![White-Doxbin](White-Doxbin.png)

### Accidental location disclosure

Despite his growing notoriety, white continued using everyday apps without properly managing their privacy settings. On **Snapchat**, for example, he left **Snap Map** location-sharing active instead of enabling Ghost Mode or restricting it to trusted contacts. This oversight allowed members of the **Doxbin** community to track his [real-world location](https://vile.sh/white/AyS1g.png), further exposing him to investigators and adversaries.

Additionally, it's important to note that the **company behind Snapchat** can still **see his activity on the app**, **his general location**, **and his movement history**. This means there were effectively **two adversaries**. The **Doxbin community**, which exploited his public location data, and **Snapchat itself**, which retained access to sensitive information and could be easily compelled to share it with law enforcement through a **subpoena** if required.

![LocationRevealed](snapmap.png)

### Internal conflicts and leaks

**TLDR; when doing a sensitive activity, maintain your anonymity at all costs, to even protect against the worst case scenario being that a trusted administrator could go be an informant. Telegram, Snapchat, etc these are all apps that can only be suitable for public use, NOT sensitive use. Even if there are internal conflicts and leaks, the possibility of any member of your own community to figure out your true identity must not even be possible in the first place.**

Tensions inside LAPSUS$ created cracks that investigators could exploit. In leaked Telegram chats, *white* accused and exposed his fellow members, sometimes even revealing their **real names**. For example, he outed *amtrak* (also known as *asyntax1*), [revealing him](https://krebsonsecurity.com/wp-content/uploads/2022/04/amtraxdox.png) as **Thalha Jubair** after police recovered LAPSUS$ Telegram conversations from *amtrak*'s phone. Another member, *Mox*, feared his own real name might be leaked after it appeared in chats. At one point, *white* even threatened *Mox*, claiming he could extract his personal data through [fake emergency disclosure requests](https://krebsonsecurity.com/wp-content/uploads/2022/04/edrtooapple.png) to **Apple**. These betrayals and leaks fueled distrust inside the group and provided law enforcement with additional identifiers shortly before arrests were made.

![Reveals-members](Reveals-members.png)

## **Arrest and legal consequences of Arion Kurtaj**


### December 2021 (first arrest)

Arion was first arrested in December 2021 in connection with LAPSUS$. He was later released pending further investigation. Despite this, he showed no signs of slowing down his hacking activities.

### 1 April 2022 (second raid and court appearance)

On the morning of April 1st, law enforcement raided him again. That same day, he appeared in court facing multiple charges:

- Three counts of **unauthorized access to a computer with intent to impair data reliability**

- One count of **fraud by false representation**

- One count of **unauthorized access to a computer with intent to hinder access to data**

- One count of **causing a computer to perform a function to secure unauthorized access to a program**

He was released on **2 April 2022**, with **one-month internet suspension** as bail condition.

### 22 September 2022 (third arrest)

On the evening of 22 September 2022, the **[City of London Police]((https://twitter.com/CityPolice/status/1573281533665972225))**, supported by the **NCA's National Cyber Crime Unit**, arrested a 17 years old in Oxfordshire on suspicion of hacking. He remained in custody following the arrest.

### 24 September 2022 (youth court hearing)

Two days later, on 24 September 2022, Arion appeared before **Highbury Corner Youth Court** in London. He faced new charges:

- Two counts of **breach of bail conditions** (to which he pleaded guilty)

- Two counts of **computer misuse** (to which he pleaded not guilty)

During the hearings, the court also heard that Arion had been violent while in custody, with dozens of reported incidents of injury or property damage.

### Medical assessment and trial outcome

Doctors ultimately deemed him **unfit to stand trial** because of his severe autism. The jury was therefore asked only to determine whether he had committed the alleged acts, not whether he acted with criminal intent.

### Final Sentence

The court ordered that Arion **be detained in a secure hospital for life**, unless doctors determine in the future that he is no longer a danger.


## **What should LAPSUS$ have done differently?**

First, LAPSUS$ should review our [Internet Usage Segmentation](../internetsegmentation/index.md). Therefore, LAPSUS$ have a strong foundation on how to gain repetitive attacks that escalate but still maintain anonymity. To avoid being doxxed, LAPSUS$ leader White should first read our guide on [transfer activities across identities](../opsecoverego/index.md), so that there are more dispersed activities across identities, resulting in the spread of data. When compromised, someone could not get the full information right away. Next, he should have used non-KYC services and apps since they do not collect the data that is in the account or associated with the account. He should also change the handles or the usernames of apps and services that he uses over a certain period of time. That way, there is much less association within his account with another from his activity.

For leveraging reputation, there is a need for reaching other group with whole difference of structure and culture. To communicate effectively, LAPSUS$ should have read our guide on [stylometry](../stylometry/index.md). Therefore, they have a solid way of communicating. Next, LAPSUS$ can [rent a remote VPS server anonymously (non-KYC cloud resellers)](../anonymousremoteserver/index.md) to avoid physical evidence if being busted by the LE, but still maintain secure and easy access.LAPSUS$ should've read our guide on [Public Chats / Private Chats / Anonymous Chats / Deniable Chats](../chats/index.md). That way, LAPSUS$ know what to be talked and where it should be talked about on a certain platform. Then, LAPSUS$ should read our guide on [Anonymous Chats Using SimpleX](../anonsimplex/index.md). From there, they don't have to worry about LE surveillance or what they are going to do next.
