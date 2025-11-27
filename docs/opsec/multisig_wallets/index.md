---
author: MulliganSecurity
date: 2025-10-18
gitea_url: http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/505
xmr: 82htErcFXbSigdhK9tbfMoJngZmjGtDUacQxxUFwSvtb9MY8uPSuYSGAuN1UvsXiXJ8BR9BVUUhgFBYDPvhrSmVkGneb91j
tags:
  - Decentralized Finances
---

# Prevent scams using Multisig 2of3 Monero wallets

### The issue of trust on anonymous platforms

When you wish to trade good or services on the Free Web, through DNMs or directly with other individuals you are immediately
confronted with a connundrum: who can you trust?

Different platforms have had different approaches over the years:

- DNMs usually require either a good track record in the form of past reviews or a hefty deposit to insure against scam and make customers whole
- Decentralized platforms such as haveno usually rely, under the hood, on multisig wallets and arbitrators

Today we will discuss multisig wallets for the monero cryptocurrency and how you can use these to trade safely in different scenarios without
having to rely on third party software.

![](platforms.png)


### Associated risks

There are two main associated risks with the above approaches:

- Rugpull on DNMs: the administrators decide to run for it, stealing everyone's funds (happens regularly)
- decentralized platform hack (much less likely)


## Trust, community and reputation

In a voluntaryist community such as the Nihilist archipelago we favor decentralized solutions. Here we will give you the means
to conduct voluntary exchanges anonymously with as little risk as possible.


First, one must understand why multisig wallets are important: they allow us to trade without needing too much trust.
When someone new comes in contact with a community on the Free Web they can be anyone and disappear whenever they want.
Without more information and a track record there is a high risk they are a scammer. As an outsider they also risk being
scammed by an established member that would then use their status to deny it. Let's describe first how such a deal could take place:

![](scammer.png)

### How do we solve this

1. Build trust and status with the rest of the community: if two well-known members of a community deal with each other they also put their
reputations at stake. If one was to renege or scam their counterpart, the victim could bring this up with proof to the rest of the community
and have the badly behaving member banished, essentially destroying all their reputation and whatever goodwill they have built.
2. Name an arbitrator: choose a third party to mediate in case of disagreement
3. Put down a stake if the trust level remains too low

#### What criteria must an arbitrator fulfill

In order to be credible, an arbitrator must be:

1. Well known and respected: their decision should be perceived as final and accepted by both parties and the wider community as final
2. Have a reputation of fairness and integrity
3. Have enough experience and expertise in the domain being traded

#### What is the arbitrator's role

The arbitrator isn't just here to resolve disputes, they have a complete role as a facilitator. Even if the deal is voluntary they will:
- ensure a fair deal is reached: one party must not get ripped off (their own reputation as well as their community's is at stake)
- ensure transparent negociation: they will be witness to all exchanges prior and during the transaction
- ensure an ethical outcome even if no deal takes place: protecting their own reputation and their community means even an outsider shouldn't get robbed when they come to trade in good faith

![](arbitrator.png)

## Tools and processes

In order to acomplish this, we need the following tools:

- A way to store and move value requiring agreement between parties:
  - the multisig wallet
- A way to conduct negociations in a private manner between parties
  - simpleX
  - PGP
- A way to prove commitments and payments to third parties
  - PGP
  - the multisig wallet

## Process


### Setup
![](creation_flow.png)

When two individuals decide to trade with each other they will first need to agree on an arbitrator and a fee (traditionally 5%, can be negociated with the arbitrator themself), this fee
is paid by both individuals.


They will then create a 2/3 multisig wallet. The following steps must be done by all participants:

### Monero-cli installation
~~~
[user@devnode:~]$ sudo apt install monero
~~~

### Choosing a monero node

In the following example, I am working with a monero node accessed over tor. You can find one of those easily using the lantern and filtering by nodes, or use a public one but through the tor proxy for added safety.
It is best, of course, to run one's own node and help the network stay decentralized that way.

### Wallet creation
~~~
[user@devnode:~]$ monero-wallet-cli --proxy 127.0.0.1:9050 --trusted-daemon --daemon-host [snip]f6zbwiarkacc[snip].onion --daemon-login myusername:myrpcpassword --generate-new-wallet testwallet1                                                                                                                                                                                                               
This is the command line monero wallet. It needs to connect to a monero                                                                                                                                                                     
daemon to work correctly.
WARNING: Do not reuse your Monero keys on another fork, UNLESS this fork has key reuse mitigations built in. Doing so will harm your privacy.

Monero 'Fluorine Fermi' (v0.18.4.2-unknown)
Logging to monero-wallet-cli.log
Enter a new password for the wallet: 
Confirm password: 
List of available languages for your wallet's seed:
If your display freezes, exit blind with ^C, then run again with --use-english-language-names
0 : Deutsch
1 : English
[snip]
Enter the number corresponding to the language of your choice: 1
Generated new wallet: 46XVFMwQiY1L4WEbuQr9kS2huy39b7xQV7voVEQyDiEu5ge2YA9C5c9HWLvYnG33iEgmC8ENX9oSsDfBQu2PCjZWDUzMqKy
View key: 131d0394fb5dbd1960f1eb7c437888dbcf6740d073939d24342b617482b50409
**********************************************************************
Your wallet has been generated!
To start synchronizing with the daemon, use the "refresh" command.
Use the "help" command to see a simplified list of available commands.
Use "help all" command to see the list of all available commands.
Use "help <command>" to see a command's documentation.
Always use the "exit" command when closing monero-wallet-cli to save 
your current session's state. Otherwise, you might need to synchronize 
your wallet again (your wallet keys are NOT at risk in any case).


NOTE: the following 25 words can be used to recover access to your wallet. Write them down and store them somewhere safe and secure. Please do not store them in your email or on file storage services outside of your immediate control.


bodies rising [snip]
[snip] sorry tarnished abnormal
**********************************************************************
The daemon is not set up to background mine.
With background mining enabled, the daemon will mine when idle and not on battery.
Enabling this supports the network you are using, and makes you eligible for receiving new monero
Do you want to do it now? (Y/Yes/N/No): : N
Background mining not enabled. Set setup-background-mining to 1 to change.
If you are new to Monero, type "welcome" for a brief overview.
Starting refresh...
Refresh done, blocks received: 0                                 
Untagged accounts:
          Account               Balance      Unlocked balance                 Label
 *       0 46XVFM        0.000000000000        0.000000000000       Primary account
------------------------------------------------------------------------------------
          Total          0.000000000000        0.000000000000
Currently selected account: [0] Primary account
Tag: (No tag assigned)
Balance: 0.000000000000, unlocked balance: 0.000000000000
Background refresh thread started
[wallet 46XVFM]: 
~~~

#### What a N/M wallet is

Multisig wallets require the signature of a set of participants to authorize transaction. N participants out of a total of M is noted as N/M.
Thus a 2/3 wallet requires two signatures from any two of three participants.

### Multisig configuration

Here are the steps each participant must follow:

#### Enable the multisig feature on their wallet

Arbitrator
~~~
[wallet 46XVFM]: set enable-multisig-experimental 1
Wallet password: 
~~~

Bob
~~~
[wallet 43jELM]: set enable-multisig-experimental 1
Wallet password:
~~~

Charlie
~~~
[wallet 4A2zSm]: set enable-multisig-experimental 1
Wallet password:
~~~


#### initialize multisig on their wallet

*Arbitrator*
~~~
[wallet 46XVFM]: prepare_multisig 
Wallet password: 
MultisigxV2R1LiZtk1e9LYR3YkfMB9fsePPdHcRwf8fxZ21XCpPFin2pGguFELkd9AC2asCwY7S1PjQMA5776EjxAGqMT3BsHjMf2uZ1am1g4BMaTaW3sw6uuhLFjHYdrm5hrP43wLpHVYdCVu52PveB2H4YiqbGGm8fvVXRJT36pHKyP3SZzidtt2RJ
Send this multisig info to all other participants, then use make_multisig <threshold> <info1> [<info2>...] with others' multisig info
This includes the PRIVATE view key, so needs to be disclosed only to that multisig wallet's participants 
~~~

*Bob*
~~~
[wallet 43jELM]: prepare_multisig 
Wallet password: 
MultisigxV2R1SqdAkGLo712QfpHVsRatqzRBfMZe1tDXCEE1tBiA9MHchiZ7w8hVZaibiiteMyJnPwLa54yHGsY4m2vB9z67WhsYCtMq2a7ZofKPMMqgm49ALqdqDR6129tm43Pb76yp8vnS7ogwuVh9WvoCieT1pCrqkoNdXGSU9QTYCMn5wbnzJqG7
Send this multisig info to all other participants, then use make_multisig <threshold> <info1> [<info2>...] with others' multisig info
This includes the PRIVATE view key, so needs to be disclosed only to that multisig wallet's participants 
~~~

*Charlie*
~~~
[wallet 4A2zSm]: prepare_multisig 
Wallet password: 
MultisigxV2R18AHCGBUEFE5V2pTsUT6zRyhiQCf8WNbV6bQ3Hc7aha3SavPr4dXuYH3NDnywwvp91AG8tamgvdQoxaRWtA69RjFpKzdg8ByFvnUNmBvVyHXC7cLhPtJnf2kVkMn9rPsCT3SQcJ8tzWMaHCGeXBYBNeySRH1ZeWLiqUFUZfY79bMvFyp9
Send this multisig info to all other participants, then use make_multisig <threshold> <info1> [<info2>...] with others' multisig info
This includes the PRIVATE view key, so needs to be disclosed only to that multisig wallet's participants 
~~~

#### Configure their local wallets with the other participants initialization data, obtained through a secure channel such as their simpleX conversation

*Arbitrator*
~~~
[wallet 46XVFM]: make_multisig 2 MultisigxV2R1SqdAkGLo712QfpHVsRatqzRBfMZe1tDXCEE1tBiA9MHchiZ7w8hVZaibiiteMyJnPwLa54yHGsY4m2vB9z67WhsYCtMq2a7ZofKPMMqgm49ALqdqDR6129tm43Pb76yp8vnS7ogwuVh9WvoCieT1pCrqkoNdXGSU9QTYCMn5wbnzJqG7 MultisigxV2R18AHCGBUEFE5V2pTsUT6zRyhiQCf8WNbV6bQ3Hc7aha3SavPr4dXuYH3NDnywwvp91AG8tamgvdQoxaRWtA69RjFpKzdg8ByFvnUNmBvVyHXC7cLhPtJnf2kVkMn9rPsCT3SQcJ8tzWMaHCGeXBYBNeySRH1ZeWLiqUFUZfY79bMvFyp9
Wallet password: 
Another step is needed
MultisigxV2Rn1LWa7qiwaxbRdzCnHZX3jua7jac6Jmr2LfSLxVx8gFMZMXQpsUK8dNSLWoxHtjtwcjfHZJWseThB5eSUuAbts7fQaHZfUa15twmbjQytCepxCb9qHxDpkmUfd2LazmgYTPXgHPN2mX8NFpZfrxj5xpm6qmbKuLaea7L5QbsxNPTE5W9zVweTZ79rGTuRnvxZWPJjb5B2rikkyo5tSRJQwbV33GCtDL5
Send this multisig info to all other participants, then use exchange_multisig_keys <info1> [<info2>...] with others' multisig info
[wallet 41fJjQ (out of sync)]:
~~~

*Bob*
~~~
[wallet 43jELM]: make_multisig 2 MultisigxV2R1LiZtk1e9LYR3YkfMB9fsePPdHcRwf8fxZ21XCpPFin2pGguFELkd9AC2asCwY7S1PjQMA5776EjxAGqMT3BsHjMf2uZ1am1g4BMaTaW3sw6uuhLFjHYdrm5hrP43wLpHVYdCVu52PveB2H4YiqbGGm8fvVXRJT36pHKyP3SZzidtt2RJ MultisigxV2R18AHCGBUEFE5V2pTsUT6zRyhiQCf8WNbV6bQ3Hc7aha3SavPr4dXuYH3NDnywwvp91AG8tamgvdQoxaRWtA69RjFpKzdg8ByFvnUNmBvVyHXC7cLhPtJnf2kVkMn9rPsCT3SQcJ8tzWMaHCGeXBYBNeySRH1ZeWLiqUFUZfY79bMvFyp9
Wallet password: 
Another step is needed
MultisigxV2Rn1LWa7qiwaxbRdzCnHZX3jua7jac6Jmr2LfSLxVx8gFMZMXPphnMJ4qSbVkDdhTk8KSejRTZ2SA3bCfH9qKFMwrckgYrQHUfRfYvfHX5cpA8jmGSFE1iXQtL6gY2Ctz2NVgSrRUqfAGht4zcEtGeYs3ot14bRoZmQkTsCgJiTqqzUPKu6h9pixZf8DkBXsvLd9aFSMmBGLWhfraijBE45PDjoB1GwL6s
Send this multisig info to all other participants, then use exchange_multisig_keys <info1> [<info2>...] with others' multisig info
[wallet 41fJjQ (out of sync)]: 
~~~

*Charlie*
~~~
[wallet 4A2zSm]: make_multisig 2 MultisigxV2R1LiZtk1e9LYR3YkfMB9fsePPdHcRwf8fxZ21XCpPFin2pGguFELkd9AC2asCwY7S1PjQMA5776EjxAGqMT3BsHjMf2uZ1am1g4BMaTaW3sw6uuhLFjHYdrm5hrP43wLpHVYdCVu52PveB2H4YiqbGGm8fvVXRJT36pHKyP3SZzidtt2RJ MultisigxV2R1SqdAkGLo712QfpHVsRatqzRBfMZe1tDXCEE1tBiA9MHchiZ7w8hVZaibiiteMyJnPwLa54yHGsY4m2vB9z67WhsYCtMq2a7ZofKPMMqgm49ALqdqDR6129tm43Pb76yp8vnS7ogwuVh9WvoCieT1pCrqkoNdXGSU9QTYCMn5wbnzJqG7
Wallet password: 
Another step is needed
MultisigxV2Rn1LWsfgetXxnLWoxHtjtwcjfHZJWseThB5eSUuAbts7fQaHZzHH3ZvptbVkDdhTk8KSejRTZ2SA3bCfH9qKFMwrckgYr43zhZR2HQsoDTGqd7piEZTdMoviuWpibaB3o8mMMH9mFhegaBAiLgasHvLoNzNKKCn7HTeK66mb8TSwZX7SuRDDT1SvKjA8eBbzhG2qgb69D5iFgNYeRY9S2TQcPRTJQXAkE
Send this multisig info to all other participants, then use exchange_multisig_keys <info1> [<info2>...] with others' multisig info
[wallet 41fJjQ (out of sync)]: 
~~~

You will note that at the end of those steps they are all manipulating the same (41fJjQ) wallet!

#### Synchronize their wallets with each other

Now they will have to do a 2-rounds key exchange:

*Arbitrator*
~~~
[wallet 41fJjQ (out of sync)]: exchange_multisig_keys MultisigxV2Rn1LUp8a8dHuJTNtmgvnNf5HihCZ9uNj2Jy5bhZ3JU5Pu1D8jV87qDh4HEaHRekj1Q9JYYdMobJuSgnCQsgdVuP8q7DxBeb5rFAYhSkUTMKMcZ5LH9AU7zSKV67aBDXpn1Jmibapj8vtTLxaQFwLEXYEqmx7Hm7hcJdtFs4grnVoWnnh5QaHrR8Vq6hpGVqQ7PvKsAzFCa65ynpwLPsbNhdhVWwLbW4CX MultisigxV2Rn1LVrwqrBvxv8S3RFmADQ5UR5LUqoQ3weuTeypD8oq2vT5XreiaHqrXoEaHRekj1Q9JYYdMobJuSgnCQsgdVuP8q7DxAf1S4bxzfgA5pc93QyfoU2z3EgEVvgAZUt4EruNTkCasN9wXzAfuK5hgJ6avG8Z8gZbfWZAB1JjeX4g1bfFy6Q8sNvQFWAmYqBvJMSK2BWTxgfLP67u6eHxNqVj4eSAvxxCLi
Wallet password: 
Another step is needed
MultisigxV2Rn1WDXGJ2QdU5bp4u5fJm2HvdayVZUT8FZ3ZdhN9oHHSDfLPk6cfdymBtjiRr4x7y37HiSXDyFAwGts2FeucAmUdDVLUdSgYYF9EpaT84314gGcrEFvxVogMWbRYqdcyUfSursd8PAMEKQCZWAiUyKaGDEPVJHJ6XNpLapQ6ZdFPr7nsTV1LvKNKrXrJ2VEo82Yx2ErF5uPX4fL8MVpbj68SPkc2TsCZx
Send this multisig info to all other participants, then use exchange_multisig_keys <info1> [<info2>...] with others' multisig info
[wallet 4Avk37 (out of sync)]: exchange_multisig_keys MultisigxV2Rn1WDXGJ2QdU5bp4u5fJm2HvdayVZUT8FZ3ZdhN9oHHSDfLPk6cfdymBtjiRr4x7y37HiSXDyFAwGts2FeucAmUdDVLUeUaBDxdSZSkUTMKMcZ5LH9AU7zSKV67aBDXpn1JmibapiqPVQdFyHMibEpRciKsdZg8kEQ3hkpWJvY1tDbXZhFS6kxtS7v8vLFFtYQRaeAN7atbc1UXzgoTJzX5q3VbEV2Kj2 MultisigxV2Rn1WDXGJ2QdU5bp4u5fJm2HvdayVZUT8FZ3ZdhN9oHHSDfLPk6cfdymBtjiRr4x7y37HiSXDyFAwGts2FeucAmUdDVLUdUzXSKRtXgA5pc93QyfoU2z3EgEVvgAZUt4EruNTkCasP5GF5usueWjnP3PLpoXZDBcZSuMqZ8yaKLefJwyffUTbk8SDSTkngGnRA7vwRyNRUm9geWVA4ThZphQG3FAfCQ52w
Wallet password: 
Multisig wallet has been successfully created. Current wallet type: 2/3
Multisig address: 4Avk37SNhMH6KuQV9K8fpdYLqbcjz8Zez5CdV4mvsuN2hALrgwJUikvGvtjtsHU5rNZGo1DKPrEucMwfoHZw3ChhDkWr8E4
[wallet 4Avk37]:
~~~

*Bob*
~~~
[wallet 41fJjQ (out of sync)]: exchange_multisig_keys MultisigxV2Rn1LUp8a8dHuJTNtmgvnNf5HihCZ9uNj2Jy5bhZ3JU5Pu1D8jsGiR58Z48S3RFmADQ5UR5LUqoQ3weuTeypD8oq2vT5XqxgExpTmzaT84314gGcrEFvxVogMWbRYqdcyUfSursd8NYh5czdVYASE92oR2ai2LtkXJpCQqzjaYfhHLYxPkb2qkdJ9qfaeAD9kSGXYtWB2SKDjxk5heQbUwaJiewrf9J1gt MultisigxV2Rn1LVrwqrBvxv8S3RFmADQ5UR5LUqoQ3weuTeypD8oq2vT5XreiaHqrXoEaHRekj1Q9JYYdMobJuSgnCQsgdVuP8q7DxAf1S4bxzfgA5pc93QyfoU2z3EgEVvgAZUt4EruNTkCasN9wXzAfuK5hgJ6avG8Z8gZbfWZAB1JjeX4g1bfFy6Q8sNvQFWAmYqBvJMSK2BWTxgfLP67u6eHxNqVj4eSAvxxCLi
Wallet password: 
Another step is needed
MultisigxV2Rn1WDXGJ2QdU5bp4u5fJm2HvdayVZUT8FZ3ZdhN9oHHSDfLPk6cfdymBtjiRr4x7y37HiSXDyFAwGts2FeucAmUdDVLUeUaBDxdSZSkUTMKMcZ5LH9AU7zSKV67aBDXpn1JmibapiqPVQdFyHMibEpRciKsdZg8kEQ3hkpWJvY1tDbXZhFS6kxtS7v8vLFFtYQRaeAN7atbc1UXzgoTJzX5q3VbEV2Kj2
Send this multisig info to all other participants, then use exchange_multisig_keys <info1> [<info2>...] with others' multisig info
[wallet 4Avk37 (out of sync)]: exchange_multisig_keys MultisigxV2Rn1WDXGJ2QdU5bp4u5fJm2HvdayVZUT8FZ3ZdhN9oHHSDfLPk6cfdymBtjiRr4x7y37HiSXDyFAwGts2FeucAmUdDVLUdSgYYF9EpaT84314gGcrEFvxVogMWbRYqdcyUfSursd8PAMEKQCZWAiUyKaGDEPVJHJ6XNpLapQ6ZdFPr7nsTV1LvKNKrXrJ2VEo82Yx2ErF5uPX4fL8MVpbj68SPkc2TsCZx MultisigxV2Rn1WDXGJ2QdU5bp4u5fJm2HvdayVZUT8FZ3ZdhN9oHHSDfLPk6cfdymBtjiRr4x7y37HiSXDyFAwGts2FeucAmUdDVLUdUzXSKRtXgA5pc93QyfoU2z3EgEVvgAZUt4EruNTkCasP5GF5usueWjnP3PLpoXZDBcZSuMqZ8yaKLefJwyffUTbk8SDSTkngGnRA7vwRyNRUm9geWVA4ThZphQG3FAfCQ52w
Wallet password: 
Multisig wallet has been successfully created. Current wallet type: 2/3
Multisig address: 4Avk37SNhMH6KuQV9K8fpdYLqbcjz8Zez5CdV4mvsuN2hALrgwJUikvGvtjtsHU5rNZGo1DKPrEucMwfoHZw3ChhDkWr8E4
[wallet 4Avk37]: 
~~~

*Charlie*
~~~
[wallet 41fJjQ (out of sync)]: exchange_multisig_keys MultisigxV2Rn1LUp8a8dHuJTNtmgvnNf5HihCZ9uNj2Jy5bhZ3JU5Pu1D8jsGiR58Z48S3RFmADQ5UR5LUqoQ3weuTeypD8oq2vT5XqxgExpTmzaT84314gGcrEFvxVogMWbRYqdcyUfSursd8NYh5czdVYASE92oR2ai2LtkXJpCQqzjaYfhHLYxPkb2qkdJ9qfaeAD9kSGXYtWB2SKDjxk5heQbUwaJiewrf9J1gt MultisigxV2Rn1LUp8a8dHuJTNtmgvnNf5HihCZ9uNj2Jy5bhZ3JU5Pu1D8jV87qDh4HEaHRekj1Q9JYYdMobJuSgnCQsgdVuP8q7DxBeb5rFAYhSkUTMKMcZ5LH9AU7zSKV67aBDXpn1Jmibapj8vtTLxaQFwLEXYEqmx7Hm7hcJdtFs4grnVoWnnh5QaHrR8Vq6hpGVqQ7PvKsAzFCa65ynpwLPsbNhdhVWwLbW4CX
Wallet password: 
Another step is needed
MultisigxV2Rn1WDXGJ2QdU5bp4u5fJm2HvdayVZUT8FZ3ZdhN9oHHSDfLPk6cfdymBtjiRr4x7y37HiSXDyFAwGts2FeucAmUdDVLUdUzXSKRtXgA5pc93QyfoU2z3EgEVvgAZUt4EruNTkCasP5GF5usueWjnP3PLpoXZDBcZSuMqZ8yaKLefJwyffUTbk8SDSTkngGnRA7vwRyNRUm9geWVA4ThZphQG3FAfCQ52w
Send this multisig info to all other participants, then use exchange_multisig_keys <info1> [<info2>...] with others' multisig info
[wallet 4Avk37 (out of sync)]: exchange_multisig_keys MultisigxV2Rn1WDXGJ2QdU5bp4u5fJm2HvdayVZUT8FZ3ZdhN9oHHSDfLPk6cfdymBtjiRr4x7y37HiSXDyFAwGts2FeucAmUdDVLUdSgYYF9EpaT84314gGcrEFvxVogMWbRYqdcyUfSursd8PAMEKQCZWAiUyKaGDEPVJHJ6XNpLapQ6ZdFPr7nsTV1LvKNKrXrJ2VEo82Yx2ErF5uPX4fL8MVpbj68SPkc2TsCZx MultisigxV2Rn1WDXGJ2QdU5bp4u5fJm2HvdayVZUT8FZ3ZdhN9oHHSDfLPk6cfdymBtjiRr4x7y37HiSXDyFAwGts2FeucAmUdDVLUeUaBDxdSZSkUTMKMcZ5LH9AU7zSKV67aBDXpn1JmibapiqPVQdFyHMibEpRciKsdZg8kEQ3hkpWJvY1tDbXZhFS6kxtS7v8vLFFtYQRaeAN7atbc1UXzgoTJzX5q3VbEV2Kj2
Wallet password: 
Multisig wallet has been successfully created. Current wallet type: 2/3
Multisig address: 4Avk37SNhMH6KuQV9K8fpdYLqbcjz8Zez5CdV4mvsuN2hALrgwJUikvGvtjtsHU5rNZGo1DKPrEucMwfoHZw3ChhDkWr8E4
[wallet 4Avk37]: 
~~~

You will note that at the end of the process, all participants are manipulating the same wallet with the same base address.

**Be advised: there is no undo in this process, any mistyped address or signature will result in an irrecoverable state and you will have to start over. Once all the wallets are properly setup, each participant should save the seed in a safe place. Do note that multisig wallet seeds are not the usual wordlist**

~~~
[wallet 4Avk37]: seed
Wallet password: 

NOTE: the following string can be used to recover access to your wallet. Write them down and store them somewhere safe and secure. Please do not store them in your email or on file storage services outside of your immediate control.

0200000003000[snip]
~~~

### Provisionning

![](wallet_funding.png)

Now the multisig wallet has been created we will need to add funds. 

But how and how much?

One must consider the risks for all parties involved.

![](funding_retrieval.png)

#### The Arbitrator

![](bad_arbitrator.png)

The arbitrator carries the least personal risk. **I recommend they add to the wallet an amount equal to half their fee as an incentive:**

- That way they will have something to lose in case they just go incommunicado instead of just not receiving their fee should the deal go through anyway
- They have a personal stake in the deal being resolved amicably, one way or the other
- This also weeds out low-effort or unworthy arbitrators: to even qualify for brokering significant deals you must have resources as well as status in your community

#### Bob (purchasing a service)
Bob being the outsider, here to purchase a service, they carry the most risk of being ripped off. They are the one putting the most money down. As such nothing beyond the negociated price
and half the arbitrator's fee is expected from them


#### Charlie (providing the service)
Charlie carries the least risk after the arbitrator, in the current setup they have no incentive not to renege or disappear out of laziness beyond the risk to their status and reputation. In order to lower
the risk of them disappearing on the buyer and arbitrator I advise having them deposit a small (5% to 10% stake of the price) along with their half of the arbitrator's fee


**As a matter of best practices I recommend each participant creates a subaddress and uses it to fund it. They can do so autonomously:**

~~~
[wallet 4Avk37 (out of sync)]: address new deposit
1  83U8D5b7KBzF7wX74RsoYq9Jtz8gkm2HkMBvqM6NEpDRVLEt36rms5yBrLRyoo38D7SMRika9g6zfRf12YhkKBNh5ht4o2A  deposit 
~~~

And then each can transfer the funds to the shared wallet

### Recap and example


Charlie wishes to purchase a poem from Bob. They agree on a price of 1 XMR. As they do not know each other they also agree to have Alice, an expert poetess and one of the leader of their comunity act as arbitrator for a 5% fee.
Furthermore, they agree that given the amount and track record, a 5% stake on Charlie's side is enough.

After reviewing the discussion and speaking to both Bob and Charlie, Alice decides the deal is fair and agrees to arbitrate it. Together they create a shared 2/3 wallet and fund it the following way:

- Alice adds a stake of 0.025XMR (half their fee as a stake)
- Charlie adds 1.025 XMR (price + half Alice's fee)
- Bob adds 0.075XMR XMR (personal stake of 0.05 + half Alice's fee)

They agree on the following:
- Should alice disappear
  - her stake will be forfeit along with her fee, to be shared between Bob and Charlie
- Should Bob disappear
  - His stake will be forfeit to Charlie
  - Alice will receive her fee (0.05XMR) and get her stake back (0.025XMR)
- Should Charlie disappear
  - Her stake (price) will be forfeit to Bob
  - Alice will receive her fee and her stake back


#### Remaining risks
Now, Bob, as an outsider still runs the risk of collusion between Alice and Charlie. If this were to happen and he were to call them out on a public forum it would be easy for Alice (a respected community figure) and Bob to
simply call him a liar and a fraud. To prevent this, all of them will sign a contract of the following form:

~~~
As agreed on 2025-10-05

Bob will purchase 1 (one) poem from Charlie for 1 XMR and pay for half the arbitration fee (0.025XMR) for a total of 1.025XMR
This amounts will be paid to the following address:
83U8D5b7KBzF7wX74RsoYq9Jtz8gkm2HkMBvqM6NEpDRVLEt36rms5yBrLRyoo38D7SMRika9g6zfRf12YhkKBNh5ht4o2A

Alice will arbitrate the deal for a fee of 0.05XMR with a personal stake of 0.025 XMR.
This amount will be paid to the following address: 
8AMAHZ3FQFLeNpM9fudKCa9qyEc2YS6FNdzVJ6TX5g4KWeGHcrYgbFqbb5B7AMrCHcTcwe1KNGmvsh217yJ8u4FNTo1a2gY

Charlie will stake 0.05 XMR as agreed and will pay for half of Alice fee (0.025XMR) for a total of 0.075 XMR
This amount will be paid to the following address:
8AMAHZ3FQFLeNpM9fudKCa9qyEc2YS6FNdzVJ6TX5g4KWeGHcrYgbFqbb5B7AMrCHcTcwe1KNGmvsh217yJ8u4FNTo1a2gY


Charlie commits to delivering the poem by 2026-01-01 00:00:00 UTC. Should they fail to do so,
Alice will collect her fee and Bob will be refunded.

Alice commits to facilitating the deal and resolving any and all disputes, should they fail to do so,
their stake will be forfeit to Bob and Charlie, and their fee refunded.

Bob and Charlie commit to accepting Alice's arbitration in all matters pertaining to this deal, within the bound
of this contract.

Upon successful completion of this trade:

Alice wwill receive their fee of 0.05 XMR along with their stake of 0.025XMR for a total of 0.025XMR
This amount will be paid to the following address:
83U8D5b7KBzF7wX74RsoYq9Jtz8gkm2HkMBvqM6NEpDRVLEt36rms5yBrLRyoo38D7SMRika9g6zfRf12YhkKBNh5ht4o2A

Bob will receive 1 poem, transfered over simpleX.

Charlie will receive a payment of 1XMR along with their stake of 0.05 XMR for a total of 1.05XMR, minus the transaction fees.
This amount will be paid to the following address:
89tMkMVuGujZq4eLBJiikeQgj51ih8cxpDDhLGQTQsSafPbgytNvaoXT5Lc2X1Nd1uEq1AXTg6VBwPWaZsqezhcyUSL76aB


latest monero block at the time of writing: b76a2a4b4c41e14320b9ab87ccae13f013650436f6ed3670f26e99bb3207e891

As agreed, so shall it be.
~~~


This is done easily using gnupg:

~~~
[user@devnode:~]$ vi contract
[user@devnode:~]$ gpg --detach-sign contract
[user@devnode:~]$ ls
contract contract.sig
[user@devnode:~]$ sha256sum contract.sig
02800572f703bf44d4dd33dfa4e9a2a85da952b9fdbeb43157f5da94fb7ddf58  contract.sig
~~~

This contract will be signed with each participant's PGP key, signature as separate files, **all signatures distributed to the other participants**

Then Alice could publish in her community a message saying she is arbitrating a deal, and add the sha256 hashes of all three signatures. Bob and Charlie can do the same on a pastebin service. They can also keep this information
for themselves.


The resulting message could look like this:

~~~
I, Alice, have been chosen as arbitrator for a deal. The bargain has been made:
ea5731b1184141f17a0c3eb5d8cb39557a26af4b5aa09cc1d6f65cf1d3288dd9
00e71d9e261aaa18dcccbf11488fe5ad9f7f3e614b38b0cd443255d17590b6f8
78e5620423cbfb79f9d5f60a4f9ad8f720c9d857bf9104a8b03343faeb6e02d2
~~~


If Alice and Charlie decide to collude, Bob now has all the required proof to show indisputably to Alice's community as well as the rest of the world that Alice and Charlie are dishonest, unreliable actors
and should not be traded with, they only need to produce a copy of the contract as well as their signature. Even without posting the hashes beforehand (which mostly serves as showing Alice's good faith and
involvement), anyone with knowledge of Alice or Bob's public key can then verify the signature:

~~~
[user@devnode:~]$ gpg --verify contract.sig 
gpg: assuming signed data in 'contract'
gpg: Signature made dim. 05 oct. 2025 14:14:51 CEST
gpg:                using EDDSA key [snip]
gpg: Good signature from [snip] [ultimate]
~~~

If so challenged, Alice and Charlie can make their own case and produce
the required monero payment proofs along with signed conversation logs. 

#### Other outcomes

If Charlie produces a poem that doesn't completely satisfies Bob, then Alice will work with them both to reach a resolution. If a resolution is agreed to, it will be written and signed with their PGP keys.
This could be an updated contract:

~~~
2025-12-15
Upon seeing the result, Alice agrees that the poem is not completely satisfactory. They
ruled that only 30% of the price will be paid to Charlie, the rest will be refunded
All other payment dispositions remain

Latest monero block hash: c1652a8fad3fbf6d38fbfd4af1cd0d6398382e4287877c7bb0eb75ef2c2afb07
~~~



## Creating a payment transaction

![](payment_flow.png)

Multisig wallets require several participants to sign the transaction, which makes it slightly more complex to use.

This is done in two steps:

1. The sharing of partial key-images - At minimum, the spender needs to get a partial key image from the people (1 or more) who will sign the transaction with him later. They need to export a file and share it with the future spender, who then imports the file to their wallet.
2. creating, signing & submitting the transaction - A transfer is created, written to file, and then this file needs to be signed by the co-signers, before it can lastly be submitted to the network.

### Recording and traceability
It is recommended to create one transaction per payment. Once a payment has been made, I recommend saving the following pieces of information that could allow anyone to verify it:

- transaction ID
- transaction key
- destination address

Here, show_transfers gave us the transaction ID (9036d3cacadb492621ef6b339d20da71d10a79544e8ccca19295ce0059441bf7) and we also have the destination address: 82htErcFXbSigdhK9tbfMoJngZmjGtDUacQxxUFwSvtb9MY8uPSuYSGAuN1UvsXiXJ8BR9BVUUhgFBYDPvhrSmVkGneb91j.

To obtain the transaction key:

~~~
[wallet 4Avk37]: get_tx_key 9036d3cacadb492621ef6b339d20da71d10a79544e8ccca19295ce0059441bf7
Wallet password: 
Tx key: ca3ac2f09aad0a3c8ffcb3baa4b819401a1fe47ef529a5f2021716cb6264c305
~~~

For each payment, participants should save this information, in case of a dispute it allows them to prove without the shadow of a doubt which payments were made and to whom. Alternatively, you can also keep the wallets around after you have emptied them.


### Fees
When paying, the fees add up: every payment until the last one is actually slightly above the amount transferred because of the fees incurred by the network. In order for the deal to be fair **the order of transactions matters** as the last payment made will also cover all the transaction fees of the previous ones.

- Alice will always be the first to be paid to avoid incurring unjust fees given their role
- Bob or Charlie, as primary parties will pay the outgoing fees depending on the final outcome

### Demo setup

For the following demo I have funded a small sum to the demonstration wallet, the same principles apply whatever the amount one wishes to transfer. As I used the same node
for broadcasting the transaction and updating the multisig wallet I can see the output immediately:

~~~
[wallet 4Avk37]: refresh
Starting refresh...
Enter password (output found in pool): 
Refresh done, blocks received: 0                                
Currently selected account: [0] Primary account
Tag: (No tag assigned)
Balance: 0.003518152330, unlocked balance: 0.000000000000
~~~


After a while (10 blocks), the output becomes spendable:

~~~
[wallet 4Avk37 (out of sync)]: refresh
Starting refresh...
Enter password (output received): 
Height 3514879, txid <d2382570f0d032283041e09b75194e5dc43931e8b1803b81fb4d16a5393a0af0>, 0.003518152330, idx 0/1
Refresh done, blocks received: 10                               
Currently selected account: [0] Primary account
Tag: (No tag assigned)
Balance: 0.003518152330, unlocked balance: 0.003518152330 (Some owned outputs have partial key images - import_multisig_info needed)
~~~

The `import_multising_info` messages indicates that we can't spend the balance by ourselves: we need other key images.

### Trade goes smoothly

![](all_well.png)

If everything goes well:
- Alice gets their fee and deposit back
- Bob gets paid for their service and their stake back

#### Paying Alice (0.075XMR)

Bob is satisfied by the result of the deal, they create a partial key image and send it to Charlie:

~~~
[wallet 4Avk37]: export_multisig_info bobkey
Wallet password: 
Multisig info exported to bobkey
~~~

Charlie will now need to import it:

~~~
[wallet 4Avk37]: import_multisig_info bobkey
Wallet password: 
Height 3514879, txid <d2382570f0d032283041e09b75194e5dc43931e8b1803b81fb4d16a5393a0af0>, 0.075, idx 0/1
Multisig info imported. Number of outputs updated: 1
~~~

Charlie can now create a transaction to Alice:

~~~
[wallet 4Avk37]: transfer 82htErcFXbSigdhK9tbfMoJngZmjGtDUacQxxUFwSvtb9MY8uPSuYSGAuN1UvsXiXJ8BR9BVUUhgFBYDPvhrSmVkGneb91j 0.075
Wallet password: 

Transaction 1/1:
Spending from address index 1
Sending 0.075.  The transaction fee is 0.000030760000

Is this okay?  (Y/Yes/N/No): Y
Unsigned transaction(s) successfully written to file: multisig_monero_tx
~~~

Bob receives the file from Charlie and signs it.

~~~
[wallet 4Avk37]: sign_multisig  multisig_monero_tx
Wallet password: 
Loaded 1 transactions, for 0.075, fee 0.000030760000, sending 0.07503076 to 82htErcFXbSigdhK9tbfMoJngZmjGtDUacQxxUFwSvtb9MY8uPSuYSGAuN1UvsXiXJ8BR9BVUUhgFBYDPvhrSmVkGneb91j, 0.000414840330 change to 4Avk37RuxDWEPz17ZNdG9nKtnpXgC5ip5fk1eyw27CQ871GfLdA4EjvA2DRe61syBvdZnEBK5gBbuDEU2brrEJfQ8rRdm1B, with min ring size 16, dummy encrypted payment ID. Is this okay?  (Y/Yes/N/No): Y
Transaction successfully signed to file multisig_monero_tx, txid 9036d3cacadb492621ef6b339d20da71d10a79544e8ccca19295ce0059441bf7
It may be relayed to the network with submit_multisig
~~~

Now that Bob has signed the transaction file, it can be submitted to the network:

~~~
[wallet 4Avk37]: submit_multisig multisig_monero_tx
Wallet password: 
Loaded 1 transactions, for 0.075, fee 0.000030760000, sending 0.07503076 to 82htErcFXbSigdhK9tbfMoJngZmjGtDUacQxxUFwSvtb9MY8uPSuYSGAuN1UvsXiXJ8BR9BVUUhgFBYDPvhrSmVkGneb91j, 0.000414840330 change to 4Avk37RuxDWEPz17ZNdG9nKtnpXgC5ip5fk1eyw27CQ871GfLdA4EjvA2DRe61syBvdZnEBK5gBbuDEU2brrEJfQ8rRdm1B, with min ring size 16, dummy encrypted payment ID. Is this okay?  (Y/Yes/N/No): Y
Transaction successfully submitted, transaction <9036d3cacadb492621ef6b339d20da71d10a79544e8ccca19295ce0059441bf7>
You can check its status by using the `show_transfers` command.
[wallet 4Avk37]: show_transfers
 3514879     in unlocked       2025-10-05 09:58:54       0.003518152330 d2382570f0d032283041e09b75194e5dc43931e8b1803b81fb4d16a5393a0af0 0000000000000000 0.000000000000 84Bvoh:0.003518152330 1 - 
 pending    out        -       2025-10-05 10:40:43       0.003072552000 9036d3cacadb492621ef6b339d20da71d10a79544e8ccca19295ce0059441bf7 0000000000000000 0.000030760000 82htErcFXbSigdhK9tbfMoJngZmjGtDUacQxxUFwSvtb9MY8uPSuYSGAuN1UvsXiXJ8BR9BVUUhgFBYDPvhrSmVkGneb91j:0.003072552000 1 - 
~~~

#### Paying Bob (1.05XMR)

Charlie now creates a transaction to pay Bob
~~~
[wallet 4Avk37]: import_multisig_info bobkey
Wallet password: 
Height 3514879, txid <d2382570f0d032283041e09b75194e5dc43931e8b1803b81fb4d16a5393a0af0>, 0.003518152330, idx 0/1
Height 3514904, txid <9036d3cacadb492621ef6b339d20da71d10a79544e8ccca19295ce0059441bf7>, 0.000414840330, idx 0/0
Height 3514904, txid <9036d3cacadb492621ef6b339d20da71d10a79544e8ccca19295ce0059441bf7>, spent 0.003518152330, idx 0/1
Multisig info imported. Number of outputs updated: 2
[wallet 4Avk37]: sweep_all 82htErcFXbSigdhK9tbfMoJngZmjGtDUacQxxUFwSvtb9MY8uPSuYSGAuN1UvsXiXJ8BR9BVUUhgFBYDPvhrSmVkGneb91j
Wallet password: 

Transaction 1/1:
Spending from address index 0

Sweeping 1.05 for a total fee of 0.000030700000.  Is this okay?  (Y/Yes/N/No): Y
Unsigned transaction(s) successfully written to file: multisig_monero_tx
~~~

He sends back to Bob the transaction created, signed with his own key, who then signs it and submits it:

~~~
[wallet 4Avk37 (out of sync)]: sign_multisig multisig_monero_tx
Wallet password: 
Loaded 1 transactions, for 1.05, fee 0.000030700000, sending 1.05 to 82htErcFXbSigdhK9tbfMoJngZmjGtDUacQxxUFwSvtb9MY8uPSuYSGAuN1UvsXiXJ8BR9BVUUhgFBYDPvhrSmVkGneb91j, 1 dummy output(s), no change, with min ring size 16, dummy encrypted payment ID. Is this okay?  (Y/Yes/N/No): Y
Transaction successfully signed to file multisig_monero_tx, txid a0d697239ecbaeb016b82403f4ca1737fb69c188d06e225d34859c1be6783663
It may be relayed to the network with submit_multisig
[wallet 4Avk37]: submit_multisig multisig_monero_tx
Wallet password: 
Loaded 1 transactions, for 1.05, fee 0.000030700000, sending 1.05 to 82htErcFXbSigdhK9tbfMoJngZmjGtDUacQxxUFwSvtb9MY8uPSuYSGAuN1UvsXiXJ8BR9BVUUhgFBYDPvhrSmVkGneb91j, 1 dummy output(s), no change, with min ring size 16, dummy encrypted payment ID. Is this okay?  (Y/Yes/N/No): Y
Transaction successfully submitted, transaction <a0d697239ecbaeb016b82403f4ca1737fb69c188d06e225d34859c1be6783663>
You can check its status by using the `show_transfers` command.
~~~


### Bob fails to deliver

![](bob_scams.png)

Now, in the case Bob failed tries to scam and didn't deliver or deliver an out of spec result

- Alice gets their fee and deposit back
- Charlie gets the price they deposited and Bob's stake
- Both Alice and Charlie will now report Bob in their respective communities as an untrustworthy partner who should be shunned

#### Paying Alice (0.075XMR)

Charlie creates a partial key image and send it to Alice:

~~~
[wallet 4Avk37]: export_multisig_info charliekey
Wallet password: 
Multisig info exported to charliekey
~~~

Alice will now need to import it:

~~~
[wallet 4Avk37]: import_multisig_info charliekey
Wallet password: 
Height 3514879, txid <d2382570f0d032283041e09b75194e5dc43931e8b1803b81fb4d16a5393a0af0>, 0.003518152330, idx 0/1
Multisig info imported. Number of outputs updated: 1
~~~

Alice can now create a transaction to pay herself:

~~~
[wallet 4Avk37]: transfer 82htErcFXbSigdhK9tbfMoJngZmjGtDUacQxxUFwSvtb9MY8uPSuYSGAuN1UvsXiXJ8BR9BVUUhgFBYDPvhrSmVkGneb91j 0.075
Wallet password: 

Transaction 1/1:
Spending from address index 1
Sending 0.075.  The transaction fee is 0.000030760000

Is this okay?  (Y/Yes/N/No): Y
Unsigned transaction(s) successfully written to file: multisig_monero_tx
~~~

Charlie receives the file from Alice and signs it.

~~~
[wallet 4Avk37]: sign_multisig  multisig_monero_tx
Wallet password: 
Loaded 1 transactions, for 0.075, fee 0.000030760000, sending 0.075 to 82htErcFXbSigdhK9tbfMoJngZmjGtDUacQxxUFwSvtb9MY8uPSuYSGAuN1UvsXiXJ8BR9BVUUhgFBYDPvhrSmVkGneb91j, 0.000414840330 change to 4Avk37RuxDWEPz17ZNdG9nKtnpXgC5ip5fk1eyw27CQ871GfLdA4EjvA2DRe61syBvdZnEBK5gBbuDEU2brrEJfQ8rRdm1B, with min ring size 16, dummy encrypted payment ID. Is this okay?  (Y/Yes/N/No): Y
Transaction successfully signed to file multisig_monero_tx, txid 9036d3cacadb492621ef6b339d20da71d10a79544e8ccca19295ce0059441bf7
It may be relayed to the network with submit_multisig
~~~

Now that Charlie has signed the transaction file, it can be submitted to the network:

~~~
[wallet 4Avk37]: submit_multisig multisig_monero_tx
Wallet password: 
Loaded 1 transactions, for 0.075, fee 0.000030760000, sending 0.075 to 82htErcFXbSigdhK9tbfMoJngZmjGtDUacQxxUFwSvtb9MY8uPSuYSGAuN1UvsXiXJ8BR9BVUUhgFBYDPvhrSmVkGneb91j, 0.000414840330 change to 4Avk37RuxDWEPz17ZNdG9nKtnpXgC5ip5fk1eyw27CQ871GfLdA4EjvA2DRe61syBvdZnEBK5gBbuDEU2brrEJfQ8rRdm1B, with min ring size 16, dummy encrypted payment ID. Is this okay?  (Y/Yes/N/No): Y
Transaction successfully submitted, transaction <9036d3cacadb492621ef6b339d20da71d10a79544e8ccca19295ce0059441bf7>
You can check its status by using the `show_transfers` command.
[wallet 4Avk37]: show_transfers
 3514879     in unlocked       2025-10-05 09:58:54       0.003518152330 d2382570f0d032283041e09b75194e5dc43931e8b1803b81fb4d16a5393a0af0 0000000000000000 0.000000000000 84Bvoh:0.003518152330 1 - 
 pending    out        -       2025-10-05 10:40:43       0.003072552000 9036d3cacadb492621ef6b339d20da71d10a79544e8ccca19295ce0059441bf7 0000000000000000 0.000030760000 82htErcFXbSigdhK9tbfMoJngZmjGtDUacQxxUFwSvtb9MY8uPSuYSGAuN1UvsXiXJ8BR9BVUUhgFBYDPvhrSmVkGneb91j:0.003072552000 1 - 
~~~

#### Refunding Charlie (1.05XMR)

Once Alice has beeen paid and her stake refunded, Charlie can receive the final payment with the remaining amount;

Alice creates a preimage for Charlie

~~~
[wallet 4Avk37]: export_multisig_info alicekey
Wallet password: 
Multisig info exported to alicekey
~~~

Charlie uses Alice's preimage to create the final transaction

~~~
[wallet 4Avk37]: import_multisig_info alicekey
Wallet password: 
Height 3514879, txid <d2382570f0d032283041e09b75194e5dc43931e8b1803b81fb4d16a5393a0af0>, 0.003518152330, idx 0/1
Height 3514904, txid <9036d3cacadb492621ef6b339d20da71d10a79544e8ccca19295ce0059441bf7>, 0.000414840330, idx 0/0
Height 3514904, txid <9036d3cacadb492621ef6b339d20da71d10a79544e8ccca19295ce0059441bf7>, spent 0.003518152330, idx 0/1
Multisig info imported. Number of outputs updated: 2
[wallet 4Avk37]: sweep_all 82htErcFXbSigdhK9tbfMoJngZmjGtDUacQxxUFwSvtb9MY8uPSuYSGAuN1UvsXiXJ8BR9BVUUhgFBYDPvhrSmVkGneb91j
Wallet password: 

Transaction 1/1:
Spending from address index 0

Sweeping 1.05 for a total fee of 0.000030700000.  Is this okay?  (Y/Yes/N/No): Y
Unsigned transaction(s) successfully written to file: multisig_monero_tx
~~~

He sends back to Alice the transaction created, signed with his own key, who then signs it and submits it:

~~~
[wallet 4Avk37 (out of sync)]: sign_multisig multisig_monero_tx
Wallet password: 
Loaded 1 transactions, for 1.05, fee 0.000030700000, sending 1.05 to 82htErcFXbSigdhK9tbfMoJngZmjGtDUacQxxUFwSvtb9MY8uPSuYSGAuN1UvsXiXJ8BR9BVUUhgFBYDPvhrSmVkGneb91j, 1 dummy output(s), no change, with min ring size 16, dummy encrypted payment ID. Is this okay?  (Y/Yes/N/No): Y
Transaction successfully signed to file multisig_monero_tx, txid a0d697239ecbaeb016b82403f4ca1737fb69c188d06e225d34859c1be6783663
It may be relayed to the network with submit_multisig
[wallet 4Avk37]: submit_multisig multisig_monero_tx
Wallet password: 
Loaded 1 transactions, for 0.000414840330, fee 0.000030700000, sending 0.000384140330 to 82htErcFXbSigdhK9tbfMoJngZmjGtDUacQxxUFwSvtb9MY8uPSuYSGAuN1UvsXiXJ8BR9BVUUhgFBYDPvhrSmVkGneb91j, 1 dummy output(s), no change, with min ring size 16, dummy encrypted payment ID. Is this okay?  (Y/Yes/N/No): Y
Transaction successfully submitted, transaction <a0d697239ecbaeb016b82403f4ca1737fb69c188d06e225d34859c1be6783663>
You can check its status by using the `show_transfers` command.
~~~


### Charlie tries to scam

![](charlie_scams.png)

If Charlie decides to dispute in bad faith the quality of Bob's work in order to obtain a reduced price or get their funds back, Alice will arbitrate in favor of Bob, leading to the following transactions:
- Alice gets their fee and deposit back
- Bob gets the price Charlie deposited and their stake back
- Both Alice and Bob will now report Charlie in their respective communities as an untrustworthy partner who should be shunned

#### Paying Alice (0.075XMR)

Bob creates a partial key image and sends it to Alice:

~~~
[wallet 4Avk37]: export_multisig_info bobkey
Wallet password: 
Multisig info exported to bobkey
~~~

Alice will now need to import it:

~~~
[wallet 4Avk37]: import_multisig_info bobkey
Wallet password: 
Height 3514879, txid <d2382570f0d032283041e09b75194e5dc43931e8b1803b81fb4d16a5393a0af0>, 0.003518152330, idx 0/1
Multisig info imported. Number of outputs updated: 1
~~~

Alice can now create a transaction to pay herself:

~~~
[wallet 4Avk37]: transfer 82htErcFXbSigdhK9tbfMoJngZmjGtDUacQxxUFwSvtb9MY8uPSuYSGAuN1UvsXiXJ8BR9BVUUhgFBYDPvhrSmVkGneb91j 0.075
Wallet password: 

Transaction 1/1:
Spending from address index 1
Sending 0.075.  The transaction fee is 0.000030760000

Is this okay?  (Y/Yes/N/No): Y
Unsigned transaction(s) successfully written to file: multisig_monero_tx
~~~

Bob receives the file from Alice and signs it.

~~~
[wallet 4Avk37]: sign_multisig  multisig_monero_tx
Wallet password: 
Loaded 1 transactions, for 0.075, fee 0.000030760000, sending 0.075 to 82htErcFXbSigdhK9tbfMoJngZmjGtDUacQxxUFwSvtb9MY8uPSuYSGAuN1UvsXiXJ8BR9BVUUhgFBYDPvhrSmVkGneb91j, 0.000414840330 change to 4Avk37RuxDWEPz17ZNdG9nKtnpXgC5ip5fk1eyw27CQ871GfLdA4EjvA2DRe61syBvdZnEBK5gBbuDEU2brrEJfQ8rRdm1B, with min ring size 16, dummy encrypted payment ID. Is this okay?  (Y/Yes/N/No): Y
Transaction successfully signed to file multisig_monero_tx, txid 9036d3cacadb492621ef6b339d20da71d10a79544e8ccca19295ce0059441bf7
It may be relayed to the network with submit_multisig
~~~

Now that Bob has signed the transaction file, it can be submitted to the network:

~~~
[wallet 4Avk37]: submit_multisig multisig_monero_tx
Wallet password: 
Loaded 1 transactions, for 0.075, fee 0.000030760000, sending 0.075 to 82htErcFXbSigdhK9tbfMoJngZmjGtDUacQxxUFwSvtb9MY8uPSuYSGAuN1UvsXiXJ8BR9BVUUhgFBYDPvhrSmVkGneb91j, 0.000414840330 change to 4Avk37RuxDWEPz17ZNdG9nKtnpXgC5ip5fk1eyw27CQ871GfLdA4EjvA2DRe61syBvdZnEBK5gBbuDEU2brrEJfQ8rRdm1B, with min ring size 16, dummy encrypted payment ID. Is this okay?  (Y/Yes/N/No): Y
Transaction successfully submitted, transaction <9036d3cacadb492621ef6b339d20da71d10a79544e8ccca19295ce0059441bf7>
You can check its status by using the `show_transfers` command.
[wallet 4Avk37]: show_transfers
 3514879     in unlocked       2025-10-05 09:58:54       0.003518152330 d2382570f0d032283041e09b75194e5dc43931e8b1803b81fb4d16a5393a0af0 0000000000000000 0.000000000000 84Bvoh:0.003518152330 1 - 
 pending    out        -       2025-10-05 10:40:43       0.003072552000 9036d3cacadb492621ef6b339d20da71d10a79544e8ccca19295ce0059441bf7 0000000000000000 0.000030760000 82htErcFXbSigdhK9tbfMoJngZmjGtDUacQxxUFwSvtb9MY8uPSuYSGAuN1UvsXiXJ8BR9BVUUhgFBYDPvhrSmVkGneb91j:0.003072552000 1 - 
~~~

#### Paying Bob (1.05XMR)

Once Alice has beeen paid and her stake refunded, Bob can receive the final payment with the remaining amount;

Alice exports a preimage for Bob to create the final transaction

~~~
[wallet 4Avk37]: export_multisig_info alicekey
Wallet password: 
Multisig info exported to alicekey
~~~

Bob import's Alice's preimage and creates the final transaction to pay himself.

~~~
[wallet 4Avk37]: import_multisig_info alicekey
Wallet password: 
Height 3514879, txid <d2382570f0d032283041e09b75194e5dc43931e8b1803b81fb4d16a5393a0af0>, 0.003518152330, idx 0/1
Height 3514904, txid <9036d3cacadb492621ef6b339d20da71d10a79544e8ccca19295ce0059441bf7>, 0.000414840330, idx 0/0
Height 3514904, txid <9036d3cacadb492621ef6b339d20da71d10a79544e8ccca19295ce0059441bf7>, spent 0.003518152330, idx 0/1
Multisig info imported. Number of outputs updated: 2
[wallet 4Avk37]: sweep_all 82htErcFXbSigdhK9tbfMoJngZmjGtDUacQxxUFwSvtb9MY8uPSuYSGAuN1UvsXiXJ8BR9BVUUhgFBYDPvhrSmVkGneb91j
Wallet password: 

Transaction 1/1:
Spending from address index 0

Sweeping 1.05 for a total fee of 0.000030700000.  Is this okay?  (Y/Yes/N/No): Y
Unsigned transaction(s) successfully written to file: multisig_monero_tx
~~~

He sends back to Alice the transaction created, signed with his own key, who then signs it and submits it:

~~~
[wallet 4Avk37 (out of sync)]: sign_multisig multisig_monero_tx
Wallet password: 
Loaded 1 transactions, for 1.05, fee 0.000030700000, sending 1.05 to 82htErcFXbSigdhK9tbfMoJngZmjGtDUacQxxUFwSvtb9MY8uPSuYSGAuN1UvsXiXJ8BR9BVUUhgFBYDPvhrSmVkGneb91j, 1 dummy output(s), no change, with min ring size 16, dummy encrypted payment ID. Is this okay?  (Y/Yes/N/No): Y
Transaction successfully signed to file multisig_monero_tx, txid a0d697239ecbaeb016b82403f4ca1737fb69c188d06e225d34859c1be6783663
It may be relayed to the network with submit_multisig
[wallet 4Avk37]: submit_multisig multisig_monero_tx
Wallet password: 
Loaded 1 transactions, for 0.000414840330, fee 0.000030700000, sending 0.000384140330 to 82htErcFXbSigdhK9tbfMoJngZmjGtDUacQxxUFwSvtb9MY8uPSuYSGAuN1UvsXiXJ8BR9BVUUhgFBYDPvhrSmVkGneb91j, 1 dummy output(s), no change, with min ring size 16, dummy encrypted payment ID. Is this okay?  (Y/Yes/N/No): Y
Transaction successfully submitted, transaction <a0d697239ecbaeb016b82403f4ca1737fb69c188d06e225d34859c1be6783663>
You can check its status by using the `show_transfers` command.
~~~

## Conclusion

Here we have laid out a secure way to trade with other people without needing a centralized trust or enforcer. Such trading is never done in a vacuum. Humans live in communities and produce wealth through free, voluntary interactions. To trade
and thrive as a community we must show integrity and fairness in our dealings with each other. This also means that we must ruthlessly ostracize the bad actors, thieves and scammers.

Modern cryptography through Tor, PGP, Monero and SimpleX allows us to trade anonymously and securely, but in the end, any trade remains an encounter betweeen two humans. It is your responsibility to do your due diligence
and adopt whatever measures you prefer before trading with someone else. The protocol described above **is** complex but also offers the **highest level of safety and security**.

If you don't know someone, if they aren't part of any community, be wary. Everyone must start somewhere, so trade and build trust, but start with small amounts that you are willing to lose as you vet that person.


**We need no state, we need no government. We are builders, not looters.**

**Through our skills we earn respect, through our trades we earn trust.**

**Those are the foundations upon which our society will thrive and, one day, overcome.**
