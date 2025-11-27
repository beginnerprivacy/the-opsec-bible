---
author: XMRonly
date: 2025-04-10
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/179"
xmr: 8AHNGepbz9844kfCqR4aVTCSyJvEKZhtxdyz6Qn8yhP2gLj5u541BqwXR7VTwYwMqbGc8ZGNj3RWMNQuboxnb1X4HobhSv3
tags:
  - Serverside Anonymity
---
# How to Verify One's Identity While Maintaining Anonymity Using PGP Canaries

```
TLDR: thanks to PGP-signed canaries, you can verify one's identity even if anonymity is present.
```

![](0.png)



## **Introduction**

  
  ![](../context/anon_remote.png)


When dealing with strangers on the internet you may not always want to reveal your real identity. Practising good OPSEC and maintaining your online anonymity can therefore be paramount in certain situations. But in an arena where anyone can be anonymous, how can you be sure people are truly who they claim to be and that you're talking to the same person across different situations? That is where Pretty Good Privacy (PGP), an encryption program that provides cryptographic privacy and authentication comes in to verify one's identity without actually revealing it. In this tutorial, we will build upon the PGP concepts [previously covered](../pgp/index.md), and expand these concepts to verifying not just messages, but entire personas and even control over infrastructure in hostile environments. 

## **Verifying Identity**

Bob has been busy working on his onion site. After putting the finishing touches on it, he has started trying to get the word out. Bob has been messaging a few people using various identities on SimpleX, and it's finally starting to pick up traction. However, when Alice received a message from Bob, she was a little skeptical. 

![](1.png)

Having learned the basics of PGP from the [previous tutorial](../pgp/index.md), Alice imports Bob's public key from an independent source (his site) then proceeds to verify if indeed Bob is who he says he is. In this case, the signature checks out and Alice can see the message contents confirming the onion site link. 

![](2.png)

Having confirmed Bob is who he says he is, Alice goes on to peruse Bob's [onion site](http://bob2bujqeou2ws7sb64jksqajrmznobuo7c7uag5cmfo5frb5l2inqid.onion/). 

![](3.png)

What Alice finds turns out to be pretty interesting. She decides to ask Bob for more details. 

![](4.png)

## **The Onion Mirror Guidelines (OMG)**

When starting his onion site, Bob decided to employ the **Onion Mirror Guidelines (OMG)** in order to validate his site and establish its credibility. The OMG Standard was initially defined by dark.fail as a way for admins to show a commitment to user safety by proving ownership of all URLs associated with their site, and by committing to regularly proving control of their PGP key. The full documentation can be found [here](http://darkfailenbsdla5mal2mxn2uz66od5vtzd5qozslagrfzachha3f3id.onion/spec/omg.txt). Let's break it down. 

The OMG Standard outlines 3 crucial pieces of information, written as text files, that must be present on all .onion URLs. 
    
    
    /pgp.txt - Required - HTTP 200 text/plain
      - A list of all PGP public keys allowed to announce your official mirrors.
      - May contain multiple PGP keys.
      - All keys must be ASCII armored.
      - Do not list a key here unless it is trusted to sign official .onion URLs. 
      - Example: http://darkfailllnkf4vf.onion/pgp.txt
    

The first, and perhaps most obvious, piece of information required is the actual PGP key(s) used to verify the site admin's identity. This must be placed at **/pgp.txt** , be ASCII armored, and be designated as official key used to sign .onion URLs. No other keys are allowed. View an example of this on Bob's onion site [here](http://bob2bujqeou2ws7sb64jksqajrmznobuo7c7uag5cmfo5frb5l2inqid.onion/pgp.txt). 
    
    
    /mirrors.txt - Required - HTTP 200 text/plain
      - PGP SIGNED list of all official mirrors of your site. 
      - Mirrors must be signed by a PGP key which is in /pgp.txt hosted at all of your URLs.
      - Any line in this file which begins with “http://“ or “https://“ 
        is an official mirror of your site.
      - Mirrors must all host the same content. No related forums, no link lists. 
        Place forums, other sites in /related.txt instead.
      - All valid mirrors must only contain a scheme and domain name, no
        ports or paths.
      - /pgp.txt and /mirrors.txt must have the same content on all of your URLs.
      - Text which is not intended to be parsed as an official mirror must 
        be commented out with a “#” as the first character on the line.
      - Example: http://darkfailllnkf4vf.onion/mirrors.txt
    

Now that a PGP key has been declared, it's time to actually use it for something. The second piece of information required is a PGP signed list of all mirrors associated with the site. Similar to before, this message must be placed at **/mirrors.txt** , be clearsigned and be designated as official URLs associated with your site. All mirrors must display the same content (hence the term "mirrors") and not include any additional related content (more on that later). View an example of this on Bob's onion site [here](http://bob2bujqeou2ws7sb64jksqajrmznobuo7c7uag5cmfo5frb5l2inqid.onion/mirrors.txt). 
    
    
    /canary.txt - Required - HTTP 200 text/plain
      - PGP SIGNED message MUST be updated every 14 days. 
      - Can be signed by any key specified in /pgp.txt
      - The message must contain the latest Bitcoin block hash and the current 
        date in YYYY-MM-DD format, with string “I am in control of my PGP key.”
        and must also include the string "I will update this canary within 14 days."
      - If you cannot do this you should not be running a darknet market. 
      - Example: http://darkfailllnkf4vf.onion/canary.txt
    

The last, and perhaps most important, piece of information is the PGP signed canary. This canary must be manually updated on a fixed interval in order to prove that the admins are still alive, free and in control of their keys and infrastructure. This canary must be placed at **/canary.txt** , be clearsigned and have the latest ̶B̶i̶t̶c̶o̶i̶n̶  Monero block hash in order to independently and verifiably provide the date at which the canary was generated. View an example of this on Bob's onion site [here](http://bob2bujqeou2ws7sb64jksqajrmznobuo7c7uag5cmfo5frb5l2inqid.onion/canary.txt). 
    
    
    /related.txt - Optional - HTTP 200 text/plain
      - PGP SIGNED list of all .onion sites related to your site. 
      - This is where you list forums, link lists, related services.
      - Follow the same rules as /mirrors.txt 
    

An optional extra piece of information is a link to services adjacent to your main website. Located at **/related.txt** , these can be auxiliary services such as forums, lists, etc. This should be PGP clearsigned the same as the official /mirrors tab. 

## **PGP Canaries**

Now that Bob is familiar with the requirements for PGP Canaries, he sets out to actually write one. Using Nihilist's [script](http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/Datura-Network/src/branch/main/0-Transparency/gen-report.sh) as a starting template, Bob gets to work making a few modifications to suit his individual needs. 

First bob will run **vim gen-canary.sh** to create the script.  
HINT: It's **ESC :wq** to write changes and quit the file. 
    
    
    #!/bin/bash
    
    # obtain the latest monero block height
    height=$(curl -s https://localmonero.co/blocks/api/get_stats | sed -E 's/.*"height":([0-9]+),.*/\1/')
    
    # use the latest monero block height to obtain its hash
    hash=$(curl -s https://localmonero.co/blocks/api/get_block_header/{$height} | sed -E 's/.*"hash":"([^"]+)".*/\1/') 
    
    # custom message
    read -p "Enter custom message (latest news of the month, how things are now, and where we're going):" custom_msg
    
    # populate of all the canary requirements
    ######-----BEGIN PGP SIGNED MESSAGE-----
    echo "I, bob, am alive and free as of $(date --iso-8601), and am in full control of my site and all other services related to my network." >> /tmp/report.txt
    echo "" >> /tmp/report.txt
    echo "The next canary will be updated on $(date -d "+14 days" --iso-8601)." >> /tmp/report.txt
    echo "" >> /tmp/report.txt
    echo "The latest Monero block hash is:" >> /tmp/report.txt
    echo "$hash" >> /tmp/report.txt
    echo "" >> /tmp/report.txt
    echo $custom_msg >> /tmp/report.txt
    echo "" >> /tmp/report.txt
    
    # gpg sign the canary
    gpg -u bob --clearsign /tmp/report.txt 
    cp /tmp/report.txt.asc ./canary.txt
    
    # now upload the canary
    

Running the script using **sh gen-canary.sh** , Bob is able to easily and reproducibly generate a PGP canary for his site. 

![](5.png)

Finally, Bob uploads the newly generated canary to his onion site. 

## **Verifying a PGP Canary**

A nice, neat, official-looking PGP canary should not be taken at face value as Alice knows. She must verify it for herself. 
    
    
    alice@debian:~$ torsocks wget http://bob2bujqeou2ws7sb64jksqajrmznobuo7c7uag5cmfo5frb5l2inqid.onion/canary.txt
    --2025-04-11 19:47:57--  http://bob2bujqeou2ws7sb64jksqajrmznobuo7c7uag5cmfo5frb5l2inqid.onion/canary.txt
    Resolving bob2bujqeou2ws7sb64jksqajrmznobuo7c7uag5cmfo5frb5l2inqid.onion (bob2bujqeou2ws7sb64jksqajrmznobuo7c7uag5cmfo5frb5l2inqid.onion)... 127.42.42.0
    Connecting to bob2bujqeou2ws7sb64jksqajrmznobuo7c7uag5cmfo5frb5l2inqid.onion (bob2bujqeou2ws7sb64jksqajrmznobuo7c7uag5cmfo5frb5l2inqid.onion)|127.42.42.0|:80... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 1204 (1.2K) [text/plain]
    Saving to: \u2018canary.txt\u2019
    
    canary.txt                         100%[================================================================>]   1.18K  --.-KB/s    in 0s      
    
    2025-04-11 19:48:00 (23.6 MB/s) - \u2018canary.txt\u2019 saved [1204/1204]
    
    alice@debian:~$ gpg --verify canary.txt 
    gpg: Signature made Fri 11 Apr 2025 05:50:29 PM EDT
    gpg:                using RSA key 6BE7DAE7C18B68E371ABACFF4207F207857508B6
    gpg:                issuer "bob@bob.com"
    gpg: Good signature from "bob bob " [unknown]
    gpg: WARNING: This key is not certified with a trusted signature!
    gpg:          There is no indication that the signature belongs to the owner.
    Primary key fingerprint: 6BE7 DAE7 C18B 68E3 71AB  ACFF 4207 F207 8575 08B6
    

Just like she verified his message and persona before, Alice now verified Bob's control of his website and infrastructure all without even knowing who Bob is! 

