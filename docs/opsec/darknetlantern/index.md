---
author: nihilist
date: 2025-01-26
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/267"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
tags:
  - Serverside Anonymity
  - Contributing to Anonymity
---
# How to run your own Darknet Lantern for Visibility and Discoverability 
```
TLDR: by running a lantern and joining the webring, you get to contribute to the multi-community effort of listing onion websites.
```
![](1.png)

In this tutorial we're going to first explain why the Darknet Lantern is important in the current Darknet context, we'll cover what it is made of, and then we'll cover how to spin up a Darknet Lantern instance, how to maintain one's list of onion links, and lastly we'll cover how to join the Darknet Webring.



## **Why is the Darknet Lantern Project Important?**

As we have explained [previously](../darknetexploration/index.md), the current Darknet ecosystem is such, that you don't have visibility on every community out there:

![](../darknetexploration/2.png)

I'm sure that most darknet communities out there are isolated from each other, because they don't know that the other communities exist, they didn't go to the right places on the web yet to find out that those other places exist.

![](../darknetexploration/15.png)

So right now you and your community may be one of the 3 here, as Alice you may list some onion links for your own small community, or you may be Charlie, sharing other onion links to your much larger community, and you (and your community) may not even be aware that Bob's community even exist, with their own knowledge of onion links that they discovered.

![](../darknetexploration/16.png)

This is why the Webring formation is crucial here, **to participate in a Webring means that your community is also maintaining a list of those other communities that are participating in the webring, so that they may also benefit from the visibility coming from your audience.** And in the same way you may also benefit from the additional visibility coming from all of the other audiences combined. 

The webring formation is crucial to maintain the decentralisation intact, that is to make sure that ONE webring participant cannot dictate who gets to have visibility, and who doesn't get to have visibility across the entire webring.

![](2.png)

In this case here, Webring participant A may not link to webring participant Z because they have some links that A doesn't tolerate (like porn links for example), but webring participant B may tolerate them and allow the links coming from that instance to be listed on their own instance all the same. **Therefore, the onion links that you list get visibility from the webring participants that choose to tolerate listing them, themselves.** On my darknet lantern instance for instance I refuse there to be porn links due to how addictive these can be, and I actively blacklist them, so if you want to find those links, you'll have to go through another webring participant that accepts to list them.

## **What is the Darknet Lantern Project ?**

![](16.png)

The Darknet Lantern project aims to provide 3 core functionalities:

  1. Allow you to run and maintain your own list of onion links, and make it accessible for whoever wants to access it,

  2. Allow you to automatically check the uptime of the onion links that you list, so that you can track which links are no longer active easily,

  3. Allow you to participate in a Darknet Webring so that your community may benefit from the visibility coming from the other communities that are participating in the same Webring. 


![](../darknetexploration/17.png)

The source code for the project is available [here](http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/darknet-lantern). At first I wrote it mainly because I was largely dissatisfied with how the [uptime-kuma](https://github.com/louislam/uptime-kuma) project required javascript and how Database-corruptive the upgrades were. After I nailed down the basic "uptime checker" part, it dawned on me that the webring part was also equally essential for the Darknet ecosystem, as explained above. So that's what I have been focusing on for the last 4 weeks, and now I can proudly say that the project is reaching maturity.

![](15.png)

The Darknet Lantern project is built using PHP, Python, and CSV files. You have the CSV files containing the onion links and their attributes, you have python scripts in the backend to automatically update the uptime of those links, including one main python script called lantern.py to manually maintain and edit your instance's csv files.

And lastly you have the index.php and static.php files to search through those CSV files, and filter the results like a regular search engine. All in all, it has been built with minimalism in mind, I tried to keep it as simple as I could to meet the needs. To make it work you need a Debian stable release (currently Debian 12 bookworm), nginx, php8.2-fpm (currently), Tor, python3 and a few other python3 dependencies that you can install via the apt package manager.

This project has been built with anonymity in mind, by default, for the serverside. When you are checking the uptimes for both clearnet and darknet websites, **the requests all go through Tor to prevent the website's location from being discovered.**

This project also takes into account that malicious webring participants may show up, and therefore **lantern comes with safeguards and checks in place to prevent any malicious inputs (meaning php, python or bash commands) from being ran from the csv values that may be received from other instances.** The PHP files are also preventing any php code from being run from the CSV files even if there was one to slip through the cracks.

## **How to setup your own Darknet Lantern Instance ?**

![](../context/anon_remote.png)

Now that we got that out of the way, let's see how you can install your own Darknet Lantern Instance:

First, git clone the repository in your directory of choice (i recommend using /srv/):
    
    
    [ Wonderland ] [ /dev/pts/23 ] [/srv/darknet-lantern]
    → apt install tor git torsocks -y
    
    [ Wonderland ] [ /dev/pts/23 ] [/srv/darknet-lantern]
    → torsocks git clone http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/darknet-lantern /srv/darknet-lantern
    
    

Install nginx and php8.2-fpm, and php-gd for the new captcha feature:
    
    
    [ Wonderland ] [ /dev/pts/23 ] [/srv/darknet-lantern]
    → apt install php-gd php8.2-fpm nginx -y
    
    

use the nginx.conf and drop it in /etc/nginx/sites-available/
    
    
    [ Wonderland ] [ /dev/pts/23 ] [/srv/darknet-lantern]
    → ls
    nginx.conf  README.md  scripts  todo.txt  torrc  www
    
    [ Wonderland ] [ /dev/pts/23 ] [/srv/darknet-lantern]
    → cp nginx.conf /etc/nginx/sites-available/lantern.conf
    
    [ Wonderland ] [ /dev/pts/23 ] [/srv/darknet-lantern]
    → vim /etc/nginx/sites-available/lantern.conf
    
    [ Wonderland ] [ /dev/pts/23 ] [/srv/darknet-lantern]
    → cat /etc/nginx/sites-available/lantern.conf
    
    server {
            listen 127.0.0.1:4443;
            server_name lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion;

            root /srv/darknet-lantern/www/;
            location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
            }
            index index.php;
    }
    
    

use mkp244o if you want to have a custom [vanity v3 hidden service domain name](../torwebsite/index.md), and then use the torrc config to have a local socks5 port (as it will be used by the python script to check the uptime of the listed onion links)
    
    
    [ Wonderland ] [ /dev/pts/23 ] [/srv/darknet-lantern]
    → vim /etc/tor/torrc
    
    [ Wonderland ] [ /dev/pts/23 ] [/srv/darknet-lantern]
    → cat /etc/tor/torrc
    
    HiddenServiceDir /var/lib/tor/onions/nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/
    HiddenServicePort 80 127.0.0.1:4443
    SocksPort 127.0.0.1:9050
    
    [ Wonderland ] [ /dev/pts/23 ] [/srv/darknet-lantern]
    → systemctl restart tor@default
    
    

enable the nginx config and validate that your website can now be accessed via the Tor browser:
    
    
    [ Wonderland ] [ /dev/pts/23 ] [/srv/darknet-lantern]
    → ln -s /etc/nginx/sites-available/lantern.conf /etc/nginx/sites-enabled/
    
    [ Wonderland ] [ /dev/pts/23 ] [/srv/darknet-lantern]
    → nginx -s reload
    
    

![](4.png)

Here we see that the website is reachable now, so let's now install the python script dependencies:
    
    
    [ Wonderland ] [ /dev/pts/23 ] [/srv/darknet-lantern]
    → apt install python3-pandas python3-requests python3-socks python3-dotenv python3-pip -y

    [ Wonderland ] [ /dev/pts/23 ] [/srv/darknet-lantern]
    → sudo pip3 install --upgrade websockets --break-system-packages
    
    

Now that's done, you can run scripts/lantern.py for the first time to confirm your own instance name:
    
    
    [ Wonderland ] [ /dev/pts/20 ] [/srv/darknet-lantern]
    → python3 scripts/lantern.py
    [+] Instance Path doesn't exist yet
    What is your Instance domain ? (ex: lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion): lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion
    
    [+] Instance Name:  lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion True
    
    lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion
    Is this your this your instance domain ? (y/n)y
    OK writing the instance url to ~/.darknet_participants_url
    [+] file written, let's read it
    lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion
    [+] Initial Setup Completed!
    [+] file exists, your Webring URL is lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion
    
    

In another terminal you can validate that ~/darknet_participant_url has been created properly:
    
    
    [ Wonderland ] [ /dev/pts/33 ] [/srv/darknet-lantern]
    → cat ~/.darknet_participant_url
    lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion#
    
    

This is the file that lantern.py will check to get your instance name the next times you run the script. And next when you run scripts/lantern.py you'll be greeted by the following CLI menu:
    
    
    [ Wonderland ] [ /dev/pts/20 ] [/srv/darknet-lantern]
    → python3 scripts/lantern.py
    [+] Instance Name: lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion True
    [+] file exists, your Webring URL is lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion
    	
    [+] Welcome to your own Darknet Lantern Instance, where you can explore the Darknet and help others do the same.
    
    Managing Websites:
     1) Add a new Website entry (into unverified.csv)
     2) Trust a Website entry (move an entry from unverified to verified.csv)
     3) Untrust a Website entry (move an entry from unverified to verified.csv)
    
    Managing Webring Participants:
     4) Synchronize new links from existing webring participants, into your unverified.csv file
     5) Add a new webring participant (and download their files into their directory (without trusting them yet!))
     6) Trust/UnTrust/Blacklist a webring participant (Potentially dangerous)
    
    Managing Wordlists:
     7) Add/Remove Words/URLs in the sensitive list (ex: drug)
     8) Add/Remove Words/URLs or links in the blacklist (ex: porn)
    
    Maintenance:
     9) Remove the duplicate URLs for your own instance
     10) Perform sanity checks on all csv files for all instances (to mark them as sensitive / or remove the ones that are blacklisted)
    
     0) Exit
    
    Select Option? (0-11): 
    
    

## **How to Maintain your own list of onion links ?**

At first your list of onion links is going to be empty, so if you try to search for a term in the searchbar you'll get the following message:

![](5.png)

So here we need to start to list some onion links. Using scripts/lantern.py's option 1 we can add those links:
    
    
    Select Option? (0-11): 1
    1
    
    [+] Add a new Website entry (into unverified.csv)
    What is the Website name ? Qubes OS Website
    What is the website Category ? Tools
    What is the website URL ? http://qubesosfasa4zl44o4tws22di6kepyzfeqv3tg4e3ztknltfxqrymdad.onion/
    Description for the website ? (Optional) OS based on Xen that focuses on compartmentalization and virtualization.
    Is the website sensitive ? (ex: related to drugs) (y/n) n
    [+] NEWROW= ['lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion', 'Tools', 'Qubes OS Website', 'http://qubesosfasa4zl44o4tws22di6kepyzfeqv3tg4e3ztknltfxqrymdad.onion/', 'NO', 'OS based on Xen that focuses on compartmentalization and virtualization.', '', '']
    [+] New row added! now writing the csv file:
    
    
    
    
    [+] Want to add another website ? (y/n) y
    
    [+] Add a new Website entry (into unverified.csv)
    What is the Website name ? Whonix Website
    What is the website Category ? Tools
    What is the website URL ? http://www.dds6qkxpwdeubwucdiaord2xgbbeyds25rbsgr73tbfpqpt4a6vjwsyd.onion/
    Description for the website ? (Optional) VM for general anonymous use
    Is the website sensitive ? (ex: related to drugs) (y/n) n
    
    [+] Want to add another website ? (y/n) y
    
    [+] Add a new Website entry (into unverified.csv)
    What is the Website name ? Feather Wallet
    What is the website Category ? Tools
    What is the website URL ? http://featherdvtpi7ckdbkb2yxjfwx3oyvr3xjz3oo4rszylfzjdg6pbm3id.onion/
    Description for the website ? (Optional) Lightweight Monero Wallet
    Is the website sensitive ? (ex: related to drugs) (y/n) n
    
    

Also, **please categorize links by their utility instead of trying to categorize them by their community name.** It does not matter who does what, what matters is what the service does ([more details](../../productivity/sum-nihil/index.md) on that thought process). For instance as you'll see below, if i want to list my own community's main website, i'll categorize it under "communities". and if i want to do the same for the blog service i run, i'll categorize it under "blogs":
    
    
    Select Option? (0-11): 1
    1
    
    [+] Add a new Website entry (into unverified.csv)
    What is the Website name ? Nowhere
    What is the website Category ? Communities
    What is the website URL ? nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion
    Description for the website ? (Optional)
    Is the website sensitive ? (ex: related to drugs) (y/n) n
    
    [+] Add a new Website entry (into unverified.csv)
    What is the Website name ? The Opsec Bible
    What is the website Category ? Blogs
    What is the website URL ? opbible7nans45sg33cbyeiwqmlp5fu7lklu6jd6f3mivrjeqadco5yd.onion
    Description for the website ? (Optional)
    Is the website sensitive ? (ex: related to drugs) (y/n) n
    
    

In order to avoid putting all eggs in one basket, I recommend marking websites that are related to Drugs (as this is the most popular sensitive darknet topic) as sensitive whenever you add them into your unverified.csv file, that way you can give your audience a safe browsing searching experience, and an opt-in sensitive browsing search experience (with ample disclaimers/warnings) if they choose to do so. 
    
    
    [+] Want to add another website ? (y/n) y
    
    [+] Add a new Website entry (into unverified.csv)
    What is the Website name ? Dark Forest
    What is the website Category ? Forums
    What is the website URL ? http://dkforestseeaaq2dqz2uflmlsybvnq2irzn4ygyvu53oazyorednviid.onion/
    Description for the website ? (Optional)
    Is the website sensitive ? (ex: related to drugs) (y/n) y
    
    [+] Want to add another website ? (y/n) n
    
    

` There is also a sensitive.csv file in your instance directory to list those keywords, so that they get automatically marked as sensitive by the python scripts.

Now that you added some websites to your unverified.csv file, you can view the csv file in www/participants/YOURINSTANCENAME.onion/unverified.csv:
    
    
    [ Wonderland ] [ /dev/pts/33 ] [/srv/darknet-lantern]
    → cat www/participants/lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/unverified.csv | grep Tools
    
    Instance,Category,Name,URL,Sensitive,Description,Status,Score
    
    lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion,Tools,Feather Wallet,http://featherdvtpi7ckdbkb2yxjfwx3oyvr3xjz3oo4rszylfzjdg6pbm3id.onion/,NO,Lightweight Monero Wallet,,
    lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion,Tools,Whonix Website,http://www.dds6qkxpwdeubwucdiaord2xgbbeyds25rbsgr73tbfpqpt4a6vjwsyd.onion/,NO,VM for general anonymous use,,
    lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion,Tools,Qubes OS Website,http://qubesosfasa4zl44o4tws22di6kepyzfeqv3tg4e3ztknltfxqrymdad.onion/,NO,OS based on Xen that focuses on compartmentalization and virtualization.,,
    
    

As you can see, the websites' uptime status and score is missing (in the last 2 columns in the csv file), therefore using scripts/uptimechecker.py we'll automatically fill those in:
    
    
    [ Wonderland ] [ /dev/pts/33 ] [/srv/darknet-lantern]
    → python3 scripts/uptimechecker.py
    [+] ONION UPTIME CHECKER
    [+] Instance Name: lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion True
    [+] Reading the CSV File: /srv/darknet-lantern/www/participants/lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/verified.csv
    
                   Name                                                URL
    0    Feather Wallet  http://featherdvtpi7ckdbkb2yxjfwx3oyvr3xjz3oo4...
    1    Whonix Website  http://www.dds6qkxpwdeubwucdiaord2xgbbeyds25rb...
    2  Qubes OS Website  http://qubesosfasa4zl44o4tws22di6kepyzfeqv3tg4...
    What is the Website name you want to trust ? (ex: Nowhere)Qubes
    
    [+] Checking if each .onion link is reachable:
    [+] Editing the uptime score
    0
    [+] http://lvgjoige2hl5qm5xcxhxuulyhdnq2wk3277eu34zpukxvacmvwva6vid.onion/read 200
    http://lvgjoige2hl5qm5xcxhxuulyhdnq2wk3277eu34zpukxvacmvwva6vid.onion/read YES
    [+] Editing the uptime score
    1
    [+] http://opbible7nans45sg33cbyeiwqmlp5fu7lklu6jd6f3mivrjeqadco5yd.onion/ 200
    http://opbible7nans45sg33cbyeiwqmlp5fu7lklu6jd6f3mivrjeqadco5yd.onion/ YES
    [+] Editing the uptime score
    2
    
    [...]
    
    

It may take a few minutes depending on the size of your list of links to check all of their uptimes, as the script has to connect through Tor for every website to tell if they are reachable or not. make sure the cronjob for scripts/uptimechecker.py is running at least once every 3 hours so that the csv files are automatically kept up to date. 
    
    
    [ Wonderland ] [ /dev/pts/23 ] [/srv/darknet-lantern]
    → crontab -e
    
    */3 0 * * * python3 /srv/darknet-lantern/scripts/uptimechecker.py
    
    

To verify links (meaning that you are moving links from your unverified.csv file into your verified.csv file), use scripts/lantern.py to do the following:
    
    
    [ Wonderland ] [ /dev/pts/33 ] [/srv/darknet-lantern]
    → python3 scripts/lantern.py
    
    Select Option? (0-11): 2
    2
    [+] Trust a Website entry (move an entry from unverified to verified.csv)
                   Name                                                URL
    0    Feather Wallet  http://featherdvtpi7ckdbkb2yxjfwx3oyvr3xjz3oo4...
    1    Whonix Website  http://www.dds6qkxpwdeubwucdiaord2xgbbeyds25rb...
    2  Qubes OS Website  http://qubesosfasa4zl44o4tws22di6kepyzfeqv3tg4...
    What is the Website name you want to trust ? (ex: Nowhere)Qubes
                   Name                                                URL
    2  Qubes OS Website  http://qubesosfasa4zl44o4tws22di6kepyzfeqv3tg4...
    What is the index of the entry that you want to move to verified.csv ? (ex: 3) 2
    ['lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion'
     'Tools' 'Qubes OS Website'
     'http://qubesosfasa4zl44o4tws22di6kepyzfeqv3tg4e3ztknltfxqrymdad.onion/'
     'NO'
     'OS based on Xen that focuses on compartmentalization and virtualization.'
     nan nan]
    [+] New row added to verified.csv! now writing to the csv
    [+] Link is now moved to verified.csv!
    
    [+] Want to trust another website ? (y/n) n
    
    

Now that's done you can check the links that you listed on your lantern instance:

![](6.png)

If you want to untrust a website, you can use the option 3 of lantern.py:
    
    
    [ Wonderland ] [ /dev/pts/33 ] [/srv/darknet-lantern]
    → python3 scripts/lantern.py
    
    Select Option? (0-11): 3
    3
    [+] Untrust a Website entry (move an entry from verified to unverified.csv)
                   Name                                                URL
    0  Qubes OS Website  http://qubesosfasa4zl44o4tws22di6kepyzfeqv3tg4...
    What is the Website name you want to untrust ? (ex: BreachForums)Qubes
                   Name                                                URL
    0  Qubes OS Website  http://qubesosfasa4zl44o4tws22di6kepyzfeqv3tg4...
    What is the index of the entry that you want to move to unverified.csv ? (ex: 3) 0
    ['lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion'
     'Tools' 'Qubes OS Website'
     'http://qubesosfasa4zl44o4tws22di6kepyzfeqv3tg4e3ztknltfxqrymdad.onion/'
     'NO'
     'OS based on Xen that focuses on compartmentalization and virtualization.'
     nan nan]
    [+] New row added to unverified.csv!
    [+] Link is now moved to unverified.csv!
    
    

![](7.png)

## **How get the links from other Webring participants ?**

Right now the webring participants may not be listed on your instance, but the files already exist here. 
    
    
    [ Wonderland ] [ /dev/pts/20 ] [/srv/darknet-lantern]
    → tree www/participants
    www/participants
    ├── lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion
    │   ├── banner.png
    │   ├── blacklist.csv
    │   ├── sensitive.csv
    │   ├── unverified.csv
    │   ├── verified.csv
    │   └── webring-participants.csv
    ├── lantern.nowhevi57f4lxxd6db43miewcsgtovakbh6v5f52ci7csc2yjzy5rnid.onion
    │   ├── banner.png
    │   ├── blacklist.csv
    │   ├── sensitive.csv
    │   ├── unverified.csv
    │   ├── verified.csv
    │   └── webring-participants.csv
    └── lanterntest.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion
        ├── banner.png
        ├── blacklist.csv
        ├── sensitive.csv
        ├── unverified.csv
        ├── verified.csv
        └── webring-participants.csv
    
    4 directories, 18 files
    
    

So let's sync the links coming from the other webring participants:
    
    
    [ Wonderland ] [ /dev/pts/30 ] [/srv/darknet-lantern]
    → python3 scripts/lantern.py
    
    Select Option? (0-11): 4
    
    Select Option? (0-11): 4
    4
    4) Synchronize new links from existing webring participants, into your unverified.csv file
    http://lantern.nowhevi57f4lxxd6db43miewcsgtovakbh6v5f52ci7csc2yjzy5rnid.onion/participants/lantern.nowhevi57f4lxxd6db43miewcsgtovakbh6v5f52ci7csc2yjzy5rnid.onion/
    [+] Downloading the files of lantern.nowhevi57f4lxxd6db43miewcsgtovakbh6v5f52ci7csc2yjzy5rnid.onion:
    [+] Webring Participant is reachable, updating their csv files:
    
    [...]
    
    http://lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/participants/lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/
    [+] Downloading the files of lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion:
    [+] Webring Participant is reachable, updating their csv files:
    
    [...]
    
    

And now that the script finished running you now have all of the links coming from other webring participants that are stored into your own unverified.csv file, so to check it you can check again from the web interface by searching for links: 

![](8.png)

And there you go ! you are now displaying the links that other webring participants are listing. You can start to verify those links yourself

![](9.png)

## **What if there is a malicious webring participant ?**

Now when you are synchronizing links from other webring participants, you may realize that there was a malicious link that got listed from a webring participant: 

![](10.png)

From here you can blacklist the link manually by adding it into the blacklist.csv file:
    
    
    [ Wonderland ] [ /dev/pts/20 ] [/srv/darknet-lantern]
    → python3 scripts/lantern.py
    
    Select Option? (0-11): 8
    8
    [+] Add/Remove words in the blacklist list (ex: porn)
    [+] Do you want to 1) add  or 2) remove Words/URLs? (type exit to exit) 1
    [+] Which word/link do you want to add to the blacklist? (write -1 to exit) http://thatonelinkyoudontwanttoseeeveragain.onion
    [+] Checking if the Word/URL is valid:
    [+] Which word/link do you want to add to the blacklist? (write -1 to exit) http://thatonelinkyoudontwanttoseeeveragain.onion
    [+] Checking if the Word/URL is valid:
    [+] Which word/link do you want to add to the blacklist? (write -1 to exit) https://thatonelinkyoudontwanttoseeeveragain.com
    [+] Checking if the Word/URL is valid:
    TrueFalse
    False
    [+] Word/URL is valid, adding the word into the blacklist
    [+] NEWROW=['https://thatonelinkyoudontwanttoseeeveragain.com']
    [+] New row added! now writing the csv file:
    [+] Which word/link do you want to add to the blacklist? (write -1 to exit) -1
    	
    [ Wonderland ] [ /dev/pts/20 ] [/srv/darknet-lantern]
    → cat www/participants/lanterntest.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/blacklist.csv
    blacklisted-words
    https://thatonelinkyoudontwanttoseeeveragain.com
    porn
    
    

and then you can run the sanity checks on the links to automatically remove the links that match any blacklisted words for all csv files in www/participants/:
    
    
    [ Wonderland ] [ /dev/pts/20 ] [/srv/darknet-lantern]
    → python3 scripts/lantern.py
    
    Select Option? (0-11): 10
    10
    [+] 10) perform sanity checks on all csv files (to mark them as sensitive / or remove the ones that are blacklisted)
    Participant:lanterntest.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion
    /srv/darknet-lantern/www/participants/lanterntest.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/verified.csv
    ['lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion', 'Tools', 'Qubes OS Website', 'http://qubesosfasa4zl44o4tws22di6kepyzfeqv3tg4e3ztknltfxqrymdad.onion/', 'NO', 'OS based on Xen that focuses on compartmentalization and virtualization.', nan, nan]
    /srv/darknet-lantern/www/participants/lanterntest.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/unverified.csv
    
    ['assholexxd6db43miewcsgtovakbh6v5f52ci7csc2yjzy5rnid.onion', 'Chat', "a link that you normally don't allow", 'https://thatonelinkyoudontwanttoseeeveragain.com', 'NO', nan, 'YES', 100.0]
    Marking row0for deletion, as it has invalid inputs
    
    

And from here as you can see, the link in question got removed, and since it is now in your blacklist.csv file, it won't ever get added to your csv files again since you:

![](11.png)

If you prefer to only run a read-only php page with all the links at once you can either use the search query **"."** or use the static.php page as follows:

![](14.png)

you can also use this optional nginx config that makes static.php your new default index page:
    
    
    server {
            listen 4443;
            listen [::]:4443;
            server_name uptime.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion;
    
            root /srv/darknet-onion-webring/www/;
            location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
            }
    
            #index index.php;
    
            # optional read-only static php file without the searchbar, to display all links by default :
            
            index static.php;
    }
    

You can also edit the default banner.png image for your instance if you want to customize your instance:

![](12.png)

If you want to change it you can upload your custom banner.png image in your instance folder in **/srv/darknet-lantern/www/participants/lantern.nowherejezblahblah.onion/banner.png** but be careful, the python scripts are going to check **if your banner has the 240x60 resolution** , if it does not it won't be accepted by the other webring participants, and it will simply be replaced by the default banner image (coming from the templates folder)
    
    
    [ laptop-privateVM ] [ /dev/pts/8 ] [blog/opsec/darknetlantern]
    → scp banner.png yourserver:/srv/darknet-lantern/www/participants/yourinstancename.onion/banner.png
    

![](17.png)

Since v1.0.1, you can now automate the updating of your lantern instance despite the www/participants folder changing (thanks to the changes made to .gitignore):
    
    
    [ Datura ] [ /dev/pts/28 ] [~]
    → /usr/bin/torsocks /usr/bin/git -C /srv/darknet-lantern/ pull
    
    warning: redirecting to http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/darknet-lantern/
    remote: Enumerating objects: 24, done.
    remote: Counting objects: 100% (24/24), done.
    remote: Compressing objects: 100% (19/19), done.
    remote: Total 19 (delta 14), reused 0 (delta 0), pack-reused 0 (from 0)
    Unpacking objects: 100% (19/19), 2.06 KiB | 421.00 KiB/s, done.
    From http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/darknet-onion-webring
       5928fd3..dc0c2ef  main       -> origin/main
    Updating 5928fd3..dc0c2ef
    Fast-forward
     README.md                                                                                          |  37 ++++++++++++++++++++++++++++++++-----
     scripts/lantern.py                                                                                 |   6 ++++--
     www/participants/lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/banner.png | Bin 14119 -> 0 bytes
     www/participants/lantern.nowhevi57f4lxxd6db43miewcsgtovakbh6v5f52ci7csc2yjzy5rnid.onion/banner.png | Bin 8952 -> 0 bytes
     www/participants/zhd7yf675dav6njgc7yjwke2u5cq7d5qim2s7xwa2ukxfzubrguqmzyd.onion/banner.png         | Bin 20935 -> 0 bytes
     5 files changed, 36 insertions(+), 7 deletions(-)
     delete mode 100644 www/participants/lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/banner.png
     delete mode 100644 www/participants/lantern.nowhevi57f4lxxd6db43miewcsgtovakbh6v5f52ci7csc2yjzy5rnid.onion/banner.png
     delete mode 100644 www/participants/zhd7yf675dav6njgc7yjwke2u5cq7d5qim2s7xwa2ukxfzubrguqmzyd.onion/banner.png
    
    

Since v1.0.1 you can now automatically perform that git pull using cronjobs like so:

```hl_lines="6"    
[ Datura ] [ /dev/pts/28 ] [~]
→ crontab -e

#lantern
*/3 0 * * * python3 /srv/darknet-lantern/scripts/uptimechecker.py
0 0 * * * /usr/bin/torsocks /usr/bin/git -C /srv/darknet-lantern/ pull
```

That way it'll update your lantern software once a day, at midnight.

Since v1.0.2 you can now also automatically synchronize new links coming from other webring participants using the following cronjob entry:

```hl_lines="7"
[ Datura ] [ /dev/pts/28 ] [~]
→ crontab -e

#lantern
*/3 0 * * * python3 /srv/darknet-lantern/scripts/uptimechecker.py
0 0 * * * /usr/bin/torsocks /usr/bin/git -C /srv/darknet-lantern/ pull
0 1 * * * python3 /srv/darknet-lantern/scripts/lantern.py 4
```
    

With those cronjobs, you'll automatically have an updated darknet lantern instance, automatically synchronising new links coming from the webring participants, and with automatically updated statuses, on a daily basis.

## **How to participate in the webring ?**

In order to participate in the webring that I am running, the only requirements I have is that your webring instance should have the core functionnalities (you list links you didn't verify yet, you also list the ones you verified, and you list the other webring participants), you should bring some new onion links i don't already have, and you shouldn't list porn links.

_Sidenote:_ you are free to fork the project, and change how the front-end looks to customize it, **but the CSV format (especially the columns order and their titles, and the values format) and the paths**(ex: http://URL.onion/participants/URL.onion/verified.csv) **those NEED to remain the same to be able to remain compatible with the other lantern instances.**

So if you are running a functional lantern instance, you can either [send me a private message on SimpleX](https://simplex.chat/contact#/?v=2-7&smp=smp%3A%2F%2FBD4qkVq8lJUgjHt0kUaxeQBYsKaxDejeecxm6-2vOwI%3D%40b6geeakpwskovltbesvy3b6ah3ewxfmnhnshojndmpp7wcv2df7bnead.onion%2F4NTxj7pyXgVGYfHs8qDdKfW-STOA8AP1%23%2F%3Fv%3D1-3%26dh%3DMCowBQYDK2VuAyEA5FMqfn6nXs8ETbpz2iu55jr3BKHlfuesWVnko-A1Ewk%253D), or you can show up [in the Darknet Lantern Simplex chatroom](https://simplex.chat/contact#/?v=2-7&smp=smp%3A%2F%2FBD4qkVq8lJUgjHt0kUaxeQBYsKaxDejeecxm6-2vOwI%3D%40b6geeakpwskovltbesvy3b6ah3ewxfmnhnshojndmpp7wcv2df7bnead.onion%2F4woLIDlpkvXRvZmaAiWA802OwiyxekdJ%23%2F%3Fv%3D1-3%26dh%3DMCowBQYDK2VuAyEAzIAoE-OWDqFJXMqgunIWHPpE_u7e52Wtu8TioPc1QwI%253D&data=%7B%22groupLinkId%22%3A%22Srr1_MNob7WfPTQIY-ug5Q%3D%3D%22%7D) i'm running, and let me know that you are running a darknet lantern instance. After that i'll go and check your darknet lantern instance to check for the new links you are bringing to the table, and if there are no porn links there, i'll add it to my darknet lantern instance by doing the following:
    
    
    Select Option? (0-11): 5
    5
    [+] Add a new webring participant (and download their files into their directory (without trusting them yet!))
    What is the onion domain of the new webring participant? (ex: lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion)  lanterntest.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion
    http://lanterntest.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/participants/lanterntest.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/
    [+] Checking if all of the required csv files exists for new webring participant lanterntest.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion:
    [+] Webring Participant is valid, adding it.
    What is the Webring instance name ? Nowhere3
    Description for the webring participant ? (Optional)
    [+] New row added! now writing the csv file:/srv/darknet-lantern/www/participants/lantern.nowhevi57f4lxxd6db43miewcsgtovakbh6v5f52ci7csc2yjzy5rnid.onion/webring-participants.csv
    [+] DOWNLOADING http://lanterntest.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/participants/lanterntest.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/verified.csv
    [+] SAVING IT INTO /srv/darknet-lantern/www/participants/lanterntest.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/verified.csv
    [+] file written, let's read it
    Instance,Category,Name,URL,Sensitive,Description,Status,Score
    
    [+] DOWNLOADING http://lanterntest.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/participants/lanterntest.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/unverified.csv
    [+] SAVING IT INTO /srv/darknet-lantern/www/participants/lanterntest.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/unverified.csv
    [+] file written, let's read it
    Instance,Category,Name,URL,Sensitive,Description,Status,Score
    
    [+] DOWNLOADING http://lanterntest.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/participants/lanterntest.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/blacklist.csv
    [+] SAVING IT INTO /srv/darknet-lantern/www/participants/lanterntest.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/blacklist.csv
    [+] file written, let's read it
    blacklisted-words
    porn
    
    [+] DOWNLOADING http://lanterntest.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/participants/lanterntest.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/sensitive.csv
    [+] SAVING IT INTO /srv/darknet-lantern/www/participants/lanterntest.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/sensitive.csv
    [+] file written, let's read it
    sensitive-words
    Market
    market
    drug
    
    
    [+] DOWNLOADING http://lanterntest.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/participants/lanterntest.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/webring-participants.csv
    [+] SAVING IT INTO /srv/darknet-lantern/www/participants/lanterntest.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/webring-participants.csv
    [+] file written, let's read it
    Name,URL,Description,Trusted,Status,Score
    
    [+] Banner is valid
    [-] Rows to delete: []
    [-] Rows to delete: []
    
    

Once added, you'll be able to see from my lantern instance that i added the new instance as a webring participant:

![](13.png)

And from there, if you are the maintainer of a webring like i am, you can make that new webring participant official by mentionning their hostname in `www/.official_participants`: 

```hl_lines="5"
[ Wonderland ] [ /dev/pts/30 ] [/srv/darknet-lantern]
→ cat www/.official_participants
lantern.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion
lantern.nowhevi57f4lxxd6db43miewcsgtovakbh6v5f52ci7csc2yjzy5rnid.onion
zhd7yf675dav6njgc7yjwke2u5cq7d5qim2s7xwa2ukxfzubrguqmzyd.onion
```

And then just do a git push to the git repository, **so that whoever else wants to run a darknet lantern instance will already have the webring participant ready to be listed with their files saved in the www/participants directory.**
    
    
    [ Datura ] [ /dev/pts/3 ] [/srv/darknet-lantern]
    → git add -A
    
    [ Datura ] [ /dev/pts/3 ] [/srv/darknet-lantern]
    → git commit
    
    [ Datura ] [ /dev/pts/3 ] [/srv/darknet-lantern]
    → torsocks git push
    
    

And that's it! you are now an official member of the darknet lantern webring, your community may now benefit from the visibility coming from the other webring participants' communities, while at the same time making sure that your community gets to know that those other communities exist.

## **How to receive link submissions ?**

Starting with Lantern version v1.1.0, your lantern instance can now receive submissions from the visitors directly, you can access the submission page on the **/submit.php** url:

![](19.png)

If you wish to receive links from your audience, you just need to copy the template submission.csv file and edit the file rights of the submissions folder accordingly (as otherwise there will be a blank page when trying to submit a new link):
    
    
    [ Mainpc-PrivateVM-Debian12 ] [ /dev/pts/14 ] [/srv/darknet-lantern]
    → cp templates/submission.csv submissions/submission.csv
    
    [ Wonderland ] [ /dev/pts/14 ] [/srv/darknet-lantern]
    → chmod 777 -R /srv/darknet-lantern/submissions/
    
    #optional, use that following command if you are updating from the previous lantern version
    [ Wonderland ] [ /dev/pts/14 ] [/srv/darknet-lantern]
    → git rm --cached /srv/darknet-lantern/submissions/submission.csv
    
    

From here, anyone can mention the new link to submit, the name of that link, the description, the category name, and wheter or not the link is sensitive (related to drugs) or not. And lastly, to prevent spam, we also implemented a Captcha mechanism.

![](18.png)

Once the link is correctly submitted, as a lantern admin you have to manually verify it (obviously there's no way we'd let strangers submit links that would be directly displayed on your own lantern instance without any manual verification whatsoever, let's be real, that would be too risky).

Back on your lantern instance server, you can run lantern.py's new option 11) to review submissions:
    
    
    [ Mainpc-PrivateVM-Debian12 ] [ /dev/pts/7 ] [/srv/darknet-lantern]
    → python3 scripts/lantern.py
    
    [+] Instance Name: dawdawddwawdadwadwadwawdaddawdov22nk2d3plyvwc7yd.onion. Valid:True
    [+] file exists, your Webring URL is dawdawddwawdadwadwadwawdaddawdov22nk2d3plyvwc7yd.onion
    
    [+] Welcome to your own Darknet Lantern Instance, where you can explore the Darknet and help others do the same.
    
    Managing Websites:
     1) Add a new Website entry (into unverified.csv)
     2) Trust/Untrust/ Blacklist a Website entry (move an entry from unverified to verified.csv)
     3) Edit link attributes
    
    Managing Webring Participants:
     4) Synchronize new links from existing webring participants, into your unverified.csv file
     5) Add a new webring participant (and download their files into their directory (without trusting them yet!))
     6) Trust/UnTrust/Blacklist a webring participant (Potentially dangerous)
    
    Managing Wordlists:
     7) Add/Remove Words/URLs in the sensitive list (ex: drug)
     8) Add/Remove Words/URLs or links in the blacklist (ex: porn)
    
    Maintenance:
     9) Remove the duplicate URLs for your own instance
     10) Perform sanity checks on all csv files for all instances (to mark them as sensitive / or remove the ones that are blacklisted)
     **11) Review submissions (Add to verified.csv/ add to unverified.csv/ delete /blacklist)**
    
     0) Exit
    
    Select an option? (0-11): 11
    

That new option is going to simply iterate over every new submission you received, allowing you to move the entry to 1) verified.csv, 2) or to unverified.csv, 3) or to simply delete it, 4) or to blacklist it if it's a malicious link:

```hl_lines="7"
name         test
desc         test
category     test
sensitive       y
Name: 0, dtype: object

Link to verify:  http://coollinkdwadwdwawaadwdawdawdwawaddwawdaadw.onion/

1) Move entry to verified.csv
2) Move entry from submission.csv to unverified.csv
3) Delete from submission.csv file
4) Add to blacklist.csv
-1) exit
Enter an option: 1
```
    

Here we need to copy the link into our Tor browser to review it, and upon reviewing it, we see that it's a cool and valid link, so we pick option 1 to move it to verified.csv. 
    
```hl_lines="7"
name         test
desc         test
category     test
sensitive       y
Name: 0, dtype: object

Link to verify:  http://weirdlinkdwadwdwawaadwdawdawdwawaddwawdaadw.onion/

1) Move entry to verified.csv
2) Move entry from submission.csv to unverified.csv
3) Delete from submission.csv file
4) Add to blacklist.csv
-1) exit
Enter an option: 2
```

Then we have a second submitted link, which upon reviewing is weird and not what you expected, but upon reviewing it's not something you need to blacklist so we select option 2 to leave it in unverified.csv for the time being.

```hl_lines="7"
name         test
desc         test
category     test
sensitive       y
Name: 0, dtype: object

Link to verify:  http://cringelinkwadawdwdwawaadwdawdawdwawaddwawdaadw.onion/

1) Move entry to verified.csv
2) Move entry from submission.csv to unverified.csv
3) Delete from submission.csv file
4) Add to blacklist.csv
-1) exit
Enter an option: 3
```

The next submission is a cringe link, so for this one instead we're going to just delete it with option 3.

```hl_lines="7"
name         test
desc         test
category     test
sensitive       y
Name: 0, dtype: object

Link to verify:  http://maliciouslinkwadwdwawaadwdawdawdwawaddwawdaadw.onion/

1) Move entry to verified.csv
2) Move entry from submission.csv to unverified.csv
3) Delete from submission.csv file
4) Add to blacklist.csv
-1) exit
Enter an option: 4
```

And the last submitted link is actually a malicious link (for example a porn link) so we select option 4 to put it into our blacklist.csv.

