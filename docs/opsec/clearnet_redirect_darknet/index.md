---
author: Anonymous
date: 2025-08-10
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/260"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
tags:
  - Serverside Anonymity
---
# How to redirect your clearnet audience to the Darknet

```
TLDR: by using the "gone-underground" project that I developed, you can redirect your clearnet audience to the darknet mirror of your websites, while also telling them to install the Tor browser
```

If you've read my tutorial on how the darknet was superior to the clearnet, you may be faced with this dilemma: "how do I make sure that my audience follows me from the clearnet to the darknet ?"

In this tutorial i'm going to show you how i have been redirecting the clearnet audience of the nowhere community to the darknet.

**First of all, take note that you should not have the clearnet presence of your website on the same server as the darknet mirror, in case if it's a sensitive service:**

![alt text](image-2.png)

## Why is this important ?

This is is because it is EASY for an adversary to take down your clearnet domain, and servers, simply because their locations are known, and thus, are easily subpoenable. **Your sensitive service should be able to survive clearnet-related takedowns and still survive, unlike what happened to XSS.is:** 

![alt text](image-3.png)

XSS.is was a black hat hacking forum, whose main forum service was clearnet-based, **and their onion mirror was just a proxy to the clearnet one)**, meaning that in the end their service did not survive the clearnet presence takedown.

**TLDR: if you want to have a sensitive service going, don't make it easy to take down by the adversary. Make sure that the main instance of the service sits on an onion-only darknet presence, and ensure that the clearnet presence remains completely separated from it, on a separate VPS, ready to be taken down without affecting the service.**

## The gone-underground php project

First, install the following dependencies on your server:
```sh
root@nowhere:/srv#  apt install nginx curl php8.2-fpm socat -y
```

Then, git clone the following repository in /srv/ :

```sh
root@nowhere:/srv# cd /srv/
root@nowhere:/srv# torsocks git clone http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/gone-underground
```

then, edit your nginx website config to be as follows:

```sh
root@nowhere:/srv# cat /etc/nginx/sites-available/nowhere.conf
server {
        listen 80;
        listen [::]:80;
        server_name nowhere.moe;
        return 301 https://$server_name$request_uri;
}


server {
set $oniondomain "http://nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion";

        add_header Onion-Location $oniondomain always;
        ######## TOR CHANGES ########

        listen 443 ssl http2;
        listen [::]:443 ssl http2;
        server_name nowhere.moe;
        ssl_certificate /root/.acme.sh/nowhere.moe/fullchain.cer;
        ssl_certificate_key /root/.acme.sh/nowhere.moe/nowhere.moe.key;


# SSL Settings


        access_log  off;
            error_log off;


        ###### WE'VE GONE UNDERGROUND PART ####
        root /srv/gone-underground/;
        location / {
            try_files $uri /underground.php;
        }

        #location ~ ^(.*)$ {
        location ~ \.php$ {
            rewrite ^ /underground.php break;
            include snippets/fastcgi-php.conf;
            fastcgi_param X-Onion-Location $oniondomain;
            fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
        }

}
```

**Take note that the important part of this nginx config is the $oniondomain variable, as this is the onion mirror to which your audience will be redirected to.**

Then, if you didn't do it already, make sure that you get a HTTPS certificate for the clearnet presence of your website:

```sh
root@nowhere:/srv# wget -O -  https://get.acme.sh | sh
root@nowhere:/srv# acme.sh --set-default-ca  --server  letsencrypt
root@nowhere:/srv# acme.sh --issue --standalone -d  nowhere.moe -k 4096
```

Then, make sure that the nginx configuration is active:

```sh
root@nowhere:/srv# rm /etc/nginx/sites-*/default
root@nowhere:/srv# ln -s /etc/nginx/sites-available/nowhere.conf /etc/nginx/sites-enabled/
root@nowhere:/srv# nginx -s reload
```

And lastly check that the redirection is happening as expected:

![alt text](image.png)

As you can see, it redirected us to the onion mirror of the website properly:

![alt text](image-1.png)

And that's it! you now know how to redirect your clearnet audience to your darknet websites without weakening your operational security.
