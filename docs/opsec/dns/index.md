---
author: nothing@nowhere
date: 2024-05-28
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/112"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
tags:
  - Serverside Anonymity
  - Clearnet Services
---
# bind9 DNS setup 

```
TLDR: you can setup bind9 to handle your clearnet domain records for all clearnet presence purposes. Even on anonymously-rented VPSes.
```

![](0.png)

In this tutorial we're going to take a look at how to setup DNS servers using bind9. 

_Disclaimer:_ If you want this service to remain anonymous, make sure you at least keep [TOR between you and the service](../sensitiveremotevshome/index.md) from the [VPS acquisition](../anonymousremoteserver/index.md) to actual service usage. 

![](../context/anon_remote.png)

## **Initial Setup**

First install the requirements:
    
    
    root@Temple:~# apt update -y ; apt upgrade -y ; apt install bind9 -y
    root@Temple:~# systemctl disable --now ufw	
    
    

Next we edit the /etc/bind/named.conf.options file to define which ip the dns server will serve:
    
    
    root@Temple:~# vim /etc/bind/named.conf.options	
    listen-on {
    	10.10.10.0/24;
    	10.1.0.0/16;
    	...
    };
    
    #OR
    listen-on { any; };
    listen-on-v6 { any; };
    
    

Next, we allow the queries to come from any sources (not just local)
    
    
    allow-query { any; };
    
    

and lastly, we add the forwarders which are the dns servers that bind9 will ask if it can't find the domain names, we can put cloudflare's dns servers for example:
    
    
    forwarders {
    	1.1.1.1;
    	1.0.0.1;
    };
    
    

Here's the result, save it with :wq
    
    
    options {
            directory "/var/cache/bind";
            dnssec-validation auto;
    
            listen-on-v6 { any; };
            listen-on { any; };
            allow-query { any; };
            forwarders {
                    1.1.1.1;
                    1.0.0.1;
            };
    };
    	
    

Then restart bind9:
    
    
    root@Temple:~# systemctl restart bind9
    root@Temple:~# systemctl status bind9
    ● named.service - BIND Domain Name Server
         Loaded: loaded (/lib/systemd/system/named.service; enabled; vendor preset: enabled)
         Active: active (running) since Tue 2021-11-02 20:37:26 UTC; 4s ago
           Docs: man:named(8)
       Main PID: 2863095 (named)
          Tasks: 8 (limit: 4584)
         Memory: 30.0M
         CGroup: /system.slice/named.service
                 └─2863095 /usr/sbin/named -f -u bind
    
    Nov 02 20:37:26 Temple named[2863095]: network unreachable resolving './NS/IN': 2001:500:12::d0d#53
    Nov 02 20:37:26 Temple named[2863095]: network unreachable resolving './NS/IN': 2001:500:2d::d#53
    Nov 02 20:37:26 Temple named[2863095]: network unreachable resolving './NS/IN': 2001:7fd::1#53
    Nov 02 20:37:26 Temple named[2863095]: network unreachable resolving './NS/IN': 2001:503:c27::2:30#53
    Nov 02 20:37:26 Temple named[2863095]: managed-keys-zone: Key 20326 for zone . is now trusted (acceptance timer complete)
    Nov 02 20:37:26 Temple named[2863095]: resolver priming query complete
    Nov 02 20:37:30 Temple named[2863095]: listening on IPv4 interface tun0, 10.8.0.1#53
    Nov 02 20:37:30 Temple named[2863095]: listening on IPv6 interface tun0, fe80::5822:e1cd:a277:e3e3%124941#53
    Nov 02 20:37:30 Temple named[2863095]: no longer listening on 10.8.0.1#53
    Nov 02 20:37:30 Temple named[2863095]: no longer listening on fe80::5822:e1cd:a277:e3e3%124941#53
    
    

and then finally we test if the dns works, let's ask our dns server for the ip address of google:
    
    
    [ 10.66.66.2/32 ] [ /dev/pts/20 ] [Nextcloud/blog]
    → nslookup google.com temple.yourdoma.in
    Server:         temple.yourdoma.in
    Address:        78.141.239.68#53
    
    Non-authoritative answer:
    Name:   google.com
    Address: 172.217.169.14
    Name:   google.com
    Address: 2a00:1450:4009:81d::200e
    	
    

And it worked ! Now let's setup an A record on our DNS server, for itself. To do that we need to specify the zones we're going to manage:
    
    
    
    root@Temple:/etc/bind# vim named.conf.local
    root@Temple:/etc/bind# cat named.conf.local
    //
    // Do any local configuration here
    //
    
    // Consider adding the 1918 zones here, if they are not used in your
    // organization
    include "/etc/bind/zones.rfc1918";
    
    root@Temple:~# vim /etc/bind/zones.rfc1918
    root@Temple:~# cat /etc/bind/zones.rfc1918
    zone "yourdoma.in"  {
            type master;
            file "db.yourdoma.in";
            allow-update { none; };
    };
    
    

Here we want to setup a subdomain of yourdoma.in so let's do it in the db.yourdoma.in file:
    
    
    $TTL    604800
    @       IN      SOA     ns1.yourdoma.in. yourdoma.in. (
                      3     ; Serial
                 604800     ; Refresh
                  86400     ; Retry
                2419200     ; Expire
                 604800 )   ; Negative Cache TTL
    ;
    ; name servers - NS records
                    3600     IN      NS      ns1.yourdoma.in.
                    3600     IN      NS      ns2.yourdoma.in.
    
    ; name servers - A records
    ns1.yourdoma.in.          IN      A      78.141.239.68
    ns2.yourdoma.in.          IN      A      45.76.133.0
    
    ; other hosts - A records
    host1.yourdoma.in.  IN      A       1.1.1.1
    host2.yourdoma.in.  IN      A       1.0.0.1	
    
    

And now we restart the bind9 service, and test if we can resolve the host1.yourdoma.in domain:
    
    
    root@Temple:/etc/bind# systemctl restart bind9
    root@Temple:/etc/bind# systemctl status bind9
    ● bind9.service - BIND Domain Name Server
         Loaded: loaded (/etc/systemd/system/bind9.service; enabled; vendor preset: enabled)
         Active: active (running) since Sun 2021-11-14 10:28:16 UTC; 51s ago
           Docs: man:named(8)
       Main PID: 3710 (named)
          Tasks: 8 (limit: 4582)
         Memory: 29.7M
         CGroup: /system.slice/bind9.service
                 └─3710 /usr/sbin/named -f -u bind
    
    Nov 14 10:28:16 Temple named[3710]: network unreachable resolving './NS/IN': 2001:500:2f::f#53
    Nov 14 10:28:16 Temple named[3710]: network unreachable resolving './NS/IN': 2001:7fd::1#53
    Nov 14 10:28:16 Temple named[3710]: network unreachable resolving './NS/IN': 2001:500:1::53#53
    Nov 14 10:28:16 Temple named[3710]: network unreachable resolving './NS/IN': 2001:500:a8::e#53
    Nov 14 10:28:16 Temple named[3710]: network unreachable resolving './NS/IN': 2001:500:9f::42#53
    Nov 14 10:28:16 Temple named[3710]: network unreachable resolving './NS/IN': 2001:dc3::35#53
    Nov 14 10:28:16 Temple named[3710]: network unreachable resolving './NS/IN': 2001:500:2::c#53
    Nov 14 10:28:16 Temple named[3710]: network unreachable resolving './NS/IN': 2001:503:ba3e::2:30#53
    Nov 14 10:28:16 Temple named[3710]: managed-keys-zone: Key 20326 for zone . is now trusted (acceptance timer complete)
    Nov 14 10:28:16 Temple named[3710]: resolver priming query complete
    	
    

To do that we use nslookup:
    
    
    [ 10.66.66.2/32 ] [ /dev/pts/115 ] [~]
    → nslookup host1.yourdoma.in temple.yourdoma.in
    Server:         temple.yourdoma.in
    Address:        78.141.239.68#53
    
    Name:   host1.yourdoma.in
    Address: 1.1.1.1
    	
    

Now we fill in the db file for the rest of the hosts we need, i'll post my complete config just for reference:
    
    
    root@Temple:/etc/bind# vim db.yourdoma.in
    root@Temple:/etc/bind# cat db.yourdoma.in
    $TTL    604800
    @       IN      SOA     ns1.yourdoma.in. yourdoma.in. (
                      7     ; Serial INCREMENT THIS EVERYTIME YOU EDIT THE FILE !!!!!!!!
                 604800     ; Refresh
                  86400     ; Retry
                2419200     ; Expire
                 604800 )   ; Negative Cache TTL
    ;
    ; name servers - NS records
                    3600     IN      NS      ns1.yourdoma.in.
                    3600     IN      NS      ns2.yourdoma.in.
    
    ; name servers - A records
    ns1.yourdoma.in.          IN      A      78.141.239.68
    ns2.yourdoma.in.          IN      A      45.76.133.0
    
    ; A records, public IPs
    temple       3600 IN A     78.141.239.68
    mail         3600 IN A     45.76.133.0
    mail         3600 IN AAAA  2001:19f0:7402:2c6:5400:3ff:fea7:22a3
    ;yourdoma.in
    
    
                 3600 IN MX 10 mail.yourdoma.in.
                 3600 IN TXT   "v=spf1 mx a:mail.yourdoma.in -all"
    _dmarc       3600 IN TXT   "v=DMARC1; p=reject; rua=mailto:dmarc@yourdoma.in; fo=1"
    
    autoconfig   3600 IN CNAME yourdoma.in.
    autodiscover 3600 IN CNAME yourdoma.in.
    
    asciinema    3600 IN CNAME yourdoma.in.
    blog         3600 IN CNAME yourdoma.in.
    chat         3600 IN CNAME yourdoma.in.
    cloud        3600 IN CNAME yourdoma.in.
    codimd       3600 IN CNAME yourdoma.in.
    cryptpad     3600 IN CNAME yourdoma.in.
    cyberchef    3600 IN CNAME yourdoma.in.
    ghostblog    3600 IN CNAME yourdoma.in.
    git          3600 IN CNAME yourdoma.in.
    gomez        3600 IN CNAME yourdoma.in.
    haste        3600 IN CNAME yourdoma.in.
    img          3600 IN CNAME yourdoma.in.
    irc          3600 IN CNAME yourdoma.in.
    jitsi        3600 IN CNAME yourdoma.in.
    kb           3600 IN CNAME yourdoma.in.
    kutt         3600 IN CNAME yourdoma.in.
    lady         3600 IN CNAME yourdoma.in.
    lain         3600 IN CNAME yourdoma.in.
    latex        3600 IN CNAME yourdoma.in.
    mind         3600 IN CNAME yourdoma.in.
    notes        3600 IN CNAME yourdoma.in.
    openproject  3600 IN CNAME yourdoma.in.
    pad          3600 IN CNAME yourdoma.in.
    privatebin   3600 IN CNAME yourdoma.in.
    pve          3600 IN CNAME yourdoma.in.
    routeur      3600 IN CNAME yourdoma.in.
    safe         3600 IN CNAME yourdoma.in.
    shells       3600 IN CNAME yourdoma.in.
    status       3600 IN CNAME yourdoma.in.
    sx           3600 IN CNAME yourdoma.in.
    test         3600 IN CNAME yourdoma.in.
    tube         3600 IN CNAME yourdoma.in.
    u            3600 IN CNAME yourdoma.in.
    www          3600 IN CNAME yourdoma.in.
    zabbix       3600 IN CNAME yourdoma.in.
    
    root@Temple:/etc/bind# systemctl restart bind9
    root@Temple:/etc/bind# systemctl status bind9
    ● bind9.service - BIND Domain Name Server
         Loaded: loaded (/etc/systemd/system/bind9.service; enabled; vendor preset: enabled)
         Active: active (running) since Sun 2021-11-14 11:37:30 UTC; 2s ago
           Docs: man:named(8)
       Main PID: 18839 (named)
          Tasks: 8 (limit: 4582)
         Memory: 29.3M
         CGroup: /system.slice/bind9.service
                 └─18839 /usr/sbin/named -f -u bind
    
    Nov 14 11:37:30 Temple named[18839]: network unreachable resolving './NS/IN': 2001:500:12::d0d#53
    Nov 14 11:37:30 Temple named[18839]: network unreachable resolving './NS/IN': 2001:500:a8::e#53
    Nov 14 11:37:30 Temple named[18839]: network unreachable resolving './NS/IN': 2001:500:1::53#53
    Nov 14 11:37:30 Temple named[18839]: network unreachable resolving './NS/IN': 2001:500:2::c#53
    Nov 14 11:37:30 Temple named[18839]: network unreachable resolving './NS/IN': 2001:500:2f::f#53
    Nov 14 11:37:30 Temple named[18839]: network unreachable resolving './NS/IN': 2001:503:ba3e::2:30#53
    Nov 14 11:37:30 Temple named[18839]: network unreachable resolving './NS/IN': 2001:500:200::b#53
    Nov 14 11:37:30 Temple named[18839]: network unreachable resolving './NS/IN': 2001:7fd::1#53
    Nov 14 11:37:30 Temple named[18839]: managed-keys-zone: Key 20326 for zone . is now trusted (acceptance timer complete)
    Nov 14 11:37:30 Temple named[18839]: resolver priming query complete
    	
    

Now, let's setup our secondary DNS server, first let's update the primary DNS server's zones.rfc1918 file as follows:
    
    
    root@Temple:/etc/bind# vim /etc/bind/zones.rfc1918
    root@Temple:/etc/bind# cat /etc/bind/zones.rfc1918
    zone "yourdoma.in" IN {
            type master;
            file "/etc/bind/db.yourdoma.in";
            allow-update { none; };
    
            allow-transfer { 45.76.133.0; };
            also-notify    { 45.76.133.0; };
    };
    	
    root@Temple:/etc/bind# systemctl restart bind9
    
    

In the allow-transfer and allow-notify parameters we put the public IP of our second DNS server. Next we restart bind9, and setup bind9 on the second server as a slave to our first server:
    
    
    root@mail:~# apt install bind9 -y
    root@mail:~# vim /etc/bind/named.conf.local
    root@mail:~# cat /etc/bind/named.conf.local
    //
    // Do any local configuration here
    //
    
    // Consider adding the 1918 zones here, if they are not used in your
    // organization
    include "/etc/bind/zones.rfc1918";
    
    root@mail:~# vim /etc/bind/zones.rfc1918
    root@mail:~# cat /etc/bind/zones.rfc1918
    zone "yourdoma.in" {
            type slave;
            file "/etc/bind/db.yourdoma.in";
            masters {78.141.239.68;};
    };
    
    root@mail:~# vim /etc/bind/db.yourdoma.in
    root@mail:~# cat /etc/bind/db.yourdoma.in
    $TTL    604800
    @       IN      SOA     ns2.yourdoma.in yourdoma.in. (
                      8     ; Serial INCREMENT THIS EVERYTIME YOU EDIT THE FILE !!!!!!!!
                 604800     ; Refresh
                  86400     ; Retry
                2419200     ; Expire
                 604800 )   ; Negative Cache TTL
    ;
    ; name servers - NS records
         IN      NS      ns1.yourdoma.in.
         IN      NS      ns2.yourdoma.in.
    
    ; name servers - A records
    ns1.yourdoma.in.          IN      A      78.141.239.68
    ns2.yourdoma.in.          IN      A      45.76.133.0
    
    ; A records, public IPs
    temple       3600 IN A     78.141.239.68
    mail         3600 IN A     45.76.133.0
    mail         3600 IN AAAA  2001:19f0:7402:2c6:5400:3ff:fea7:22a3
    ;yourdoma.in
    
    
                 3600 IN MX 10 mail.yourdoma.in.
                 3600 IN TXT   "v=spf1 mx a:mail.yourdoma.in -all"
    _dmarc       3600 IN TXT   "v=DMARC1; p=reject; rua=mailto:dmarc@yourdoma.in; fo=1"
    
    autoconfig   3600 IN CNAME yourdoma.in.
    autodiscover 3600 IN CNAME yourdoma.in.
    
    asciinema    3600 IN CNAME yourdoma.in.
    blog         3600 IN CNAME yourdoma.in.
    chat         3600 IN CNAME yourdoma.in.
    cloud        3600 IN CNAME yourdoma.in.
    codimd       3600 IN CNAME yourdoma.in.
    cryptpad     3600 IN CNAME yourdoma.in.
    cyberchef    3600 IN CNAME yourdoma.in.
    ghostblog    3600 IN CNAME yourdoma.in.
    git          3600 IN CNAME yourdoma.in.
    gomez        3600 IN CNAME yourdoma.in.
    haste        3600 IN CNAME yourdoma.in.
    img          3600 IN CNAME yourdoma.in.
    irc          3600 IN CNAME yourdoma.in.
    jitsi        3600 IN CNAME yourdoma.in.
    kb           3600 IN CNAME yourdoma.in.
    kutt         3600 IN CNAME yourdoma.in.
    lady         3600 IN CNAME yourdoma.in.
    lain         3600 IN CNAME yourdoma.in.
    latex        3600 IN CNAME yourdoma.in.
    mind         3600 IN CNAME yourdoma.in.
    notes        3600 IN CNAME yourdoma.in.
    openproject  3600 IN CNAME yourdoma.in.
    pad          3600 IN CNAME yourdoma.in.
    privatebin   3600 IN CNAME yourdoma.in.
    pve          3600 IN CNAME yourdoma.in.
    routeur      3600 IN CNAME yourdoma.in.
    safe         3600 IN CNAME yourdoma.in.
    shells       3600 IN CNAME yourdoma.in.
    status       3600 IN CNAME yourdoma.in.
    sx           3600 IN CNAME yourdoma.in.
    test         3600 IN CNAME yourdoma.in.
    tube         3600 IN CNAME yourdoma.in.
    u            3600 IN CNAME yourdoma.in.
    	
    www          3600 IN CNAME yourdoma.in.
    zabbix       3600 IN CNAME yourdoma.in.	
    
    
    
    
    root@mail:/etc/bind# systemctl restart bind9
    
    root@mail:/etc/bind# systemctl status bind9
    ● named.service - BIND Domain Name Server
         Loaded: loaded (/lib/systemd/system/named.service; enabled; vendor preset: enabled)
         Active: active (running) since Sun 2021-11-14 14:34:38 UTC; 1min 17s ago
           Docs: man:named(8)
       Main PID: 94005 (named)
          Tasks: 5 (limit: 2340)
         Memory: 17.8M
            CPU: 46ms
         CGroup: /system.slice/named.service
                 └─94005 /usr/sbin/named -f -u bind
    
    Nov 14 14:34:38 mail named[94005]: running
    Nov 14 14:34:38 mail named[94005]: zone yourdoma.in/IN: Transfer started.
    Nov 14 14:34:38 mail named[94005]: transfer of 'yourdoma.in/IN' from 78.141.239.68#53: connected using 45.76.133.0#53677
    Nov 14 14:34:38 mail named[94005]: zone yourdoma.in/IN: transferred serial 9
    Nov 14 14:34:38 mail named[94005]: zone yourdoma.in/IN: transfer: could not set file modification time of '/etc/bind/db.yourdoma.in': permission denied
    Nov 14 14:34:38 mail named[94005]: transfer of 'yourdoma.in/IN' from 78.141.239.68#53: Transfer status: success
    Nov 14 14:34:38 mail named[94005]: transfer of 'yourdoma.in/IN' from 78.141.239.68#53: Transfer completed: 1 messages, 49 records, 1118 bytes, 0.001 secs (1118000 bytes/sec) (serial 9)
    Nov 14 14:34:38 mail named[94005]: zone yourdoma.in/IN: sending notifies (serial 9)
    Nov 14 14:34:38 mail named[94005]: managed-keys-zone: Key 20326 for zone . is now trusted (acceptance timer complete)
    Nov 14 14:34:38 mail named[94005]: resolver priming query complete
    
    root@mail:/etc/bind# systemctl disable --now apparmor
    root@mail:/etc/bind# chown bind:bind -R /etc/bind
    
    root@mail:/etc/bind# systemctl restart bind9
    root@mail:/etc/bind# systemctl status bind9
    ● named.service - BIND Domain Name Server
         Loaded: loaded (/lib/systemd/system/named.service; enabled; vendor preset: enabled)
         Active: active (running) since Sun 2021-11-14 14:39:17 UTC; 1s ago
           Docs: man:named(8)
       Main PID: 94210 (named)
          Tasks: 4 (limit: 2340)
         Memory: 14.1M
            CPU: 29ms
         CGroup: /system.slice/named.service
                 └─94210 /usr/sbin/named -f -u bind
    
    Nov 14 14:39:17 mail named[94210]: running
    Nov 14 14:39:17 mail named[94210]: zone yourdoma.in/IN: Transfer started.
    Nov 14 14:39:17 mail named[94210]: transfer of 'yourdoma.in/IN' from 78.141.239.68#53: connected using 45.76.133.0#51509
    Nov 14 14:39:17 mail named[94210]: zone yourdoma.in/IN: transferred serial 9
    Nov 14 14:39:17 mail named[94210]: transfer of 'yourdoma.in/IN' from 78.141.239.68#53: Transfer status: success
    Nov 14 14:39:17 mail named[94210]: transfer of 'yourdoma.in/IN' from 78.141.239.68#53: Transfer completed: 1 messages, 49 records, 1118 bytes, 0.004 secs (279500 bytes/sec) (serial 9)
    Nov 14 14:39:17 mail named[94210]: zone yourdoma.in/IN: sending notifies (serial 9)
    Nov 14 14:39:17 mail named[94210]: dumping master file: /etc/bind/tmp-PF5Ud0HF2G: open: permission denied
    Nov 14 14:39:17 mail named[94210]: resolver priming query complete
    Nov 14 14:39:17 mail named[94210]: managed-keys-zone: Key 20326 for zone . is now trusted (acceptance timer complete)
    
    

And from there let's check if the domain name resolution works:
    
    
    [ 10.66.66.2/32 ] [ /dev/pts/115 ] [~]
    → nslookup ns1.yourdoma.in temple.yourdoma.in
    Server:         temple.yourdoma.in
    Address:        78.141.239.68#53
    
    Name:   ns1.yourdoma.in
    Address: 78.141.239.68
    
    
    [ 10.66.66.2/32 ] [ /dev/pts/115 ] [~]
    → nslookup ns2.yourdoma.in temple.yourdoma.in
    Server:         temple.yourdoma.in
    Address:        78.141.239.68#53
    
    Name:   ns2.yourdoma.in
    Address: 45.76.133.0
    
    
    [ 10.66.66.2/32 ] [ /dev/pts/115 ] [~]
    → nslookup ns2.yourdoma.in mail.yourdoma.in
    Server:         mail.yourdoma.in
    Address:        45.76.133.0#53
    
    Name:   ns2.yourdoma.in
    Address: 45.76.133.0
    
    
    [ 10.66.66.2/32 ] [ /dev/pts/115 ] [~]
    → nslookup ns1.yourdoma.in mail.yourdoma.in
    Server:         mail.yourdoma.in
    Address:        45.76.133.0#53
    
    Name:   ns1.yourdoma.in
    Address: 78.141.239.68
    	
    

Everything looks good, we can resolve domain names on both the master and slave DNS servers

## **Dynamic bind9 DNS setup**

Now for my current setup, i need my yourdoma.in domain name to resolve a public IP that often changes, therefore i need a dynamic bind9 DNS setup for the A record of my yourdoma.in domain. It is possible to set it up with bind9, so let's do it:
    
    
    oot@Temple:/etc/bind# apt install bind9utils
    root@Temple:/etc/bind# which ddns-confgen
    /usr/sbin/ddns-confgen
    
    	
    root@Temple:/etc/bind# ddns-confgen -s yourdoma.in
    # To activate this key, place the following in named.conf, and
    # in a separate keyfile on the system or systems from which nsupdate
    # will be run:
    key "ddns-key.yourdoma.in" {
            algorithm hmac-sha256;
            secret "Rq7gXz4Hu0AZYun6iX/ypbGRcS9W6GHqJiqksEvM8Nw=";
    };
    
    # Then, in the "zone" statement for the zone containing the
    # name "yourdoma.in", place an "update-policy" statement
    # like this one, adjusted as needed for your preferred permissions:
    update-policy {
              grant ddns-key.yourdoma.in name yourdoma.in ANY;
    };
    
    # After the keyfile has been placed, the following command will
    # execute nsupdate using this key:
    nsupdate -k <****keyfile>

Now that's done, we follow the instructions that the command just output for us, starting with named.conf.local edit:
    
    
    root@Temple:/etc/bind# vim /etc/bind/named.conf.local
    root@Temple:/etc/bind# cat /etc/bind/named.conf.local
    //
    // Do any local configuration here
    //
    
    // Consider adding the 1918 zones here, if they are not used in your
    // organization
    include "/etc/bind/zones.rfc1918";
    key "ddns-key.yourdoma.in" {
            algorithm hmac-sha256;
            secret "Rq7gXz4Hu0AZYun6iX/ypbGRcS9W6GHqJiqksEvM8Nw=";
    };	
    
    

Next, we setup the update-policy for our yourdoma.in zone:
    
    
    root@Temple:/etc/bind# vim zones.rfc1918
    root@Temple:/etc/bind# cat zones.rfc1918
    zone "yourdoma.in" {
            type master;
            file "/etc/bind/db.yourdoma.in";
    
            allow-transfer { 45.76.133.0; };
            also-notify    { 45.76.133.0; };
    
            update-policy {
              grant ddns-key.yourdoma.in name yourdoma.in ANY;
            };
    };
    
    root@Temple:/etc/bind# systemctl restart bind9
    
    

Now that's done, we're going to setup the dynamic DNS script on our client whose public IP is changing often:
    
    
    root@home:~# which nsupdate
    /usr/bin/nsupdate
    
    root@home:~# vim /etc/ddnssupdate.key
    root@home:~# cat /etc/ddnssupdate.key
    key "ddns-key.yourdoma.in" {
            algorithm hmac-sha256;
            secret "Rq7gXz4Hu0AZYun6iX/ypbGRcS9W6GHqJiqksEvM8Nw=";
    };
    	
    root@home:~# cd /var/www/yourdoma.in/
    root@home:/var/www/yourdoma.in# vim dyndns.sh
    root@home:/var/www/yourdoma.in# cat dyndns.sh
    #!/bin/bash
    
    #MYIP=$(dig +short myip.opendns.com @resolver1.opendns.com)
    MYIP=$(curl ifconfig.me)
    
    KEY=/etc/ddnsupdate.key
    NS=ns1.yourdoma.in
    DOMAIN=yourdoma.in.
    ZONE=yourdoma.in.
    
    nsupdate -k $KEY -v <****<****EOF
    server $NS
    zone $ZONE
    update delete $DOMAIN A
    update add $DOMAIN 30 A $MYIP
    send
    EOF

Now let's test it:
    
    
    root@home:/var/www/yourdoma.in# chattr -i /etc/resolv.conf
    root@home:/var/www/yourdoma.in# vim /etc/resolv.conf
    root@home:/var/www/yourdoma.in# cat /etc/resolv.conf
    #nameserver 1.1.1.1
    #nameserver 1.0.0.1
    nameserver 78.141.239.68
    nameserver 45.76.133.0
    root@home:/var/www/yourdoma.in# chattr +i /etc/resolv.conf
    
    root@home:/var/www/yourdoma.in# chmod +x dyndns.sh
    root@home:/var/www/yourdoma.in# ./dyndns.sh
      % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                     Dload  Upload   Total   Spent    Left  Speed
    100    14  100    14    0     0     89      0 --:--:-- --:--:-- --:--:--    89
    update failed: SERVFAIL
    
    

Now if you get this error, it probably means that the dns bind server does not have permissions to edit files in /etc/bind/, and rather has access to /var/lib/bind, so let's make those changes:
    
    
    root@Temple:/etc/bind# vim /etc/bind/zones.rfc1918
    root@Temple:/etc/bind# cat /etc/bind/zones.rfc1918
    zone "yourdoma.in" {
            type master;
            file "/var/lib/bind/db.yourdoma.in";
    
            allow-transfer { 45.76.133.0; };
            also-notify    { 45.76.133.0; };
    
            update-policy {
              grant ddns-key.yourdoma.in name yourdoma.in ANY;
            };
    };
    	
    root@Temple:/etc/bind# mv /etc/bind/db.yourdoma.in /var/lib/bind/
    root@Temple:/etc/bind# systemctl restart bind9
    
    

Now that's done, let's also do it on the secondary dns:
    
    
    root@mail:~# vim /etc/bind/zones.rfc1918
    root@mail:~# mv /etc/bind/db.yourdoma.in /var/lib/bind/
    root@mail:~# mv /etc/bind/db._domainkey.yourdoma.in /var/lib/bind/
    root@mail:~# systemctl restart bind9
    	
    

Now that's done, let's test our dynamic dns script: 
    
    
    root@home:/var/www/yourdoma.in# ./dyndns.sh
      % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                     Dload  Upload   Total   Spent    Left  Speed
    100    14  100    14    0     0     72      0 --:--:-- --:--:-- --:--:--    72
    root@home:/var/www/yourdoma.in#
    
    

No error messages, so let's check if our script updated the the zone file as intended:
    
    
    root@Temple:/etc/bind# cat /var/lib/bind/db.yourdoma.in
    $ORIGIN .
    $TTL 604800     ; 1 week
    yourdoma.in                 IN SOA  ns1.yourdoma.in. yourdoma.in. (
                                    10         ; serial
                                    604800     ; refresh (1 week)
                                    86400      ; retry (1 day)
                                    2419200    ; expire (4 weeks)
                                    604800     ; minimum (1 week)
                                    )
    $TTL 3600       ; 1 hour
                            NS      ns1.yourdoma.in.
                            NS      ns2.yourdoma.in.
    **$TTL 30 ; 30 seconds
                            A       92.148.147.119**
    $ORIGIN yourdoma.in.
    $TTL 3600       ; 1 hour
    _dmarc                  TXT     "v=DMARC1; p=reject; rua=mailto:dmarc@yourdoma.in; fo=1"
    asciinema               CNAME   yourdoma.in.
    
    [...]
    	
    

And it did! Now let's make sure our dynamic dns script runs every minute:
    
    
    root@home:/var/www/yourdoma.in# crontab -e
    * * * * * "/var/www/yourdoma.in/dyndns.sh"
    
    root@home:/var/www/yourdoma.in# cronitor select
    
    ✔ "/var/www/yourdoma.in/dyndns.sh"
    ----► Running command: "/var/www/yourdoma.in/dyndns.sh"
    
    [+] updating ns1.yourdoma.in:
    
    ----► ✔ Command successful    Elapsed time 0.353s
    	
    

Looks good! Now don't forget to edit the options file for your secondary dns server:
    
    
    root@mail:~# vim /etc/bind/named.conf.options
    root@mail:~# cat /etc/bind/named.conf.options
    
    options {
            directory "/var/cache/bind";
            dnssec-validation auto;
    
            listen-on-v6 { any; };
            listen-on { any; };
    
            allow-query { any; };
    
            forwarders {
                    1.1.1.1;
                    1.0.0.1;
            };
    };
    root@mail:~# systemctl restart bind9
    	
    

And that's it! We managed to setup 2 DNS servers using bind9 with a master-slave configuration along with dynamic DNS. Now if you want your DNS servers to propagate, you will have to wait:

![](1.png)

You can check the status of the DNS propagation on [this](https://www.dnstester.net/) website (wait a 24hours to propagate fully):

![](2.png)

you can check again after 24 hours:

![alt text](image.png)

As you can see, none of the major DNS servers around the world are aware of my ns1.yourdoma.in record, therefore i need to wait for my dns record to propagate (by setting the DNS server as the DNS servers for a particular domain, on a registrar):

## **DNSSEC Setup**

Once your dns records have propagated we can setup DNSSEC:
    
    
    root@mail-gw:~# vim /etc/bind/named.conf.options
    root@mail-gw:~# cat /etc/bind/named.conf.options
    options {
            directory "/var/cache/bind";
    
            //dnssec-validation yes;
            //dnssec-enable yes;
            //dnssec-lookaside auto; //since debian 12 these are no longer needed
    
            listen-on-v6 { any; };
            listen-on { any; };
            allow-query { any; };
            forwarders {
                    1.1.1.1;
                    1.0.0.1;
            };
    };
    	
    

Then generate the DNS keys for your domain:
    
    
    root@mail-gw:~# cd /var/cache/bind
    root@mail-gw:/var/cache/bind# dnssec-keygen -a NSEC3RSASHA1 -b 2048 -n ZONE nowhere.moe
    Generating key pair...................+++++ ..................................................................................................................+++++
    Knowhere.moe.+007+54398
    root@mail-gw:/var/cache/bind# dnssec-keygen -f KSK -a NSEC3RSASHA1 -b 4096 -n ZONE nowhere.moe
    Generating key pair........................................................................++++ .....................++++
    Knowhere.moe.+007+44145
    	
    

then create the zone file:
    
    
    root@mail-gw:/var/cache/bind# for key in `ls Knowhere.moe*.key`; do echo "\$INCLUDE $key">> nowhere.moe.zone; done
    root@mail-gw:/var/cache/bind# cat nowhere.moe.zone
    $INCLUDE Knowhere.moe.+007+44145.key
    $INCLUDE Knowhere.moe.+007+54398.key
    
    

Then sign the zone with the dnssec-signzone command:
    
    
    root@mail-gw:/var/cache/bind# for key in `ls Knowhere.moe*.key`; do echo "\$INCLUDE $key">> nowhere.moe.zone; done
    root@mail-gw:/var/cache/bind# cat nowhere.moe.zone
    $INCLUDE Knowhere.moe.+007+44145.key
    $INCLUDE Knowhere.moe.+007+54398.key
    root@mail-gw:/var/cache/bind# dnssec-signzone -A -3 $(head -c 1000 /dev/random | sha1sum | cut -b 1-16)			-N INCREMENT -o nowhere.moe -t nowhere.moe.zone
    
    
    dnssec-signzone: warning: Knowhere.moe.+007+44145.key:5: no TTL specified; zone rejected
    dnssec-signzone: fatal: failed loading zone from 'nowhere.moe.zone': no ttl
    
    

if you get the no ttl error like me, regen the keys with the TTL thanks to the -L flag:
    
    
    
    root@mail-gw:/var/cache/bind# dnssec-keygen -L 3600 -a NSEC3RSASHA1 -b 2048 -n ZONE nowhere.moe
    Generating key pair.........................................+++++ .......+++++
    Knowhere.moe.+007+35034
    
    root@mail-gw:/var/cache/bind# dnssec-keygen -L 3600 -f KSK -a NSEC3RSASHA1 -b 4096 -n ZONE nowhere.moe
    Generating key pair......++++ ..................................................................................................................................................................++++
    Knowhere.moe.+007+23388
    
    root@mail-gw:/var/cache/bind# for key in `ls Knowhere.moe*.key`; do echo "\$INCLUDE $key">> nowhere.moe.zone; done
    
    root@mail-gw:/var/cache/bind# cat nowhere.moe.zone
    
    $INCLUDE Knowhere.moe.+007+23388.key
    $INCLUDE Knowhere.moe.+007+35034.key
    
    root@mail-gw:/var/cache/bind# dnssec-signzone -A -3 $(head -c 1000 /dev/random | sha1sum | cut -b 1-16) -N INCREMENT -o nowhere.moe -t db.nowhere.moe
    dnssec-signzone: warning: db.nowhere.moe:17: TTL set to prior TTL (3600)
    dnssec-signzone: fatal: No signing keys specified or found.
    
    root@mail-gw:/var/cache/bind# cat nowhere.moe.zone >> db.nowhere.moe
    
    
    root@mail-gw:/var/cache/bind# dnssec-signzone -AA -n 3 -3 $(head -c 1000 /dev/urandom | sha1sum | cut -b 1-16)	-N INCREMENT -o nowhere.moe -t db.nowhere.moe
    
    dnssec-signzone: warning: db.nowhere.moe:17: TTL set to prior TTL (3600)
    Verifying the zone using the following algorithms:
    - NSEC3RSASHA1
    Zone fully signed:
    Algorithm: NSEC3RSASHA1: KSKs: 1 active, 0 stand-by, 0 revoked
                             ZSKs: 1 active, 0 stand-by, 0 revoked
    db.nowhere.moe.signed
    Signatures generated:                       51
    Signatures retained:                         0
    Signatures dropped:                          0
    Signatures successfully verified:            0
    Signatures unsuccessfully verified:          0
    Signing time in seconds:                 0.068
    Signatures per second:                 750.000
    Runtime in seconds:                      0.076
    	
    

If it gives you further errors, debug it here https://dnsviz.net/d/nowhere.moe/dnssec/:

Then we continue:
    
    
    root@mail-gw:/var/cache/bind# vim /etc/bind/named.conf.local
    root@mail-gw:/var/cache/bind# cat /etc/bind/named.conf.local
    zone "nowhere.moe"  {
            type master;
            file "db.nowhere.moe.signed";
            allow-update { none; };
    };
    	
    

Then restart bind9:
    
    
    root@mail-gw:/var/cache/bind# systemctl restart bind9
    root@mail-gw:/var/cache/bind# systemctl status bind9
    * named.service - BIND Domain Name Server
         Loaded: loaded (/lib/systemd/system/named.service; enabled; vendor preset: enabled)
         Active: active (running) since Fri 2022-09-30 19:58:12 CEST; 3s ago
           Docs: man:named(8)
       Main PID: 42611 (named)
          Tasks: 4 (limit: 507)
         Memory: 7.8M
            CPU: 19ms
         CGroup: /system.slice/named.service
                 `-42611 /usr/sbin/named -f -u bind
    
    Sep 30 19:58:12 mail-gw named[42611]: zone 127.in-addr.arpa/IN: loaded serial 1
    Sep 30 19:58:12 mail-gw named[42611]: zone localhost/IN: loaded serial 2
    Sep 30 19:58:12 mail-gw named[42611]: zone nowhere.moe/IN: sig-re-signing-interval less than 3 * refresh.
    Sep 30 19:58:12 mail-gw named[42611]: zone nowhere.moe/IN: loaded serial 18 (DNSSEC signed)
    Sep 30 19:58:12 mail-gw named[42611]: all zones loaded
    Sep 30 19:58:12 mail-gw named[42611]: running
    Sep 30 19:58:12 mail-gw named[42611]: zone nowhere.moe/IN: sending notifies (serial 18)
    Sep 30 19:58:12 mail-gw named[42611]: client @0x7fad306d5130 23.137.250.141#48501 (nowhere.moe): transfer of 'nowhere.moe/IN': IXFR version not in journal, falling back to AXFR
    Sep 30 19:58:12 mail-gw named[42611]: client @0x7fad306d5130 23.137.250.141#48501 (nowhere.moe): transfer of 'nowhere.moe/IN': AXFR-style IXFR started (serial 18)
    Sep 30 19:58:12 mail-gw named[42611]: client @0x7fad306d5130 23.137.250.141#48501 (nowhere.moe): transfer of 'nowhere.moe/IN': AXFR-style IXFR ended: 2 messages, 104 records, 19335 bytes, 0.001 secs (19335000 bytes/sec) (serial 18)
    

So from now on when you want to edit your zone, you will need to first edit the db file and then run the dnssign command: 
    
    
    root@mail-gw:/var/cache/bind# vim db.nowhere.moe
    
    root@mail-gw:/var/cache/bind# dnssec-signzone -AA -n 3 -3 $(head -c 1000 /dev/urandom | sha1sum | cut -b 1-16)	-N INCREMENT -o nowhere.moe -t db.nowhere.moe
    
    dnssec-signzone: warning: db.nowhere.moe:17: TTL set to prior TTL (3600)
    Verifying the zone using the following algorithms:
    - NSEC3RSASHA1
    Zone fully signed:
    Algorithm: NSEC3RSASHA1: KSKs: 1 active, 0 stand-by, 0 revoked
                             ZSKs: 1 active, 0 stand-by, 0 revoked
    db.nowhere.moe.signed
    Signatures generated:                       53
    Signatures retained:                         0
    Signatures dropped:                          0
    Signatures successfully verified:            0
    Signatures unsuccessfully verified:          0
    Signing time in seconds:                 0.068
    Signatures per second:                 779.411
    Runtime in seconds:                      0.080
    
    root@mail-gw:/var/cache/bind# systemctl restart bind9
    
    root@mail-gw:/var/cache/bind# systemctl status bind9
    * named.service - BIND Domain Name Server
         Loaded: loaded (/lib/systemd/system/named.service; enabled; vendor preset: enabled)
         Active: active (running) since Sat 2022-10-01 10:37:34 CEST; 1s ago
           Docs: man:named(8)
       Main PID: 45909 (named)
          Tasks: 4 (limit: 507)
         Memory: 7.8M
            CPU: 21ms
         CGroup: /system.slice/named.service
                 `-45909 /usr/sbin/named -f -u bind
    	
    

Now when we test the dnssec to our bindserver we see the following:
    
    
    [ 10.0.0.10/16 ] [ nowhere ] [~]
    → dig @23.137.250.140 stream.nowhere.moe. A +dnssec +multiline
    
    ; <<>> DiG 9.18.4-2-Debian <<>> @23.137.250.140 stream.nowhere.moe. A +dnssec +multiline
    ; (1 server found)
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<****- opcode: QUERY, status: NOERROR, id: 52175
    ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 1
    
    ;; OPT PSEUDOSECTION:
    ; EDNS: version: 0, flags: do; udp: 1232
    ; COOKIE: bb834e65ec1896a601000000633c65914ff2b9c6c7b43b1d (good)
    ;; QUESTION SECTION:
    ;stream.nowhere.moe. IN A
    
    ;; ANSWER SECTION:
    stream.nowhere.moe. 604800 IN CNAME web-gw.nowhere.moe.
    stream.nowhere.moe. 604800 IN RRSIG CNAME 7 3 604800 (
                                    20221103152726 20221004152726 35034 nowhere.moe.
                                    qIu/a2pi8e52tLqNBmCbeFHGK3TkQLquJNcziCoCYlQY
                                    qOOFiXisOz7sg05uWxvX04kKofQyuUb9X/+e20r28WUe
                                    gAhS1LJWE9BfBHfq/iQBXX4yWLTTYMqyjDyW56RUX7Z9
                                    zJs46TJB983ggZ1VwAJOifDGvl4vYSld/XeFy0EQy62G
                                    3Etq9GZe+O5ZEKsuYA+9RGockq/TwwLn6ibZfst172xt
                                    B/uKxmX+J3gcBzeGp1wwGd07UdlxaLyniQ41DSYmdTdD
                                    jECbxVQRvMnC1MhD8nYsmhm/YroKXeQpMX7ugJD1ZomY
                                    A7/ofGO6asXTGY2V3JxiITop0nKlfSlLbA== )
    web-gw.nowhere.moe. 604800 IN A 23.137.250.141
    web-gw.nowhere.moe. 604800 IN RRSIG A 7 3 604800 (
                                    20221103152726 20221004152726 35034 nowhere.moe.
                                    hlE0hXZiU9/LnSKghK3OKMxIbrrimFqF0HfHJubzQ50U
                                    f9g3m9bZJeANu4iJHCmPR1TVJUp0qYxUTRb815kWGKIq
                                    DHUNErDN+WhZoTBMT8jzdX8kntKFnd8+N/d/gjQ91Oxp
                                    MOGf2V1fAu0wnvVZGzn6PGmQfb1vsZ3pskmTd5bz/A1g
                                    nPoT3MXYWQol8x8h9bYdBwwz/cmbHbeZ2s8NIgFj/F46
                                    cciq3lIs6HDmmYzE50TQ5YApCyHDYSM7gu/u/O/4pxAP
                                    55Fo5qtkZQCMoRtcRJh+GG5X7W2onoi4zICAZXpD5L6z
                                    IaBl++bwjDaSIOiAsV2j+gRGETtUQ4Ef4w== )
    
    ;; Query time: 23 msec
    ;; SERVER: 23.137.250.140#53(23.137.250.140) (UDP)
    ;; WHEN: Tue Oct 04 18:56:01 CEST 2022
    ;; MSG SIZE  rcvd: 725

for simplicity sake i have this script to automate the signing of the dns zone file, the checking of it and the restarting of the service in one script:
    
    
    root@mail-gw:/var/cache/bind# cat restartdns.sh
    
    #!/bin/bash
    
    # check the zone for errors:
    named-checkzone nowhere.moe db.nowhere.moe
    
    # sign it:
    dnssec-signzone -AA -n 3 -3 $(head -c 1000 /dev/urandom | sha1sum | cut -b 1-16)        -N INCREMENT -o nowhere.moe -t db.nowhere.moe
    
    #restart bind9
    systemctl restart bind9
    
    #check bind9 status
    systemctl status bind9
    
    

updated restartdns.sh script: (thanks to Notorious from notlean.net)
    
    
    
    1) updated algorythms  to avoid errors **https://dnsviz.net/d/nowhere.moe/dnssec/**
    
    dnssec-keygen -L 3600 -a ECDSAP256SHA256 -b 2048 -n ZONE notlean.net
    dnssec-keygen -L 3600 -f KSK -a ECDSAP256SHA256 -b 2048 -n ZONE notlean.net
    for key in `ls Knotlean.net*.key`; do echo "\$INCLUDE $key">> notlean.net.zone; done
    cat notlean.net.zone >> forward.notlean.net.db
    dnssec-signzone -A -3 $(head -c 1000 /dev/random | sha1sum | cut -b 1-16) -N INCREMENT -o notlean.net -t forward.notlean.net.db
    rndc reload
    systemctl status named
    
    
    2) cat restartdns.sh 
    
    #!/bin/bash
    
    set -eu
    
    # Bnd Path
    ZONE_PATH="/var/cache/bind/notorious"
    
    # Domain name
    ZONE_NAME="notlean.net"
    
    # Bind zone file name
    ZONE_FILE="forward.notlean.net.db"
    
    # Generate NSEC3 salt
    NSEC3_SALT=$(head -c 1000 /dev/urandom | sha1sum | cut -b 1-16)
    
    # Go to zone path
    pushd $ZONE_PATH
    
    # Verify zone and check for errors
    echo "Chcking zone errors for $ZONE_NAME ..."
    if ! named-checkzone $ZONE_NAME $ZONE_FILE; then
        echo "Error during zonbe checking. Verify the file."
        exit 1
    fi
    
    # Signing zone DNSSEC
    echo "Signing zone file for $ZONE_NAME..."
    dnssec-signzone -A -3 $NSEC3_SALT -N INCREMENT -o $ZONE_NAME -t $ZONE_FILE
    
    # Restart BIND9
    echo "Restart BIND9..."
    rndc reload
    
    # Check bind status
    echo "Vérification du statut de BIND9..."
    systemctl status bind9
    
    # Back to local dir
    popd
    
    echo "Execution end"
    
    

