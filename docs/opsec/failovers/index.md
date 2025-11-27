---
author: nihilist
date: 2024-04-06
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/274"
xmr: 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
tags:
  - Serverside Deniability
  - Self-Hosted
  - High Availability
  - Core Tutorial
---
# Electrical Failover (basic UPS setup) 

```
TLDR: you can use a UPS to ensure that your home server remains online even if the adversary were to temporarily cut off the electricity where you live.
```

![](../context/sensitive_self.png)

**Threat Model:**

What if an adversary tells your electricity provider to temporarily power off your electricity to check if it manages to shut down a particular hidden service ? How do you ensure that your hidden service running at home remains accessible even without the main electrical input ?

![](0.png)

In this tutorial we'll look at the most fundamental part of both Disaster Recovery Planning and Business Continuity for home servers. We'll look at how to deal with power outages. 

![](1.png)

For the Electrical Outages, we'll setup a UPS in between our homeserver and the main electrical input, so that in case of a power outage the home server can keep running for a while before finally shutting down. The UPS will then send a message to the Network UPS Tools suite to tell the server to shutdown when the batteries run low. 



## **Electrical Outages - UPS setup**

Before buying a UPS, you need to know how much your home server can draw power (in watts), to make it simple just look at your power supply in your Homeserver. Mine is a RM 750x:

![](2.png)

and as explained in the technical specs, it can draw up to 750 Watts of power:

![](3.png)

So you need a UPS that can generate at least 750 Watts of power, such as the APC Back-UPS 1600VA:

![](4.png)

For my usecase, i picked that one because it can power my homeserver with the 900Watts it can output. Perfect for my server that can draw 750Watts.

First make sure your homeserver's plugged onto the UPS which is plugged onto the main electrical source. Then power on the homeserver, and after it booted, connect the serial to usb cable from the UPS to the homeserver, and you'll see it appear like so:
    
    
    [ Wonderland ] [ /dev/pts/3 ] [~]
    → lsusb
    
    [...]
    
    Bus 003 Device 003: ID 051d:0002 American Power Conversion Uninterruptible Power Supply
    
    [...]
    	
    

Then, let's install network ups tools (nut) and make it scan for any ups connected via UPS like ours:
    
    
    [ Wonderland ] [ /dev/pts/3 ] [~]
    → apt update -y ; apt install nut nut-client nut-server -y
    
    [ Wonderland ] [ /dev/pts/3 ] [~]
    → sudo nut-scanner -U
    Scanning USB bus.
    [nutdev1]
            driver = "usbhid-ups"
            port = "auto"
            vendorid = "051D"
            productid = "0002"
            product = "Back-UPS BX1600MI FW:378600G -302202G"
            serial = "DWAADWAWDWA"
            vendor = "American Power Conversion"
            bus = "003"
    	
    
    
    
    [ Wonderland ] [ /dev/pts/3 ] [~]
    → cat /etc/nut/upsmon.conf
    RUN_AS_USER root
    MONITOR apc-ups@localhost 1 admin secret master
    
    MINSUPPLIES 1
    SHUTDOWNCMD "/sbin/shutdown -h +0"
    POLLFREQ 5
    POLLFREQALERT 5
    HOSTSYNC 15
    DEADTIME 15
    POWERDOWNFLAG /etc/killpower
    RBWARNTIME 43200
    NOCOMMWARNTIME 300
    FINALDELAY 5
    
    [ Wonderland ] [ /dev/pts/3 ] [~]
    → cat /etc/nut/upsd.conf
    LISTEN 0.0.0.0 3493
    
    [ Wonderland ] [ /dev/pts/3 ] [~]
    → cat /etc/nut/nut.conf
    
    MODE=netserver
    
    
    [ Wonderland ] [ /dev/pts/3 ] [~]
    → cat /etc/nut/upsd.users
    [monuser]
            password = secret
            admin master
    	
    
    
    
    [ Wonderland ] [ /dev/pts/3 ] [~]
    → systemctl status nut-server nut-client nut-monitor
    ● nut-server.service - Network UPS Tools - power devices information server
         Loaded: loaded (/lib/systemd/system/nut-server.service; enabled; preset: enabled)
         Active: active (running) since Sat 2024-04-06 17:23:47 CEST; 5s ago
       Main PID: 707274 (upsd)
          Tasks: 1 (limit: 76930)
         Memory: 620.0K
            CPU: 2ms
         CGroup: /system.slice/nut-server.service
                 └─707274 /lib/nut/upsd -F
    
    Apr 06 17:23:47 wonderland systemd[1]: Started nut-server.service - Network UPS Tools - power devices information server.
    Apr 06 17:23:47 wonderland nut-server[707274]: fopen /run/nut/upsd.pid: No such file or directory
    Apr 06 17:23:47 wonderland nut-server[707274]: Could not find PID file '/run/nut/upsd.pid' to see if previous upsd instance is already running!
    Apr 06 17:23:47 wonderland nut-server[707274]: listening on 0.0.0.0 port 3493
    Apr 06 17:23:47 wonderland upsd[707274]: listening on 0.0.0.0 port 3493
    Apr 06 17:23:47 wonderland upsd[707274]: Connected to UPS [apc-ups]: usbhid-ups-apc-ups
    Apr 06 17:23:47 wonderland nut-server[707274]: Connected to UPS [apc-ups]: usbhid-ups-apc-ups
    Apr 06 17:23:47 wonderland nut-server[707274]: Running as foreground process, not saving a PID file
    Apr 06 17:23:47 wonderland upsd[707274]: Running as foreground process, not saving a PID file
    
    ● nut-monitor.service - Network UPS Tools - power device monitor and shutdown controller
         Loaded: loaded (/lib/systemd/system/nut-monitor.service; enabled; preset: enabled)
         Active: active (running) since Sat 2024-04-06 17:23:47 CEST; 5s ago
       Main PID: 707276 (upsmon)
          Tasks: 2 (limit: 76930)
         Memory: 836.0K
            CPU: 2ms
         CGroup: /system.slice/nut-monitor.service
                 ├─707276 /lib/nut/upsmon -F
                 └─707277 /lib/nut/upsmon -F
    
    Apr 06 17:23:47 wonderland systemd[1]: Started nut-monitor.service - Network UPS Tools - power device monitor and shutdown controller.
    Apr 06 17:23:47 wonderland nut-monitor[707276]: fopen /run/nut/upsmon.pid: No such file or directory
    Apr 06 17:23:47 wonderland nut-monitor[707276]: Could not find PID file to see if previous upsmon instance is already running!
    Apr 06 17:23:47 wonderland nut-monitor[707276]: UPS: apc-ups@localhost (primary) (power value 1)
    Apr 06 17:23:47 wonderland nut-monitor[707276]: Using power down flag file /etc/killpower
    Apr 06 17:23:47 wonderland nut-monitor[707277]: Init SSL without certificate database
    Apr 06 17:23:47 wonderland nut-monitor[707277]: Login on UPS [apc-ups@localhost] failed - got [ERR ACCESS-DENIED]
    
    ● nut-monitor.service - Network UPS Tools - power device monitor and shutdown controller
         Loaded: loaded (/lib/systemd/system/nut-monitor.service; enabled; preset: enabled)
         Active: active (running) since Sat 2024-04-06 17:23:47 CEST; 5s ago
       Main PID: 707276 (upsmon)
          Tasks: 2 (limit: 76930)
         Memory: 836.0K
            CPU: 2ms
         CGroup: /system.slice/nut-monitor.service
                 ├─707276 /lib/nut/upsmon -F
                 └─707277 /lib/nut/upsmon -F
    
    Apr 06 17:23:47 wonderland systemd[1]: Started nut-monitor.service - Network UPS Tools - power device monitor and shutdown controller.
    Apr 06 17:23:47 wonderland nut-monitor[707276]: fopen /run/nut/upsmon.pid: No such file or directory
    Apr 06 17:23:47 wonderland nut-monitor[707276]: Could not find PID file to see if previous upsmon instance is already running!
    Apr 06 17:23:47 wonderland nut-monitor[707276]: UPS: apc-ups@localhost (primary) (power value 1)
    Apr 06 17:23:47 wonderland nut-monitor[707276]: Using power down flag file /etc/killpower
    Apr 06 17:23:47 wonderland nut-monitor[707277]: Init SSL without certificate database
    Apr 06 17:23:47 wonderland nut-monitor[707277]: Login on UPS [apc-ups@localhost] failed - got [ERR ACCESS-DENIED]
    
    

We can check if the server can get all the 
    
    
    [ Wonderland ] [ /dev/pts/3 ] [~]
    → upsc apc-ups@localhost
    Init SSL without certificate database
    battery.charge: 100
    battery.charge.low: 10
    battery.mfr.date: 2001/01/01
    battery.runtime: 3167
    battery.runtime.low: 120
    battery.type: PbAc
    battery.voltage: 27.2
    battery.voltage.nominal: 24.0
    device.mfr: American Power Conversion
    device.model: Back-UPS BX1600MI
    device.serial: DDWAWADWADADW
    device.type: ups
    driver.name: usbhid-ups
    driver.parameter.pollfreq: 30
    driver.parameter.pollinterval: 1
    driver.parameter.port: auto
    driver.parameter.productid: 0002
    driver.parameter.serial: DWDADWAWDDWAADWDAW
    driver.parameter.synchronous: auto
    driver.parameter.vendorid: 051D
    driver.version: 2.8.0
    driver.version.data: APC HID 0.98
    driver.version.internal: 0.47
    driver.version.usb: libusb-1.0.26 (API: 0x1000109)
    input.sensitivity: medium
    input.transfer.high: 295
    input.transfer.low: 145
    input.voltage: 234.0
    input.voltage.nominal: 230
    ups.beeper.status: enabled
    ups.delay.shutdown: 20
    ups.firmware: 378600G -302202G
    ups.load: 10
    ups.mfr: American Power Conversion
    ups.mfr.date: 2022/02/08
    ups.model: Back-UPS BX1600MI
    ups.productid: 0002
    ups.realpower.nominal: 900
    ups.serial: DAWDWDAWADWADWDAWAD
    ups.status: OL
    ups.test.result: Done and passed
    ups.timer.reboot: 0
    ups.timer.shutdown: -1
    ups.vendorid: 051d
    
    

Now that the UPS is detected, we can install an interface for the nut service:
    
    
    [ Wonderland ] [ /dev/pts/3 ] [~]
    → apt install nut-cgi -y
    	
    [ Wonderland ] [ /dev/pts/3 ] [~]
    → vim /etc/nut/hosts.conf
    
    [ Wonderland ] [ /dev/pts/3 ] [~]
    → cat /etc/nut/hosts.conf
    
    MONITOR apc-ups@localhost "APC UPS - 1600VA"
    
    [ Wonderland ] [ /dev/pts/3 ] [~]
    → cat /etc/nut/upsset.conf
    I_HAVE_SECURED_MY_CGI_DIRECTORY
    
    [ Wonderland ] [ /dev/pts/3 ] [~]
    → apt install apache2 -y 
    
    [ Wonderland ] [ /dev/pts/3 ] [~]
    → a2enmod cgi
    Your MPM seems to be threaded. Selecting cgid instead of cgi.
    Enabling module cgid.
    To activate the new configuration, you need to run:
      systemctl restart apache2
    
    [ Wonderland ] [ /dev/pts/3 ] [~]
    → systemctl restart apache2
    
    

And now we can browse it from the web on port 80: the url is: **http://192.168.0.100/cgi-bin/nut/upsstats.cgi?host=apc-ups@localhost &treemode;**

![](6.png)

we can see the following graph to know the Battery Charge, Voltage, Input and Load:

![](7.png)

And for more details you can see the data tree:

![](8.png)

Now let's test if it works by unplugging the main electrical source:

![](11.png)

First thing you'll notice is the UPS starting to do a loud beep every 3 seconds, but you can see it in action from the web interface:

![](9.png)

Here as you can see the UPS is working on battery, and slowly the charge is being drained from 100% (now at 97% after 5 minutes) Of course it's being drained slowly due to being on a low load (18% currently), meaning it could last another 20 minutes of electrical outage easily.

