---
author: nate
date: 2025-10-16
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/184"
xmr: 85f5DRfgFwwCz5Fg1HvRGjYHwUNnTuxNYNVy9SPTqm5GKUi9R7EoTGS4TuTjgC3s9w8aUgdeZdANA86s3rfdN3ppJYdAHrv
tags:
  - Clientside Anonymity
---
# Routing the network through Cloak using OpenWRT router 

This guide will showcase how to set up [Cloak](https://github.com/cbeuw/Cloak) on a OpenWRT router. 
If you are not using OpenWRT, [this Cloak tutorial](../cloak/index.md) _may_ be more suitable. 

To follow and apply this guide, you will need: 

* An [anonymously rented](../vps-deniability/index.md) remote server running Linux (preferrably Ubuntu or Debian) with an uncensored internet connection, with port TCP/443 reachable from the internet 
* A router or other gateway device running OpenWRT ([OpenWRT Tutorial](../openwrt/index.md)) 

### Why hide OpenVPN traffic? 
While OpenVPN traffic is encrypted, it is distinguishable.  OpenVPN can be detected with very few false-positives. 
This can be an issue in areas under the rule of authoritarian regimes, where VPN and proxy protocols (and Tor) may be [illegal or blocked](../toolslegality/index.md#vpns). 

To bypass detection and blocking of VPNs, we will use Cloak. 

### Why Cloak? 

* Cloak is a modern censorship-evasion tool that disguises proxied traffic as HTTPS connections 
* Cloak works in the countries with the most strict internet censorship (CN, RU, IR) 
* Cloak servers are difficult to identify, even with active scanning or probing 

![](../cloak/1.png)

## Part 1: Setting up the remote server

### Setting up OpenVPN server on the remote server

To use Cloak, you must first install proxy software on the server. 
This tutorial will use OpenVPN, we can use a quick setup script by running these commands via SSH: 

* *Note: While the script provided is [open source](../opsec/technologyserves/index.md#what-technologies-should-be-used), it's important to review the script before running it on your server.*

```
wget https://raw.githubusercontent.com/angristan/openvpn-install/refs/heads/master/openvpn-install.sh -O openvpn.sh
chmod +x openvpn.sh
sudo ./openvpn.sh
```

![](remote-server-login.png)


The script will ask for some configuration information, this is what was entered in this tutorial: 

* IP Address: 127.0.0.1 
* IPv6 Support: No (n) 
* OpenVPN Port: 1194 (1) 
* Protocol: TCP (2) 
* DNS: Current system resolvers (1) 
* Compression: No (n) 
* Customized encryption: No (n) 

![](openvpn-setup.png)


Once all the configuration information has been given, the script will install the necessary packages. 
After the script installs some packages, you will be prompted to create the OpenVPN client configuration, the client configuration will be named "openvpn" with a passwordless config. 

![](openvpn-first-user.png)


### Hiding the OpenVPN Server 
The OpenVPN server is now running on the remote server, but it could be discoverable from the internet. This OpenVPN server should only be accessed locally through the Cloak server, so we should disable direct access to the OpenVPN server from the internet. 

To disable direct access to the OpenVPN server, we will need to run some commands as root. 

```
echo "local 127.0.0.1" >> /etc/openvpn/server.conf

# We will also add this route to avoid modifying the OpenWRT routing configuration
# REPLACE 1.2.3.4 with the public IP address of the remote server

echo "push \"route 1.2.3.4 255.255.255.255 net_gateway\"" >> /etc/openvpn/server.conf
service openvpn restart
```

![](hide-openvpn.png)


We can now download the created OpenVPN configuration file, we will need it later.  You can do this easily using `sftp` and your SSH credentials: 

![](download-config.png)


The OpenVPN server should now be running on the remote server, without being exposed to the internet. 
Now, we can move on to the Cloak side of the setup. 

### Setting up the Cloak server on the remote server

Type `uname -m` to get the hardware type, we need it to know which version of Cloak server to download.

![](server-uname.png)


Next, we pick the corresponding `ck-server` from the [latest release of Cloak](https://github.com/cbeuw/Cloak/releases) and download it to the server, along with the example configuration. 
We will also need to generate keys and a UID for later, so we will do that too:

```
wget https://github.com/cbeuw/Cloak/releases/download/v2.12.0/ck-server-linux-amd64-v2.12.0 -O ck-server
wget https://raw.githubusercontent.com/cbeuw/Cloak/refs/heads/master/example_config/ckserver.json
chmod +x ck-server
./ck-server -key
./ck-server -uid
```

![](cloak-server-keys.png)


From this output, we get the following information:

* Public key: `ptyKrSt8gUQQyuP/d8VYBAcYt1OxV60pxdZ8f/3fx30=`
* Private key: `oBMLYV59+aEYZ1f7PO8/7NNvmFu2nq2EEbgZvGI8Xmc=`
* UID: `ZWBKXkASTyThlxBbj19gQA==`

Now we edit ckserver.json to add our keys, UID, and OpenVPN configuration information:

```
{
  "ProxyBook": {
    "shadowsocks": [
      "tcp",
      "127.0.0.1:8388"
    ],
    "openvpn": [
      "tcp",
      "127.0.0.1:1194"
    ],
    "tor": [
      "tcp",
      "127.0.0.1:9001"
    ]
  },
  "BindAddr": [
    ":443",
    ":80"
  ],
  "BypassUID": [
    "ZWBKXkASTyThlxBbj19gQA=="
  ],
  "RedirAddr": "www.bing.com",
  "PrivateKey": "oBMLYV59+aEYZ1f7PO8/7NNvmFu2nq2EEbgZvGI8Xmc=",
  "AdminUID": "",
  "DatabasePath": "userinfo.db"
}
```
`RedirAddr` determines what webpage is shown when a non-Cloak user tries to connect to the Cloak server. 
Non-Cloak traffic will be forwarded to `RedirAddr`. 

Now that the configuration is done, we can move ck-server and ckserver.json into different directories: 
```
mv ck-server /bin/ck-server
mkdir /etc/cloak
mv ckserver.json /etc/cloak/ckserver.json
```

To make sure that the Cloak server is always running, we can add a service file at `/etc/systemd/system/cloak.service`: 
```
[Unit]
Description=Cloak
After=network.target

[Service]
ExecStart=/bin/ck-server -c /etc/cloak/ckserver.json
WorkingDirectory=/etc/cloak
StandardOutput=journal
StandardError=journal
Restart=always
User=root
Group=root

[Install]
WantedBy=multi-user.target
```

Now we run the following commands to enable the service: 
```
sudo systemctl daemon-reload
sudo systemctl enable cloak.service
sudo systemctl start cloak.service
```

You can test if the server is running by executing `service cloak status` and seeing the output

![](cloak-service.png)



## Part 2: Setting up the OpenWRT router

### Setting up the Cloak client on the OpenWRT router

First, we need to access the router via SSH and type `uname -m` to get the hardware type (architecture).

![](openwrt-ssh.png)


Next we pick the corresponding `ck-client` from the [latest release of Cloak](https://github.com/cbeuw/Cloak/releases) and download it onto the router

* *Note: Make sure you download the correct architecture (`uname -m` on the **router**) of **Cloak client**!*

```
wget https://github.com/cbeuw/Cloak/releases/download/v2.12.0/ck-client-linux-arm-v2.12.0 -O /bin/cloak
chmod +x /bin/cloak
mkdir /etc/cloak
wget https://raw.githubusercontent.com/cbeuw/Cloak/refs/heads/master/example_config/ckclient.json -O /etc/cloak/ckclient.json
```

![](install-cloak-openwrt.png)


Now we edit `/etc/cloak/ckclient.json` on the router to add our configuration:
```
{
  "Transport": "direct",
  "ProxyMethod": "openvpn",
  "EncryptionMethod": "aes-gcm",
  "UID": "ZWBKXkASTyThlxBbj19gQA==",
  "PublicKey": "ptyKrSt8gUQQyuP/d8VYBAcYt1OxV60pxdZ8f/3fx30=",
  "ServerName": "www.bing.com",
  "NumConn": 4,
  "BrowserSig": "chrome",
  "StreamTimeout": 300
}
```

* EncryptionMethod should *NOT* be set to `plain`, or OpenVPN could be fingerprinted in your traffic to the Cloak server.  You should use `aes-gcm` or `chacha20-poly1305`  
* `ServerName` is the domain that is displayed in the unencrypted SNI, so any monitors or sensors see a connection to www.bing.com in this case.  Ideally, it should match `RedirAddr` in the Cloak server configuration on the remote server. 
* BrowserSig is the browser you will _appear_ to be using.  Current supported options are `chrome`, `firefox`, and `safari` 


Now we create the startup service for the Cloak client on the OpenWRT router, at `/etc/init.d/cloak`: 
```
#!/bin/sh /etc/rc.common
USE_PROCD=1
START=89 # Number in rc.d queue, before S90OpenVPN
#stops before networking stops
STOP=90
PROG=/bin/cloak
HOST="1.2.3.4" # HOST is the public IP address of the Cloak server
PORT="1194" # The port for Cloak client
CONFIG="/etc/cloak/ckclient.json"
start_service() {
procd_open_instance
procd_set_param user root
procd_set_param command "$PROG" -s "$HOST" -l "$PORT" -c "$CONFIG"
procd_set_param stdout 1
procd_set_param stderr 1
procd_set_param respawn ${respawn_threshold:-3600} ${respawn_timeout:-5} ${respawn_retry:-5}
procd_close_instance
echo "Cloak is working!"
}
stop_service() {
service_stop $PROG
echo "Cloak has stopped!"
}
reload_service() {
stop
sleep 5s
echo "Cloak restarted!"
start
}
```
Note: `PORT` is set to 1194 here to skip the step of modifying the OpenVPN client configuration file.  If you decide to use a different Cloak client port, you will need to change the port in the OpenVPN client configuration file (.ovpn) 

Now we run some commands to activate the Cloak service: 
```
chmod +x /etc/init.d/cloak
ln -s /etc/init.d/cloak /etc/rc.d/S89cloak
/etc/init.d/cloak start
service cloak enable
```

![](openwrt-enable-cloak.png)



### Setting up OpenVPN client on the OpenWRT router 

Log into the OpenWRT router as root using SSH, and run `opkg update && opkg install openvpn-openssl luci-app-openvpn`: 

![](openwrt-install-openvpn.png)


Next, open the OpenWRT router's web interface in the browser by typing the router's IP address into the search bar.  Log in as root and hover over the new "VPN" tab and select "OpenVPN" 

![](openwrt-navigate.png)


You should now see the OpenVPN configuration page.  At the bottom section, "OVPN configuration file upload", click "Browse" and go to the location you downloaded the `openvpn.ovpn` file to, and select it to be uploaded.

Name the instance "Cloak" and click the Upload button. 

![](upload-config.png)


**Warning: You will not have internet access during this part of the tutorial until the configuration is complete or until the OpenVPN client configuration is disabled** 

Now, go back to the OpenVPN page and check "Enabled" on the Cloak configuration and click "Save & Apply".  The page will refresh and Cloak will be started.  You will lose internet connectivity on all devices except the OpenWRT router.  

Now, hover over "Network" on the router navigation panel and choose "Interfaces"

![](navigate-interfaces.png)


Click "Add new interface..." and name it VPN

Leave protocol set to "DHCP Client", and set Device to "tun0"

![](create-interface.png)


Click "Create interface"

You will get another popup directing you to assign a firewall zone to the interface.  We will click the empty box at the bottom and create a new zone, also called VPN. 

![](create-firewall-zone.png)


Click save to exit the popup, then click "Save & Apply" at the bottom.

For the last steps, we have to configure the firewall zone.  Hover over "Network" in the navigation menu and select "Firewall"

![](navigate-firewall.png)


Click "Add" in the Zones menu to create a new zone, and configure it as follows:

![](zone-config-1.png)


Now move to "Advanced Settings" and set "Covered devices" to "tun0"

![](zone-config-2.png)


You may have to add "VPN" to the "Allow forward to *destination zones*" list on the LAN interface. 

**To prevent traffic leaks from the connected devices, you should remove WAN from this setting as well** 

* *This will block **DHCP clients** from accessing the internet without the VPN, even while it's disabled!*
* *This will **not** prevent the **router**, or programs running on it, from accessing the internet without the VPN!*
* *Add "WAN" back to this setting on the LAN interface to restore non-VPN internet access to other devices on the network.*

![](zone-config-optional.png)

## Checking the connection

1. Connect to the OpenVPN configuration on the OpenWRT web interface
2. Ensure zones are properly configured as above to avoid leaking unprotected traffic from connected devices
3. Connect the devices to the OpenWRT router
4. Run `curl ip-api.com` on a connected device to see your IP address (or you can go there in a web browser)
```
root@localhost:~# curl ip-api.com
{
  "status"       : "success",
  "continent"    : "Oceania",
  "continentCode": "OC",
  "country"      : "Australia",
  "countryCode"  : "AU",
  "region"       : "QLD",
  "regionName"   : "Queensland",
  "city"         : "South Brisbane",
  "district"     : "",
  "zip"          : "4101",
  "lat"          : -27.4767,
  "lon"          : 153.017,
  "timezone"     : "Australia/Brisbane",
  "offset"       : 36000,
  "currency"     : "AUD",
  "isp"          : "Resource Quality Assurance",
  "org"          : "Resource Quality Assurance",
  "as"           : "",
  "asname"       : "",
  "mobile"       : false,
  "proxy"        : true,
  "hosting"      : false,
  "query"        : "1.2.3.4"
}
```

## What can traffic observers see?

![](observers.png)

Observers can see TLS metadata, and attempt to infer the browser.  Our configuration will emulate a modern version of the Chrome browser. 
Traffic is split into (`NumConn`) different connections, making it difficult to detect patterns such as website fingerprints.
Also in the TLS metadata is the SNI, which contains `www.bing.com` as we set in the Cloak client configuration as `ServerName`. 
If the traffic observers decide to check the Cloak server, the Cloak server will open a connection to `RedirAddr` (www.bing.com) and proxy all non-Cloak traffic to `RedirAddr`, so the Cloak server will behave like the real website. 
