---
author: balkanaccc
date: 2025-07-15
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/183"
xmr: 89XfVm8BqWYTms5Ts4cKhr1xscf3mHW9LGjT3H7546TXW4dqeW425G4Fux548HVTTZPPJx6egQj2uCfiZwkn9uosChEBJ5R
---
# How to route your entire network through a VPN on the router

In this tutorial we're going to explain how to set up a VPN that covers the whole Local Area Network. Every device connected to LAN will automatically have its traffic routed through Mullvad VPN.

![](diagram.png)



## Setting up OpenWrt
Tutorial on setting up OpenWrt on your router is planned for the future: [How to have privacy on your router (OpenWrt)](http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/161).

## Installing WireGuard on the router
First of all, navigate to the OpenWrt panel on 192.168.1.1. After logging in to LuCI, navigate to **System** > **Software**. Click on the **Update lists...** button to run `opkg update` and refresh the available packages list.

After pulling the package list, search for `wireguard` in the package filter and look for `luci-app-wireguard`. Click **Install...** to install the wireguard package. Go to **System** > **Reboot** to reboot the router.

![](0.png)
## Downloading the Mullvad VPN configuration
Visit https://mullvad.net/en/account/wireguard-config to download a WireGuard configuration file from Mullvad. After generating a key, configure the exit location you want your router to connect through. Save the **.conf** file.

![](3.png)

## Creating a WireGuard interface
With the **.conf** file ready, log back into the router. Go to **Network** > **Interfaces** >> **Add new interface...**.

![](1.png) 

I will name our new VPN interface `wg0`, and set the protocol to **WireGuard VPN**. Click **Create interface**.

![](2.png)

Under the **General Settings** tab, paste the **PrivateKey** value from the configuration file into the **Private Key** field. Paste the IPv4 and IPv6 addresses separately from under **Address** into the **IP Adresses** fields.

![](4.png)

Under the **Advanced Setttings** tab, paste the **DNS** value from the configuration file into the **Use custom DNS servers** field.

![](10.png)

Click **Save & Apply**.

## Setting up the firewall
Go to **Network** > **Firewall** and click **Add**.

![](11.png)

Set the **Input**, **Output** and **Forward** to **accept**. Check the **Masquerading** and **MSS clamping** checkboxes. Set the **Covered networks** to **lan** and our WireGuard interface. Set **Allow forward to destination zones** to **wan**. Set **Allow forward from source zones** to **lan**.

![](12.png)

Click **Save**. Click **Save & Apply**.

## Configuring peers
Go to **Networking** > **Interfaces** and click **Edit** under our WireGuard interface. Under the **Peers** tab, click on **Add peer**. Add the **Description**, paste the **PublicKey** from the configuration file as well as the IPv4 and IPv6 adresses. Check the **Route Allowed IPs** checkbox. The **Endpoint** value consists of `IP`:`port`. Copy the IP address into the **Endpoint Host** field, and the port into the **Endpoint Port** field.

![](6.png)

Click **Save**. Click **Save & Apply**.

## Gateway metrics
Go back to **Network** > **Interfaces** and edit the **wg0** interface. Under **Advanced settings**, set **Use gateway metric** to `10`. Click **Save**.


Edit the **WAN** interface. Under **Advanced settings**, set **Use gateway metric** to `20`. Click **Save**.

Click **Save & Apply**.


## Verify the VPN connection
Go to https://mullvad.net/en/check from any device connected to your Local Area Network. You can verify that the traffic is going through Mullvad VPN.

![](9.png)


## Conclusion
Using OpenWrt is a hassle-free way to protect the whole Local Area Network with Mullvad VPN.
