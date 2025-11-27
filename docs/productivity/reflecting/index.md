

# Reflecting: Brainstorming Ideas while on the run 

![](../../opsec/contribute/38.png)

## **Why is this important ?**

You may not always find all the best ideas while in front of your computer, maybe you're like me and you get ideas from time to time to problems that linger on without solutions for too long. Sometimes the solution to one of those problems just flashes in my mind while i'm at work, or while i'm outdoors. Lightning strikes wherever and you can't just predict it.

## **When you get a simple idea**

Maybe you just got a vague idea like this one:
    
    
    Protecting your Anonymity online by typing like a character (Stylometry)
    	
    

You could just tell yourself "alright i'll hang on to that idea until i get home", and if you're one of those memory atheletes you may remember it, but frankly i can't due to the amount of different topics i need to tackle each day for work, and for my personal projects.

So to make sure you don't forget it, go on your [grapheneOS phone](../../opsec/graphene/index.md), go in your [SimpleX Chat App](../../opsec/anonsimplex/index.md) and go into the chat called **"Private Notes":**

![](1.png)

Now this may look like a simple idea, but it will need to be brainstormed further when you get the time to dig into it back home like i did [here](https://git.nowhere.moe/nihilist/the-opsec-bible/issues/13#issuecomment-694).

## **When you get a complex idea**

And sometimes, you may have a flash of lightning with a complete flow of ideas that you need to write down immediately. When that is so, i usually just grab a piece of paper and i start making a todolist right off the bat like this one:
    
    
    Requires:
    -(at minimum 2 wan) dual wan config as showcased in https://blog.nowhere.moe/opsec/failover-wan/index.md
    -power failover setup as showcased in https://blog.nowhere.moe/opsec/failovers/index.md
    -linux homeserver https://blog.nowhere.moe/opsec/linux/index.md
    -qemu hypervisor https://blog.nowhere.moe/opsec/hypervisorsetup/index.md
    -pfsense qemu VM as showcased in https://blog.nowhere.moe/opsec/pf_virt/index.md
    -isolated LAN network for the VMs also as showcased in https://blog.nowhere.moe/opsec/pf_virt/index.md
    
    Starting from a setup where you have:
    -a pfsense VM
    -an isolated LAN network
    -and a debian VM in that LAN network
    -a HDD with a VC hidden volume of 100GB (pfsense 20gb, debian 60gb)
    
    To be showcased:
    -how to move that debian VM in a veracrypt hidden container (shut it down and then move it in there)
    -clone that debian VM to another debian VM B
    -rename debian VM A to "Tor bridge VM (with VPN)"
    -rename debian VM B to "hidden service VM 1"
    -setup mullvadVPN on that VM for a "serverside -> VPN -> tor -> clients" setup
    
    -Then mention the automating deniability protection w/ emergency shutdown script as showcased in https://blog.nowhere.moe/opsec/physicalsecurity/index.md
    
    -How to setup the firewall on the pfsense VM to only allow the "Tor Bridge VM (with VPN)" to access the WAN, and how to restrict any other host in the LAN network (such as the "Hidden service VM 1") to only access the "tor bridge VM"
    -then on the "tor bridge (with vpn) VM" setup the tor bridge, with a mullvad connection ( "serverside -> VPN -> tor -> clients" setup)
    
    -Then setup tor on the hidden service VM, and configure it to use the "tor bridge VM" as the bridge to connect to tor.
    -Then setup the actual hidden service (on some basic local nginx service on port 80) saying "welcome to blahblah.onion"
    
    

Or i might also just start drawing [graphs](../graphs/index.md) like this one on paper still:

![](../../opsec/torthroughvpn/1.png)

In case if you also work in IT like me, **DO NOT USE YOUR WORK COMPUTER FOR PERSONAL PROJECTS** , tackle personal projects either on your personal phone, or on a piece of paper that you'll fold and bring home with you. Make sure you always separate work life, and private life, **work topics on your work computer, and personal topics on your personal computer/phone.**

And then once you're at home, you can either open up your Simplex "Private Notes Chat", or unfold your piece of paper with your notes on it, to put your ideas in digital form into a [drawio graph](../graphs/index.md), or into a well-made todolist on the appropriate [gitea issue](https://git.nowhere.moe/nihilist/the-opsec-bible/issues/66#issuecomment-692).

And that's it! you're now able to grab a hold of your ideas wherever you go before you forget them, and bring them home into your projects, where they belong.

