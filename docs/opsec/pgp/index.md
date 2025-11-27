---
author:
  - cynthia (age)
  - nihilist (pgp)
date:
  - 2025-06-09
  - 2022-12-05
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/226"
xmr:
  - 84ybq68PNqKL2ziGKfkmHqAxu1WpdSFwV3DreM88DfjHVbnCgEhoztM7T9cv5gUUEL7jRaA6LDuLDXuDw24MigbnGqyRfgp
  - 8C1MNeB4KEHGApg6sPxFPn3NWERD3mPv7AjC8mCm1CJCXjoKnf36SYBdZ6ywCMdZRC4cxu7Uax3tufDqMXS2mLvHNCJzQZS
tags:
  - Core Tutorial
  - Serverside Privacy
---

# How to encrypt files and messages (Age and PGP)

```
TLDR: you can manually encrypt messages (E2EE) to ensure that no matter where you send them, only the recipient can read the contents of the message.
```

In this tutorial we're going to look at how to setup Age and PGP keys, and use them to encrypt messages 


![](../context/private_remote.png)



## Analogy

Bob wants to send a sensitive message to Alice. Bob intends to send his sensitive message to Alice through various means, for example on Teams, Discord or even on Wickr. However Bob knows that these service providers will never respect his privacy, they will always spy on Bob's conversation:

![](1.png)

Bob then decides that noone other than Alice will be able to decrypt his message. So, Bob decides to use some encryption tool, to be able to send a sensitive message to Alice **on any platform** he wishes, because he knows that only Alice will be able to decrypt it: 

![](2.png)

Why should you even care about encryption? Simple, you only want one person to be able to read your message, so you use an encryption tool. You can use it when you do not trust the chat platform you are using, or the email provider, or any other form of communication with text. They give you a simple way of encrypting your messages with others' public key, so that way you're sure that noone can read your messages.

## PGP

![](0.png)

### **Initial Setup**

Let's begin by generating your first key: 
    
    
    [ 10.8.0.3/24 ] [ nowhere ] [~]
    → gpg --gen-key
    gpg (GnuPG) 2.2.40; Copyright (C) 2022 g10 Code GmbH
    This is free software: you are free to change and redistribute it.
    There is NO WARRANTY, to the extent permitted by law.
    
    Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

    GnuPG needs to construct a user ID to identify your key.
    
    Real name: nihilist
    Email address: nihilist@nowhere.moe
    You selected this USER-ID:
        "nihilist <****nihilist@nowhere.moe>"
    
    Change (N)ame, (E)mail, or (O)kay/(Q)uit? o
    We need to generate a lot of random bytes. It is a good idea to perform
    some other action (type on the keyboard, move the mouse, utilize the
    disks) during the prime generation; this gives the random number
    generator a better chance to gain enough entropy.
    We need to generate a lot of random bytes. It is a good idea to perform
    some other action (type on the keyboard, move the mouse, utilize the
    disks) during the prime generation; this gives the random number
    generator a better chance to gain enough entropy.
    gpg: revocation certificate stored as '/home/nothing/.gnupg/openpgp-revocs.d/89C359E4110050AA5BDDEA3E0284FFC275D0931B.rev'
    public and secret key created and signed.
    
    pub   rsa3072 2022-12-05 [SC] [expires: 2024-12-04]
          89C359E4110050AA5BDDEA3E0284FFC275D0931B
    uid                      nihilist <****nihilist@nowhere.moe>
    sub   rsa3072 2022-12-05 [E] [expires: 2024-12-04]

Then we can list our keys like so:
    
    
    [ 10.8.0.3/24 ] [ nowhere ] [~]
    → gpg --list-keys
    /home/nothing/.gnupg/pubring.kbx
    --------------------------------
    pub   rsa3072 2022-12-05 [SC] [expires: 2024-12-04]
          89C359E4110050AA5BDDEA3E0284FFC275D0931B
    uid           [ultimate] nihilist <****nihilist@nowhere.moe>
    sub   rsa3072 2022-12-05 [E] [expires: 2024-12-04]
    
    
    #to list the key fingerprint:
    [ 10.8.0.3/24 ] [ nowhere ] [~]
    → gpg --fingerprint nihilist@nowhere.moe
    pub   rsa3072 2022-12-05 [SC] [expires: 2024-12-04]
          89C3 59E4 1100 50AA 5BDD  EA3E 0284 FFC2 75D0 931B
    uid           [ultimate] nihilist <****nihilist@nowhere.moe>
    sub   rsa3072 2022-12-05 [E] [expires: 2024-12-04]

Now let's export our public key like so:
    
    
    [ 10.8.0.3/24 ] [ nowhere ] [~]
    → gpg --output ~/nihilist.pubkey --armor --export nihilist@nowhere.moe
    
    [ 10.8.0.3/24 ] [ nowhere ] [~]
    → cat ~/nihilist.pubkey
    -----BEGIN PGP PUBLIC KEY BLOCK-----
    
    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
    5DG7X8sJauKPjhhHELWVrghx6GRTgjX9SLcZRQ==
    =B+QD
    -----END PGP PUBLIC KEY BLOCK-----
    	
    

This can be put publicly on your website, so that users will be able to encrypt their messages before sending it to you.

### **Encrypt/Decrypt messages**

Now let's encrypt our messages with alice's public key after she generates her pgp keys:
    
    
    [ 10.8.0.3/24 ] [ nowhere ] [~]
    → gpg --gen-key
    gpg (GnuPG) 2.2.40; Copyright (C) 2022 g10 Code GmbH
    This is free software: you are free to change and redistribute it.
    There is NO WARRANTY, to the extent permitted by law.
    
    Note: Use "gpg --full-generate-key" for a full featured key generation dialog.
    
    GnuPG needs to construct a user ID to identify your key.
    
    Real name: alice
    Email address: alice@nowhere.com
    You selected this USER-ID:
        "alice <****alice@nowhere.com>"
    
    Change (N)ame, (E)mail, or (O)kay/(Q)uit? o
    We need to generate a lot of random bytes. It is a good idea to perform
    some other action (type on the keyboard, move the mouse, utilize the
    disks) during the prime generation; this gives the random number
    generator a better chance to gain enough entropy.
    We need to generate a lot of random bytes. It is a good idea to perform
    some other action (type on the keyboard, move the mouse, utilize the
    disks) during the prime generation; this gives the random number
    generator a better chance to gain enough entropy.
    gpg: revocation certificate stored as '/home/nothing/.gnupg/openpgp-revocs.d/2A4ACCAC38F55DEE59EA38CBCA761853B6A47483.rev'
    public and secret key created and signed.
    
    pub   rsa3072 2022-12-05 [SC] [expires: 2024-12-04]
          2A4ACCAC38F55DEE59EA38CBCA761853B6A47483
    uid                      alice <****alice@nowhere.com>
    sub   rsa3072 2022-12-05 [E] [expires: 2024-12-04]
    	
    [ 10.8.0.3/24 ] [ nowhere ] [~]
    → gpg --output ~/alice.pubkey --armor --export alice@nowhere.com
    
    [ 10.8.0.3/24 ] [ nowhere ] [~]
    → cat ~/alice.pubkey
    -----BEGIN PGP PUBLIC KEY BLOCK-----
    
    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
    CdIDJHjajZtj14jc+uBRMMc=
    =up53
    -----END PGP PUBLIC KEY BLOCK-----

So let's first import alice's public key like so:
    
    
    [ 10.8.0.3/24 ] [ nowhere ] [~]
    → gpg --import alice.pubkey
    gpg: key CA761853B6A47483: "alice " not changed
    gpg: Total number processed: 1
    gpg:              unchanged: 1
    	
    

In order to make sure this is alice's public key, check the fingerprint of it:
    
    
    [ 10.8.0.3/24 ] [ nowhere ] [~]
    → gpg --fingerprint alice@nowhere.com
    pub   rsa3072 2022-12-05 [SC] [expires: 2024-12-04]
          2A4A CCAC 38F5 5DEE 59EA  38CB CA76 1853 B6A4 7483
    uid           [ultimate] alice <****alice@nowhere.com>
    sub   rsa3072 2022-12-05 [E] [expires: 2024-12-04]

Once you're sure that it is alice's public key, you can "sign it", which basically means that you trust that key:
    
    
    [ 10.8.0.3/24 ] [ nowhere ] [~]
    → gpg --sign-key alice@nowhere.com
    
    sec  rsa3072/CA761853B6A47483
         created: 2022-12-05  expires: 2024-12-04  usage: SC
         trust: ultimate      validity: ultimate
    ssb  rsa3072/7A75B89E1AA090CF
         created: 2022-12-05  expires: 2024-12-04  usage: E
    [ultimate] (1). alice 
    
    
    sec  rsa3072/CA761853B6A47483
         created: 2022-12-05  expires: 2024-12-04  usage: SC
         trust: ultimate      validity: ultimate
     Primary key fingerprint: 2A4A CCAC 38F5 5DEE 59EA  38CB CA76 1853 B6A4 7483
    
         alice 
    
    This key is due to expire on 2024-12-04.
    Are you sure that you want to sign this key with your
    key "nihilist " 
    
    Really sign? (y/N) y
    	
    

From there we can encrypt our message.txt:
    
    
    [ 10.8.0.3/24 ] [ nowhere ] [~]
    → vim message.txt
    
    [ 10.8.0.3/24 ] [ nowhere ] [~]
    → cat message.txt
    this is my very secret message !
    	
    

Before encrypting it, we can also sign it, although it is optional. There are 3 ways to sign the message:
    
    
    Create binary or ASCII-armored detached signature from input
    --detach-sign
    
    Wrap input in plaintext signature
    --clearsign
    
    Encode input into binary or ASCII-armored output with an integrated signature
    --sign
    	
    

To sign the message while also remaining in plaintext, we use the second option --clearsign (also, if you have multiple private keys like me, choose it with the -u flag to specify who is sending the message):
    
    
    [ 10.8.0.3/24 ] [ nowhere ] [~]
    → gpg -u nihilist@contact.nowhere.moe --clearsign message.txt
    
    [ 10.8.0.3/24 ] [ nowhere ] [~]
    → cat message.txt.asc
    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA256
    
    this is my very secret message !
    -----BEGIN PGP SIGNATURE-----
    
    iQHOBAEBCAA4FiEEicNZ5BEAUKpb3eo+AoT/wnXQkxsFAmOOR1waHG5paGlsaXN0
    QG5paGlsaXNtLm5ldHdvcmsACgkQAoT/wnXQkxubCwwAgxB2JIFz/vSewL0ScF1i
    K307GR4mNIyMy3VRgtuVdONau4X8p68tRS+wqoVRFB8GDLXTkzJsaULwghm8RQaV
    x0NOx60kgmXckP00uQM+ySDRqpHoVb5HYRqPrbOhJ6L1AFnexyhuhclvQoS4Zm0e
    PkvcMFaWOevQnbS8Vh2fVby4fsq5YdzSig4mu6KjQeR+Gu29xkAJp+lgMT1Ia0pL
    DVZaUw+AVHyaeQzdokdw0eoU01gl+dzPyaPamAGTbqI5Z7+DMOMgtgC9cpPP+26F
    jTpmq7fFxQ3fpAbEIlcahZzNBSyd1QGu6uKs/V4hqx4Fj7qg4puq+raxgg0JlyEZ
    greVnUYBONlTTIDgIKqI8D5iFhW6cCHQzXvYjLqCCuY35ZHP0TRkSycZaNjO1/4/
    EaNNvLm/uzi3+HhvPW57a9+bcGiVvTLhhje8sVUxioDd36DA4fYkd8BqBNkYvjRa
    e/D6QxqcdeK/RM0tUdlEsypp0KV3musGbyrYRhycEQPF
    =GuJm
    -----END PGP SIGNATURE-----
    
    

The signed message is saved as "message.txt**.asc** ", now let's encrypt it using alice's public key, and also don't forget to encrypt it with the private key you want with the -u flag again:
    
    
    [ 10.8.0.3/24 ] [ nowhere ] [~]
    → gpg --encrypt --sign --armor -u nihilist@contact.nowhere.moe -r alice@nowhere.com message.txt.asc
    
    [ 10.8.0.3/24 ] [ nowhere ] [~]
    → ls -lash | grep message
    4.0K -rw-r--r--  1 nothing nothing   33 Dec  5 19:03 message.txt
    4.0K -rw-r--r--  1 nothing nothing  741 Dec  5 19:13 message.txt.asc
    4.0K -rw-r--r--  1 nothing nothing 2.2K Dec  5 19:14 message.txt.asc.asc
    
    [ 10.8.0.3/24 ] [ nowhere ] [~]
    → cat message.txt.asc.asc
    -----BEGIN PGP MESSAGE-----
    
    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
    B8xjrEs=
    =kY62
    -----END PGP MESSAGE-----
    
    

The encrypted message is created as "message.txt.asc**.asc** ", so now we can send it to alice anywhere (teams, gmail, outlook, protonmail), wherever you want, **because only alice will be able to decode the message.** Once alice retrieves the message.txt.asc.asc she can decrypt it like so:
    
    
    [ 10.8.0.3/24 ] [ nowhere ] [~]
    → gpg -d message.txt.asc.asc
    gpg: encrypted with 3072-bit RSA key, ID 7A75B89E1AA090CF, created 2022-12-05
          "alice <****alice@nowhere.com>"
    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA256
    
    this is my very secret message !
    -----BEGIN PGP SIGNATURE-----
    
    iQHOBAEBCAA4FiEEicNZ5BEAUKpb3eo+AoT/wnXQkxsFAmOOR1waHG5paGlsaXN0
    QG5paGlsaXNtLm5ldHdvcmsACgkQAoT/wnXQkxubCwwAgxB2JIFz/vSewL0ScF1i
    K307GR4mNIyMy3VRgtuVdONau4X8p68tRS+wqoVRFB8GDLXTkzJsaULwghm8RQaV
    x0NOx60kgmXckP00uQM+ySDRqpHoVb5HYRqPrbOhJ6L1AFnexyhuhclvQoS4Zm0e
    PkvcMFaWOevQnbS8Vh2fVby4fsq5YdzSig4mu6KjQeR+Gu29xkAJp+lgMT1Ia0pL
    DVZaUw+AVHyaeQzdokdw0eoU01gl+dzPyaPamAGTbqI5Z7+DMOMgtgC9cpPP+26F
    jTpmq7fFxQ3fpAbEIlcahZzNBSyd1QGu6uKs/V4hqx4Fj7qg4puq+raxgg0JlyEZ
    greVnUYBONlTTIDgIKqI8D5iFhW6cCHQzXvYjLqCCuY35ZHP0TRkSycZaNjO1/4/
    EaNNvLm/uzi3+HhvPW57a9+bcGiVvTLhhje8sVUxioDd36DA4fYkd8BqBNkYvjRa
    e/D6QxqcdeK/RM0tUdlEsypp0KV3musGbyrYRhycEQPF
    =GuJm
    -----END PGP SIGNATURE-----
    gpg: Signature made Mon 05 Dec 2022 07:34:36 PM UTC
    gpg:                using RSA key 89C359E4110050AA5BDDEA3E0284FFC275D0931B
    gpg:                issuer "nihilist@nowhere.moe"
    gpg: Good signature from "nihilist <****nihilist@nowhere.moe>" [ultimate]

Once decrypted, she can see that the message has our PGP signature.

![](3.png)

And that's it! That covers the basics of how to use PGP


## Age

![](0a.png)

You may be thinking: what's the difference between PGP and Age? PGP is a traditional way of encrypting files and messages, while Age is meant to be a more modern alternative to PGP.

Age has really tiny keys (compared to PGP key sizes), uses modern cryptographic algorithms by default, while still being more secure and simpler to use than PGP.

### **Initial Setup**

Let's begin by installing age first.

```bash
root@localhost:~# apt install age
```

Generate your key and output the private key into a text file. We will be outputting the private and public key to a file named `key.txt`

```bash
bob@localhost:~$ age-keygen -o key.txt
Public key: age1gme6y93jm9nx7thzfu7ma8q7t0qhxae6m4r37m23f83d3phheejs25m8h0
```

Now we can give people the public key that age gave us. It can be put publicly on your website, so that users will be able to encrypt their messages before sending it to you.

The keys are so tiny, that if we want, we can encode the public key into a little QR code for people to scan

```bash
bob@localhost:~$ sudo apt install qrencode
bob@localhost:~$ qrencode -o pubkey_qr.png age1gme6y93jm9nx7thzfu7ma8q7t0qhxae6m4r37m23f83d3phheejs25m8h0
```

![](qr.png)

### **Encrypt/Decrypt messages**

Since age doesn't have the concept of a keyring like PGP, we have to store Alice's key somewhere in a text file to use.

```bash
alice@localhost:~$ age-keygen -o key.txt
Public key: age1y7gjjkrukaxzueae3dh60f57cn893d8y38vwh774kye7p8wm850q80ehvm
bob@localhost:~$ mkdir keyring/
bob@localhost:~$ echo "age1y7gjjkrukaxzueae3dh60f57cn893d8y38vwh774kye7p8wm850q80ehvm" > keyring/alice.txt
```

After this, we can encrypt our special file for Alice.

This special file will be a message in a text file.

```bash
bob@localhost:~$ vim message.txt
bob@localhost:~$ cat message.txt
This is a very secret message!
```

We can then encrypt the file with Alice's key.

```bash
bob@localhost:~$ age -R keyring/alice.txt -o encrypted_message --armor message.txt 
bob@localhost:~$ cat encrypted_message 
-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBjR29MQkg2UVQ2Q2VSbmlP
RmE0QzJ0d0NQQ2tEN2VaL2kxWEZEK2hqeGpZClFVNUNlbmJxL1E3dDNBaFFkbzhN
MnU4OHZneExGWk5pekdsWU9yNE5QeTAKLS0tIG0yWlMwMSs4cXM0Skg4UUtyOGJ2
b2paVnd1WkdLL1RDdDBJYWdHT3krQTAKL+g6Z7DKLXfmYfW4I3AT9HSimwixmLyx
D5Cc55tVZRk2BPj683U8wqSAZWqFoqJgu/97PCY/BvmBpX3KrnOc
-----END AGE ENCRYPTED FILE-----
```

Alternatively, we can also encrypt it in binary-mode, by omitting `--armor`

```bash
bob@localhost:~$ age -R keyring/alice.txt -o encrypted_message message.txt 
bob@localhost:~$ xxd encrypted_message 
00000000: 6167 652d 656e 6372 7970 7469 6f6e 2e6f  age-encryption.o
00000010: 7267 2f76 310a 2d3e 2058 3235 3531 3920  rg/v1.-> X25519 
00000020: 6337 3053 314c 6753 6767 5568 675a 3733  c70S1LgSggUhgZ73
00000030: 5030 426e 6442 7277 674c 6465 564e 4245  P0BndBrwgLdeVNBE
00000040: 5557 5473 3077 396b 5979 490a 3936 6236  UWTs0w9kYyI.96b6
00000050: 6378 5979 4734 7155 5a63 684c 5832 4b76  cxYyG4qUZchLX2Kv
00000060: 464d 4365 4f6c 5a45 5662 6d67 3936 696c  FMCeOlZEVbmg96il
00000070: 6b35 3164 3761 340a 2d2d 2d20 654c 6950  k51d7a4.--- eLiP
00000080: 544d 4e53 7a4f 6556 744e 644f 484a 5258  TMNSzOeVtNdOHJRX
00000090: 754f 7979 424d 3438 344a 612b 364c 4f6b  uOyyBM484Ja+6LOk
000000a0: 4a63 6d41 2f75 630a c9c7 7824 3919 06c8  JcmA/uc...x$9...
000000b0: ba74 5e39 5c89 118a 4091 3722 7741 f098  .t^9\...@.7"wA..
000000c0: 5d84 6af2 3cb8 03fa e7a6 8b84 1a20 bf7a  ].j.<........ .z
000000d0: e948 32c6 7db9 2f1f abed a677 d5fe 5b80  .H2.}./....w..[.
000000e0: ad2e 837b 5ed9 77                        ...{^.w
```

Alice can now download and decrypt this file with her key and get the messsage that Bob wanted to send her.

```bash
alice@localhost:~$ age --decrypt -i key.txt encrypted_message 
This is a very secret message!
```
