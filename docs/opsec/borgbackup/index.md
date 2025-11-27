---
author: oxeo0
date: 2025-08-29
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/321"
xmr: 862Sp3N5Y8NByFmPVLTPrJYzwdiiVxkhQgAdt65mpYKJLdVDHyYQ8swLgnVr8D3jKphDUcWUCVK1vZv9u8cvtRJCUBFb8MQ
tags:
  - Core Tutorial
  - Clientside Privacy
---

# Backup data remotely without revealing contents to the VPS provider - BorgBackup

```
TLDR: you can backup data to VPSes without allowing the vps provider to see the contents
```

![borgbackup logo](1.webp)

## Introduction

Having good, encrypted backups of your most sensitive data is always a good idea. In case your hardware gets seized, damaged, or you are forced to remove the data in an emergency, you should be able to restore it later.
We already discussed the need for backups in [another tutorial](../plausiblydeniabledataprotection/index.md).

In this one, we will use [borg backup](https://www.borgbackup.org/) to store an encrypted copy on an [anonymously rented VPS](../anonymousremoteserver/index.md).

## Why not rsync?

If you've read our Linux tutorial, you may know [rsync](../linuxbasics/index.md#rsync) utility. It can be used to synchronize local data with a remote server. However, rsync does **not handle client side encryption**. Your data is encrypted during transit (by both [SSH and Tor](../anonaccess/index.md)), but once it lands on a VPS, it is **unencrypted** - visible to the provider like in a [glass box](../cloud_provider_adversary/index.md#conclusion). Even if the disk on the remote VPS was encrypted, the provider can rather easily [extract the encryption keys](../cloud_provider_adversary/index.md#live-ram-extraction) from the RAM snapshot, and get access to your files.

This is commonly referred to as server-side encryption, and you can read more about its flaws [here](../serversideencryption/index.md#server-side-encryption-is-a-myth).

![graph illustrating what happens after your data is sent to provider - a glass box](2.avif)

## Client-side encryption

[Borg backup](https://www.borgbackup.org/) encrypts the data **before** they are being sent to the remote. You have full control over your encryption key, it should be stored in a safe place **locally** and without it - no one can see the data you have backed up.

Even though the provider can observe the metadata (like how big your backup is) - all they see is an encrypted blob of AES-256 encrypted data (we will demonstrate that [later on](#what-does-the-vps-provider-see)).

![graph illustrating how borg encrypts files before they are being sent](3.avif)

You can read more about borg security model on their [wiki page](https://borgbackup.readthedocs.io/en/stable/internals/security.html).

## Compression and deduplication

In addition to client-side encryption, borg also includes compression and deduplication features which help save bandwidth especially during incremental updates. Once a backup have been created and transferred to the remote VPS, it will not require you to upload the same files again.

## Prerequisites

It is assumed you have a [Debian-based OS](../linux/index.md) installed on your client machine with Tor service running:

```shell
user@mercury:~$ sudo apt update
user@mercury:~$ sudo apt install tor
user@mercury:~$ sudo systemctl enable --now tor
```

For the remote server, you should [rent it anonymously](../anonymousremoteserver/index.md) and configure [SSH hidden service](../homeserver-onion/index.md#method-1-ssh-over-onion-on-command-line) to access it.

## Installation

Borg should be included in [Debian](../linuxbasics/index.md#why-debian) repositories, we need to install it both on the VPS and local machine.

```shell
remote@pluto:~$ sudo apt update
remote@pluto:~$ sudo apt install borgbackup
```

```shell
user@mercury:~$ sudo apt update
user@mercury:~$ sudo apt install borgbackup netcat-openbsd
```

> `netcat-openbsd` package will be used to proxy ssh connection over Tor in later steps.

## SSH setup

Create identity on the client, it will be used to connect to the VPS with [public key authentication](https://help.ubuntu.com/community/SSH/OpenSSH/Keys):

```shell
user@mercury:~$ ssh-keygen -t ed25519
Generating public/private ed25519 key pair.
Enter file in which to save the key (/home/user/.ssh/id_ed25519): /home/user/.ssh/vpshost_id
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/user/.ssh/vpshost_id
Your public key has been saved in /home/user/.ssh/vpshost_id.pub
[...]
user@mercury:~$ cat ~/.ssh/vpshost_id.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINijxmQxk90OJF9Bg4NsiMJSxfnYFnTDE2hRcTCgCKdM user@mercury
```

Copy the public key we just generated, you need to place the key in `~/.ssh/authorized_keys` file to allow client connecting without entering password anymore.

```shell
remote@pluto:~$ mkdir ~/.ssh
remote@pluto:~$ vim ~/.ssh/authorized_keys
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINijxmQxk90OJF9Bg4NsiMJSxfnYFnTDE2hRcTCgCKdM
```

> You don't need to copy the username and server the key was generated at. Depending on your setup, this may contain sensitive info such as your user and client host name.

Now back on the client, create or add the server to your client ssh config similarly to what we did in 
[remote drive tutorial](../anondrive/index.md#client-configuration):
```shell
user@mercury:~$ vim ~/.ssh/config
Host vpshost
  ProxyCommand /bin/nc -xlocalhost:9050 -X5 %h %p
  User remote
  Hostname onionurlofyourvps.onion
  IdentityFile ~/.ssh/vpshost_id
  IdentitiesOnly yes
  Port 22
```

Here, the `Hostname` option should be an onion address of [SSH hidden service](../homeserver-onion/index.md#method-1-ssh-over-onion-on-command-line) you can reach your VPS on.

The `User` is the name of user you are logged in on the VPS as. Depending on your preference you may want to [create a separate user](../linuxbasics/index.md#creating-a-new-user) just for borg jobs. In this case, you need to copy the SSH public key to a `.ssh` directory within his home folder.

If everything is set up properly, your client machine can now SSH into the VPS without typing in the password like so:

```
user@mercury:~$ ssh vpshost
The authenticity of host 'onionurlofyourvps.onion (<no hostip for proxy command>)' can't be established.
ED25519 key fingerprint is [...].
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'onionurlofyourvps.onion' (ED25519) to the list of known hosts.
[...]
remote@pluto:~$ 
```

## Initializing the repository

To create a backup, we first need to create a Borg repository with an encryption password. It will be used to store encrypted backups on the remote.

Make sure to store this password somewhere separately, so that in case you loose access to your setup, you are able to restore from this backup.

```shell
user@mercury:~$ borg init --encryption=repokey vpshost:/home/remote/borgdata
Enter new passphrase: 
Enter same passphrase again: 
Do you want your passphrase to be displayed for verification? [yN]: N

By default repositories initialized with this version will produce security
errors if written to with an older version (up to and including Borg 1.0.8).

If you want to use these older versions, you can disable the check by running:
borg upgrade --disable-tam ssh://vpshost/home/remote/borgdata

See https://borgbackup.readthedocs.io/en/stable/changes.html#pre-1-0-9-manifest-spoofing-vulnerability for details about the security implications.

IMPORTANT: you will need both KEY AND PASSPHRASE to access this repo!
If you used a repokey mode, the key is stored in the repo, but you should back it up separately.
Use "borg key export" to export the key, optionally in printable format.
Write down the passphrase. Store both at safe place(s).
```

Borg informs us we need to export the key, so we will do that and also save it somewhere independent of our client machine:

```shell
user@mercury:~$ borg key export vpshost:/home/remote/borgdata
BORG_KEY dc8dce249ac53a09c6db0d9e707a649f2ad73c6d8aa754db03b6b2b000d70be7
hqlhbGdvcml0aG2mc2hhMjU2pGR[...]
```

Make sure to **really** think about recovery scenario. The password and the key should be stored separately (on a different machine, or in different physical location altogether).

In case you loose access to the client and do not have password **and** the key, you will **not be able to restore it from backup**.

## Creating backup manually

Let's say we want to back up some important stuff from our `~/Documents` directory:

```shell
user@mercury:~/Documents$ ls -la
total 36
drwxr-xr-x  5 user user  4096 Aug 25 20:46 .
drwx------ 16 user user  4096 Jun 22 13:30 ..
drwxr-xr-x  8 user user  4096 Jun  8 11:17 blog-contributions
drwxr-xr-x  8 user user  4096 Jun  8 11:04 darknet-lantern
-rw-------  1 user user  1653 Jun  8 11:30 secrets.kdbx
drwxr-xr-x  2 user user  4096 Jun  8 16:47 video-tutorials
```

To do that, you can use `borg create` command. You will be asked for the repo password we set earlier.

```shell
user@mercury:~$ borg create --verbose --progress --stats --compression zstd,9 vpshost:/home/remote/borgdata::vm1-backup-{now:%Y-%m-%d} ~/Documents/
```

The `{now:%Y-%m-%d}` part of backup name will automatically name your backup with current date. If you want to backup files more often than once a day, you may also include `%H-%M` switches. Be aware this may leak the timezone of your client to a remote host.

Additionally, I used `--compression zstd,9` to speed up transfer over Tor and save space on the remote. This flag is optional.

After your backup is done, borg will display a summary:

```shell
Repository: ssh://vpshost/home/remote/borgdata
Archive name: vm1-backup-2025-08-23
Archive fingerprint: f4ae4773193170306db3f6bd54a97a880299c4631819070836f2948c2b82d9f0
Time (start): Sat, 2025-08-23 20:30:34
Time (end):   Sat, 2025-08-23 20:41:49
Duration: 11 minutes 15.28 seconds
Number of files: 5773
Utilization of max. archive size: 0%
------------------------------------------------------------------------------
                       Original size      Compressed size    Deduplicated size
This archive:              525.73 MB            433.60 MB            428.18 MB
All archives:              525.72 MB            433.60 MB            428.46 MB

                       Unique chunks         Total chunks
Chunk index:                    5728                 5892
```

As you can see, the compression saved us almost 20% of backup space.

### Incremental backup

Now we will try creating a new file in `~/Documents` directory:

```shell hl_lines="6"
user@mercury:~/Documents$ ls -la
total 36
drwxr-xr-x  5 user user  4096 Aug 25 20:46 .
drwx------ 16 user user  4096 Jun 22 13:30 ..
drwxr-xr-x  8 user user  4096 Jun  8 11:17 blog-contributions
-rw-r--r--  1 user user 10707 Aug 23 20:46 borg-blog.md
drwxr-xr-x  8 user user  4096 Jun  8 11:04 darknet-lantern
-rw-------  1 user user  1653 Jun  8 11:30 secrets.kdbx
drwxr-xr-x  2 user user  4096 Jun  8 16:47 video-tutorials
```

And backing it up under new name in the same borg repository:

```shell hl_lines="11 16"
user@mercury:~$ borg create --verbose --progress --stats --compression zstd,9 vpshost:/home/remote/borgdata::vm1-backup-new-{now:%Y-%m-%d} ~/Documents/
Enter passphrase for key ssh://vpshost/home/remote/borgdata: 
Creating archive at "vpshost:/home/remote/borgdata::vm1-backup-new-2025-08-23"
------------------------------------------------------------------------------                                  

Repository: ssh://vpshost/home/remote/borgdata
Archive name: vm1-backup-new-2025-08-23
Archive fingerprint: 64054b4595b1431e107c423b84798902c7cfaf0d5eed629cbb4d5dc186d8de40
Time (start): Sat, 2025-08-23 20:50:53
Time (end):   Sat, 2025-08-23 20:50:54
Duration: 1.53 seconds
Number of files: 5774
Utilization of max. archive size: 0%
------------------------------------------------------------------------------
                       Original size      Compressed size    Deduplicated size
This archive:              525.74 MB            433.60 MB              5.45 kB
All archives:                1.05 GB            867.20 MB            428.61 MB

                       Unique chunks         Total chunks
Chunk index:                    5732                11785
```

As you can see, this time the backup took much less time since it only sent the files that actually changed.
This is called an [incremental backup](https://en.wikipedia.org/wiki/Incremental_backup).

## List existing backups

To list backups existing on the remote, we can use `borg list` command:

```shell
user@mercury:~$ borg list vpshost:/home/remote/borgdata
Enter passphrase for key ssh://vpshost/home/remote/borgdata: 
vm1-backup-2025-08-23                Sat, 2025-08-23 20:30:34 [f4ae4773193170306db3f6bd54a97a880299c4631819070836f2948c2b82d9f0]
vm1-backup-new-2025-08-23            Sat, 2025-08-23 20:50:53 [64054b4595b1431e107c423b84798902c7cfaf0d5eed629cbb4d5dc186d8de40]
```

## Restoring from a backup

Let's say the files on client side got deleted:

```shell
user@mercury:~$ ls -la ~/Documents/
total 8
drwxr-xr-x  2 user user 4096 Aug 23 21:48 .
drwx------ 18 user user 4096 Aug 23 21:48 ..
```

Now, we need to restore from a remote backup.

Since borg extracts backups relative to the current directory and contains full paths in the backup, we need to first go to the root directory of filesystem. This way files will be restored in a correct place.

```shell
user@mercury:~$ cd /
```

After this, use `borg extract` to restore backup from the remote back to the client.

```shell
user@mercury:/$ borg extract --verbose --progress vpshost:/home/remote/borgdata::vm1-backup-new-2025-08-23
Enter passphrase for key ssh://vpshost/home/remote/borgdata: 
 82.2% Extracting: home/user/Documents/video-tutorials/Make ANY Messaging Service E2E Encrypted With PGP.webm
```

After the extraction process is done, we can see the files again in `~/Documents` directory:

```shell
user@mercury:/$ ls -la ~/Documents/
total 36
drwxr-xr-x  5 user user  4096 Aug 25 20:46 .
drwx------ 18 user user  4096 Jun 22 22:35 ..
drwxr-xr-x  8 user user  4096 Jun  8 11:17 blog-contributions
-rw-r--r--  1 user user 10707 Aug 23 20:46 borg-blog.md
drwxr-xr-x  8 user user  4096 Jun  8 11:04 darknet-lantern
-rw-------  1 user user  1653 Jun  8 11:30 secrets.kdbx
drwxr-xr-x  2 user user  4096 Jun  8 16:47 video-tutorials
```

## Script for automatic backup creation

This script is adapted from the one in [official documentation](https://borgbackup.readthedocs.io/en/stable/quickstart.html#automating-backups). You can change the variables to match your preferred configuration.

Here, we also do `borg prune` to keep only certain amount of backups per day/week/month. This is useful since you don't need to keep very old backups with 1 day resolution, but backup from yesterday could be very useful.

```shell
#!/bin/sh

export BORG_REPO=vpshost:/home/remote/borgdata
export BORG_PASSPHRASE='BnPmnSfk3cxLoHSpnf7NzY'
BACKUP_NAME='vm1-backup'
LOCAL_DIR="/home/user/Documents"
KEEP_DAILY=1
KEEP_WEEKLY=5
KEEP_MONTHLY=6

info() { printf "\n%s %s\n\n" "$( date )" "$*" >&2; }
trap 'echo $( date ) Backup interrupted >&2; exit 2' INT TERM

info "Starting backup"

borg create --verbose --progress --stats --compression zstd,9 ::"$BACKUP_NAME"-{now:%Y-%m-%d} "$LOCAL_DIR"

backup_exit=$?

info "Pruning repository"

borg prune --list --glob-archives "$BACKUP_NAME-*" --keep-daily $KEEP_DAILY --keep-weekly $KEEP_WEEKLY --keep-monthly $KEEP_MONTHLY

prune_exit=$?

# actually free repo disk space by compacting segments

info "Compacting repository"

borg compact

compact_exit=$?

# use highest exit code as global exit code
global_exit=$(( backup_exit > prune_exit ? backup_exit : prune_exit ))
global_exit=$(( compact_exit > global_exit ? compact_exit : global_exit ))

if [ ${global_exit} -eq 0 ]; then
    info "Backup, Prune, and Compact finished successfully"
elif [ ${global_exit} -eq 1 ]; then
    info "Backup, Prune, and/or Compact finished with warnings"
else
    info "Backup, Prune, and/or Compact finished with errors"
fi

exit ${global_exit}
```

You can save this script in `~/backup-job.sh` and mark it as executable:

```shell
user@mercury:~$ chmod +x backup-job.sh
```

Then add it to crontab as such:

```shell
user@mercury:~$ crontab -e
0 10 * * * /home/user/backup-job.sh
```

This will make a backup to remote VPS every day at 10 am. If you don't know how that works, please refer to [crontab.guru](https://crontab.guru/) site.

## What does the VPS provider see

Let's check the `~/borgdata` directory from the remote VPS:

```shell
remote@pluto:~/borgdata$ find .
.
./README
./data
./data/0
./data/0/0
./data/0/1
./data/0/2
./data/0/3
./data/0/4
./data/0/5
./data/0/6
./data/0/7
./data/0/8
./data/0/9
./config
./nonce
./integrity.9
./hints.9
./index.9
./lock.roster

remote@pluto:~/borgdata$ cat README 
This is a Borg Backup repository.
See https://borgbackup.readthedocs.io/

remote@pluto:~/borgdata$ cat config 
[repository]
version = 1
segments_per_dir = 1000
max_segment_size = 524288000
append_only = 0
storage_quota = 0
additional_free_space = 0
id = dc8dce249ac53a09c6db0d9e707a649f2ad73c6d8aa754db03b6b2b000d70be7
key = hqlhbGdvcml0aG2mc2hhMjU2pGRhdGHaAN6YY...
```

As you can see, the data is partitioned into segments with sizes up to **500MB**. When we peek at such segment, we see the magic `BORG_SEG` and then **encrypted** data:

```shell
remote@pluto:~/borgdata$ hexdump -C data/0/2 | head -n 5
00000000  42 4f 52 47 5f 53 45 47  fa 5b 3b a3 9d 00 00 00  |BORG_SEG.[;.....|
00000010  00 0d 15 86 6f 32 b1 55  5a dc c6 63 70 fb 59 43  |....o2.UZ..cp.YC|
00000020  bd c8 9b ec f1 b1 b4 64  98 c9 31 bc 24 af 1e 6d  |.......d..1.$..m|
00000030  57 03 5b 68 88 45 cf 88  a3 9c dd ff d4 98 c0 e9  |W.[h.E..........|
00000040  55 db 95 6e 7a 46 64 3b  52 57 86 0b 0b 8e a1 82  |U..nzFd;RW......|
```

VPS provider has no way of knowing what the data actually contains.

## Conclusion

Congrats! You now know how to back up your files remotely with client-side encryption.

While this tutorial showcased the basics of borg, you may also want to read the [official documentation](https://borgbackup.readthedocs.io/en/stable/usage/general.html) of borg for more advanced setups.
