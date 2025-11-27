---
author: MulliganSecurity
date: 2025-08-22
gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/407"
xmr: 82htErcFXbSigdhK9tbfMoJngZmjGtDUacQxxUFwSvtb9MY8uPSuYSGAuN1UvsXiXJ8BR9BVUUhgFBYDPvhrSmVkGneb91j
---

# Git LFS over Tor - Proof of Concept

## Abstract

[Git LFS](https://git-lfs.com/) (Large File Storage) is an extension to git as well as a specialized client. It aims to reduce the amount of space taken by a repository on an enduser machine, improve performance
and make handling binary files more efficient.

## Usecases
Somethines you will want to version non-text files in a git repository. Git being text-oriented this is usually a bad idea performance-wise. Yet the need could be:
- AI models
- Images and other media
- Other blobs that your repo needs at deployment time

## Architecture

![](lfs.png)

As exposed, text files are versioned under git as normal, large files (registered with git lfs to be stored within it) are uploaded separately and replaced with placeholders containing their hash in the main repo.
This allows the user to lazily download them based on need.


## Forgejo setup

In order to support LFS in forgejo one can either update the configuration file as follows:

~~~
[server]
LFS_START_SERVER = true
~~~

or pass the following environment variables:

~~~
FORGEJO__server__LFS_START_SERVER = true;
~~~

This can be done directly in a docker-compose file (woking with the one from the [forgejo tutorial](../forgejo-anon/index.md#forgejo-instance-setup):

```
services:
  server:
    image: codeberg.org/forgejo/forgejo:12
    container_name: forgejo
    environment:
      - USER_UID=1000
      - USER_GID=1000
      - FORGEJO__webhook__ALLOWED_HOST_LIST="alerter" # add this to enable the alerter
      - FORGEJO__server__LFS_START_SERVER=true;
    restart: unless-stopped
    networks:
      - forgejo
      - tor-forgejo
    volumes:
      - ./forgejo:/data
      - /etc/timezone:/etc/timezone:ro
      - /etc/localtime:/etc/localtime:ro
    ports:
      - "127.0.0.1:3009:3000"
      - "127.0.0.1:2222:22"
    # prevent dns leaks by setting dns server to a bogus address like localhost
    dns:
      - 127.0.0.1

  alerter:
    image: simplex-alerter:latest
    restart: unless-stopped
    volumes:
      - /my/alerter/data/folder:/alerterconfig
    networks:
      - forgejo
  tor-forgejo:
    image: osminogin/tor-simple
    restart: unless-stopped
    container_name: tor-forgejo
    volumes:
      - ./tor-data:/var/lib/tor
      - ./tor-data/torrc:/etc/tor
    networks:
      - tor-forgejo

networks:
  tor-forgejo:
  forgejo:
    external: false
```



### effects
- `LFS_START_SERVER`: enables LFS support

### Per-repo serverside configuration
No further configuration is required, now every repo will have git-lfs support.


## Client-setup

For this demonstration we will be working from a new repository. Before starting you will need to have created it in forgejo.


To make use of a git-lfs enable repository the user needs to install the git-lfs extension. On debian this is done by running:


```
[user@devnode:~]$ sudo apt install git-lfs
```


We will now test git lfs in a new repository for tracking various type of binary files:

~~~
[user@devnode:~/Documents]$ git init git_lfs_test
Initialized empty Git repository in /home/user/Documents/git_lfs_test/.git/
[user@devnode:~/Documents]$ cd git_lfs_test/

[user@devnode:~/Documents/git_lfs_test]$ git config user.name "lfstestuser"
[user@devnode:~/Documents/git_lfs_test]$ git config user.email "user@dev.null"
[user@devnode:~/Documents/git_lfs_test]$ git config http.proxy "socks5h://127.0.0.1:9050"

[user@devnode:~/Documents/git_lfs_test]$ git lfs install --local
Updated Git hooks.
Git LFS initialized.

[user@devnode:~/Documents/git_lfs_test]$ git commit -m "root commit" --allow-empty
[master (root-commit) 5f3d67e] root commit

[user@devnode:~/Documents/git_lfs_test]$ git lfs track "*.png" "*.webp" "*.jpg" "*.avif" "*.mp4" "*.webm"
Tracking "*.png"
Tracking "*.webp"
Tracking "*.jpg"
Tracking "*.avif"
Tracking "*.mp4"
Tracking "*.webm"

[user@devnode:~/Documents/git_lfs_test]$ cat .gitattributes 
*.png filter=lfs diff=lfs merge=lfs -text

[user@devnode:~/Documents/git_lfs_test]$ git add .gitattributes 

[user@devnode:~/Documents/git_lfs_test]$ git commit -m "register pngs for tracking"
[master 4b1ffbd] register pngs for tracking
 1 file changed, 1 insertion(+)
 create mode 100644 .gitattributes
~~~

Now that we have created the .gitattributes file, git-lfs will know to replace png files with pointers to the selfsame and upload them separately.

~~~
[user@devnode:~/Documents/git_lfs_test]$ cp ~/Documents/opsec-blogposts/forgejo-anon/0.png .

[user@devnode:~/Documents/git_lfs_test]$ git add 0.png 

[user@devnode:~/Documents/git_lfs_test]$ git commit -m "add png file"
[master cb9bfe3] add png file
 1 file changed, 3 insertions(+)
 create mode 100644 0.png

[user@devnode:~/Documents/git_lfs_test]$ git show HEAD 
commit cb9bfe3487130a81246dffd0a6999556eb07bbe6 (HEAD -> master)
Author: lfstestuser <user@dev.null>
Date:   Sat Aug 9 12:26:19 2025 +0200

    add png file

diff --git a/0.png b/0.png
new file mode 100644
index 0000000..69b64e6
--- /dev/null
+++ b/0.png
@@ -0,0 +1,3 @@
+version https://git-lfs.github.com/spec/v1
+oid sha256:afc78d10477909ac0dabd989141b66dc24cda3d07d903828b3d60da365ddef2f
+size 23701
~~~

As we can see, the binary file wasn't registered as is in the git repo, instead a pointer file was used.

We will also add multiple files to a single directory:

~~~
[user@devnode:~/Documents/git_lfs_test]$ mkdir various_files
[user@devnode:~/Documents/git_lfs_test]$ cp ../opsec-blogposts/forgejo-anon/1.png various_files/
[user@devnode:~/Documents/git_lfs_test]$ cp ../opsec-blogposts/forgejo-anon/2.png various_files/
[user@devnode:~/Documents/git_lfs_test]$ git add various_files/

[user@devnode:~/Documents/git_lfs_test]$ git commit -m "add multiple files"
[master 5f63094] add multiple files
 2 files changed, 6 insertions(+)
 create mode 100644 various_files/1.png
 create mode 100644 various_files/2.png

[user@devnode:~/Documents/git_lfs_test]$ git push
Locking support detected on remote "origin". Consider enabling it with:
  $ git config lfs.http://gitea2vyndora6imjfobo4rtnqylicqrncxjy34bb6v4zf56vlvz55yd.onion/midas/lfs_test.git/info/lfs.locksverify true
Uploading LFS objects: 100% (2/2), 51 KB | 0 B/s, done.

Enumerating objects: 6, done.
Counting objects: 100% (6/6), done.
Delta compression using up to 12 threads
Compressing objects: 100% (5/5), done.
Writing objects: 100% (5/5), 615 bytes | 615.00 KiB/s, done.
Total 5 (delta 0), reused 0 (delta 0), pack-reused 0 (from 0)
remote: . Processing 1 references
remote: Processed 1 references in total
To http://gitea2vyndora6imjfobo4rtnqylicqrncxjy34bb6v4zf56vlvz55yd.onion/midas/lfs_test.git
   a43b58f..5f63094  master -> master
~~~


Now let's push this data over to forgejo:

~~~
[user@devnode:~/Documents/git_lfs_test]$ git remote add origin http://[redacted].onion/midas/lfs_test.git
[user@devnode:~/Documents/git_lfs_test]$ git push --set-upstream origin master
Locking support detected on remote "origin". Consider enabling it with:
  $ git config lfs.http://[redacted].onion/midas/lfs_test.git/info/lfs.locksverify true
Uploading LFS objects: 100% (1/1), 24 KB | 0 B/s, done.

Enumerating objects: 8, done.
Counting objects: 100% (8/8), done.
Delta compression using up to 12 threads
Compressing objects: 100% (5/5), done.
Writing objects: 100% (8/8), 760 bytes | 760.00 KiB/s, done.
Total 8 (delta 0), reused 0 (delta 0), pack-reused 0 (from 0)
remote: . Processing 1 references
remote: Processed 1 references in total
To http://[redacted].onion/midas/lfs_test.git
 * [new branch]      master -> master
branch 'master' set up to track 'origin/master'.
~~~

When opening the repository in the browser, the file will appear normally:

![](example.png)

If one hovers over the data usage indication, they will see a breakdown of repo usage between git and lfs:

![](data_usage.png)


## New contributor setup

As a new contributor, one would initially clone the existing repository:

~~~
[user@devnode:~/Documents]$ git clone -c http.proxy="socks5h://127.0.0.1:9050" http://[redacted].onion/midas/lfs_test.git gitlfstest2
Cloning into 'gitlfstest2'...
remote: Enumerating objects: 8, done.
remote: Counting objects: 100% (8/8), done.
remote: Compressing objects: 100% (5/5), done.
remote: Total 8 (delta 0), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (8/8), done.
~~~

Without doing any other setup, this is what happens regarding git-lfs files: they do not get downloaded with the repo

~~~
[user@devnode:~/Documents]$ cd gitlfstest2/

[user@devnode:~/Documents/gitlfstest2]$ ls
0.png

[user@devnode:~/Documents/gitlfstest2]$ cat 0.png 
version https://git-lfs.github.com/spec/v1
oid sha256:afc78d10477909ac0dabd989141b66dc24cda3d07d903828b3d60da365ddef2f
size 23701
~~~


This is desired behavior, a user should only have to download the files they need.



Let's do a minimal configuration as a new contributor:

~~~
[user@devnode:~/Documents/gitlfstest2]$ git lfs install --local
Updated Git hooks.
Git LFS initialized.

[user@devnode:~/Documents/gitlfstest2]$ git lfs pull --include="0.png"
Downloading LFS objects: 100% (1/1), 24 KB | 0 B/s

[user@devnode:~/Documents/gitlfstest2]$ file 0.png 
0.png: ISO Media, AVIF Image

[user@devnode:~/Documents/gitlfstest2]$ git lfs pull --include="various_files"
Downloading LFS objects: 100% (2/2), 51 KB | 0 B/s


~~~

We now have downloaded the png file (through the git lfs pull command), and can modify it;

We could have downloaded all files by simply running `git lfs pull`

~~~
[user@devnode:~/Documents/gitlfstest2]$ git config user.name "contributor"

[user@devnode:~/Documents/gitlfstest2]$ git config user.email "contributor@dev.null"

[user@devnode:~/Documents/gitlfstest2]$ cp ../opsec-blogposts/forgejo-anon/10.png 0.png 

[user@devnode:~/Documents/gitlfstest2]$ git add 0.png 

[user@devnode:~/Documents/gitlfstest2]$ git commit -m "change image"
[master d45dabb] change image
 1 file changed, 2 insertions(+), 2 deletions(-)

[user@devnode:~/Documents/gitlfstest2]$ git show HEAD 
commit d45dabb7527368e249e82b145d4775619faad50a (HEAD -> master)
Author: contributor <contributor@dev.null>
Date:   Sat Aug 9 12:42:49 2025 +0200

    change image

diff --git a/0.png b/0.png
index 69b64e6..92d7e5f 100644
--- a/0.png
+++ b/0.png
@@ -1,3 +1,3 @@
 version https://git-lfs.github.com/spec/v1
-oid sha256:afc78d10477909ac0dabd989141b66dc24cda3d07d903828b3d60da365ddef2f
-size 23701
+oid sha256:41ed41f5bd24c4e84c32b61617cde55a84ea0569f64f06c99863010897c1de1c
+size 12101

[user@devnode:~/Documents/gitlfstest2]$ git push
Locking support detected on remote "origin". Consider enabling it with:
  $ git config lfs.https://gitea2vyndora6imjfobo4rtnqylicqrncxjy34bb6v4zf56vlvz55yd.onion/midas/lfs_test.git/info/lfs.locksverify true
Uploading LFS objects: 100% (1/1), 12 KB | 0 B/s, done.

Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Delta compression using up to 12 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 382 bytes | 382.00 KiB/s, done.
Total 3 (delta 0), reused 0 (delta 0), pack-reused 0 (from 0)
remote: . Processing 1 references
remote: Processed 1 references in total
To ssh://gitea2vyndora6imjfobo4rtnqylicqrncxjy34bb6v4zf56vlvz55yd.onion:2222/midas/lfs_test.git
   cb9bfe3..d45dabb  master -> master

~~~

Back in our first repository, if we pull the changes:

~~~
[user@devnode:~/Documents/gitlfstest2]$ cd ../git_lfs_test
[user@devnode:~/Documents/git_lfs_test]$ git pull
remote: Enumerating objects: 5, done.
remote: Counting objects: 100% (5/5), done.
remote: Compressing objects: 100% (3/3), done.
remote: Total 3 (delta 0), reused 0 (delta 0), pack-reused 0 (from 0)
Unpacking objects: 100% (3/3), 363 bytes | 363.00 KiB/s, done.
From ssh://gitea2vyndora6imjfobo4rtnqylicqrncxjy34bb6v4zf56vlvz55yd.onion:2222/midas/lfs_test
   cb9bfe3..d45dabb  master     -> origin/master
Updating cb9bfe3..d45dabb
Fast-forward
 0.png | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

[user@devnode:~/Documents/git_lfs_test]$ gwenview 0.png 
~~~

We get the new file without having to do any lfs-related command, because we already told our local repo that we were interested in keeping this one local and updated:

![](newimage.png)


## Conclusion
Git-lfs has matured a lot and can be used to handle repository growth more effectively when non-text files represent a significant fraction of the checked in files. It gives the option
to only download what files users are really interested in and only them.
