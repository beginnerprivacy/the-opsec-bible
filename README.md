# The Opsec Bible

## Work on blog posts

If you're here and want to contribute to our blog posts, you only need to fork and clone the [opsec-blogposts](http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/opsec-blogposts) repo.

```
$ git -c "http.proxy=socks5h://127.0.0.1:9050" clone "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/[you]/opsec-blogposts.git" --depth=1
```

We have a more detailed [contributing guide](http://opbible7nans45sg33cbyeiwqmlp5fu7lklu6jd6f3mivrjeqadco5yd.onion/opsec/contribute/) that will help you with later steps. It may be somewhat incomplete currently so I'll list some general steps you should consider while writing/editing markdown blog posts.

- the main file of each post's directory is `index.md`, you should also make references to `index.md` of other blog posts
  for example: `Do it like [we did before](../anonsms/index.md).`
- you should fill the metatags with necessary information about author and blog post in general:
  ```
  ---
  author: oxeo0
  date: 2025-05-16
  gitea_url: "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible/issues/278"
  xmr: 862Sp3N5Y8NByFmPVLTPrJYzwdiiVxkhQgAdt65mpYKJLdVDHyYQ8swLgnVr8D3jKphDUcWUCVK1vZv9u8cvtRJCUBFb8MQ
  ---

  # Blog post title
  ```
- you can preview markdown in VSCodium or other markdown editors. If you need to see how it would look on our blog, check the *Run the blog locally* section below.
- it's preferred to compress larger (>30kB) images to `AVIF` format using the [avifenc](https://manpages.debian.org/unstable/libavif-bin/avifenc.1.en.html) command:
  ```
  $ avifenc 0.png --yuv 420 --range l -q 50 -c svt --speed 0 --ignore-exif -o 0.png
  ```
  We'll handle that if you're unsure or face any problems with compression.
- Even though all issues should remain [on the main repository](http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible), you should make Pull Request to the [opsec-blogposts](http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/opsec-blogposts) repo once you're done with your contribution.

## Clone everything

Our blog consists of a few git submodules. To fully clone it, use the following command:
```
$ git -c "http.proxy=socks5h://127.0.0.1:9050" clone "http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/the-opsec-bible.git" --depth=1 --recursive --shallow-submodules
```

In case of `connection refused` error, make sure you have Tor daemon running in the background listening with `SocksPort 9050`.

The cloning process over the Tor network can take a while. Please be patient and try again in case of network issues.

We try to optimize the size of this repository and its submodules, currently those are:
```
26.31M the-opsec-bible
36.48M hacking
44.84M opsec
6.78M  productivity
33.10M selfhosting

147.5M total
```

## Run the blog locally

You need to install [mkdocs-material package](https://pkgs.org/search/?q=mkdocs-material) from your distro's repository or [from pip](https://squidfunk.github.io/mkdocs-material/getting-started/).

Maye sure you fetched all submodules as in previous step, then from the main directory run:
```
$ mkdocs serve
```

It should be served on `http://locahost:8000`

## Run the blog on the server

We have a [separate repo](http://gdatura24gtdy23lxd7ht3xzx6mi7mdlkabpvuefhrjn4t5jduviw5ad.onion/nihilist/blog-deploy) to run the blog post in **production environment** - with automatic updates and reverse proxy.

