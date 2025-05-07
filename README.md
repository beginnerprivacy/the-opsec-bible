# Nihilist OPSEC blog
mkdocs-material markdown edition

# How to run

## Docker

To run the blog yourself, you'll need a Tor daemon running with socks5 proxy at `localhost:9050`. It will be used to clone/pull the repository from Docker container.

You also need an onionv3 domain and hidden service exposing `localhost:7080`as HTTP.

Download 3 files from the `deploy/` directory. You only need to edit the `SITE_URL` in `docker-compose.yml` to the vanity domain you generated.

Then run:
```
$ docker compose up -d && docker compose logs -f 
```
It will automatically clone the repository and start serving it with nginx on the URL you provided.

## Local development

You need to install [mkdocs-material package](https://pkgs.org/search/?q=mkdocs-material) from your distro's repository or [from pip](https://squidfunk.github.io/mkdocs-material/getting-started/).

Then from the main directory run:
```
$ mkdocs serve
```

It should be served on `http://locahost:8000`

