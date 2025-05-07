#!/bin/sh

apk add --no-cache git wget mkdocs-material py3-regex py3-requests py3-colorama

mkdir -p /repo
cd /repo
#rm -rf -- /repo/..?* /repo/.[!.]* /repo/*

while true; do
  echo "$(date): Cloning or updating the repository..."
  git config --global --add safe.directory /repo
  git config --global --add http.proxy socks5h://localhost:9050
  if [ -d "/repo/.git" ]; then
    git restore .
    git pull origin "${BRANCH}"
  else
    git clone -b "${BRANCH}" "${REPO_URL}" /repo
  fi;

  sed -i "s/^site_url:.*//g" /repo/mkdocs.yml
  echo "site_url: ${SITE_URL}" >> /repo/mkdocs.yml

  echo "Building mkdocs site..."
  # remove old contents
  rm -rf /servable/*
  ## do necessarry transition related fixes
  #sh blogfix.sh
  mkdocs build -d /servable
  sleep $REFRESH_SEC
done

