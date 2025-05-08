#!/bin/sh

# url-encode '%' char: https://github.com/gohugoio/hugo/issues/4586
sed -i 's/#51%_attack/#51%25_attack/g' ./content/posts/monerop2pool/index.md
