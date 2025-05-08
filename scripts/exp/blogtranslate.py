#!/usr/bin/python3

# experimental script converting all blog posts into given language using ollama

import requests
import shutil
import os

LANG = 'spanish'
OLLAMA_HOST = 'http://ollama:11434/'
OLLAMA_MODEL = 'qwen3:1.7b'
OLLAMA_PROMPT = f'''Translate the blog post into {LANG}, keep the technical language as well as Linux commands in english. Keep the overall structure - source code tags, metadata key names (like "author", "title", "date", ...) but translate the values of metadata fields. Only output the translated blog.

For example this fragment:
```
---
author: XMRonly
title: "How to Get an Email Account Anonymously (Emails as a Service)"
date: 2024-10-16
description: "This blog post explains how to sign up for an anonymous email account using Proton Mail and Tor, focusing on privacy and avoiding personal information input. It highlights the limitations of traditional email and the need for privacy-focused alternatives.."
summary: "This blog post explains how to sign up for an anonymous email account using Proton Mail and Tor, focusing on privacy and avoiding personal information input. It highlights the limitations of traditional email and the need for privacy-focused alternatives.."
tags: ['email', 'anonymous', 'privacy', 'protonmail', 'tor', 'opsec']
ShowToc: true
TocOpen: true
editPost:
    URL: "http://git.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/nihilist/blog-contributions/issues/26"
    Text: "Suggest Changes"
    appendFilePath: false
---


![](../../assets/img/user.png) XMRonly - 2024 / 10 / 16

# How to Get an Email Account Anonymously (Emails as a Service)

![](0.png)



## **Introduction**

Email is one of the most widely used forms of online communication, both for personal and professional interactions. With billions sent daily, you would expect email to be secure, accessible, and readable by only the intended recipient. Unfortunately, email is an old technology and this is not always the case. With metadata being visible, large email providers scanning emails, as well as potential government surveillance in some parts of the world, it is no surprise that email is hardly considered private. As such, you may want to send an email that is not tied to your real identity. In this article, we will explore how to sign up for email account anonymously. Specifically, we will explore a privacy-focused email provider, **Proton Mail** , and how to sign up using Tor without inputting any additional information whatsoever.```

Should become:
```
---
author: XMRonly
title: "Cómo Obtener una Cuenta de Correo Electrónico Anónimamente (Servicios de Correo Electrónico)"
date: 2024-10-16
description: "Este artículo explica cómo registrarse para una cuenta de correo electrónico anónima utilizando Proton Mail y Tor, centrándose en la privacidad y evitando introducir información personal. Destaca las limitaciones del correo tradicional y la necesidad de alternativas centradas en la privacidad."
summary: "Este artículo explica cómo registrarse para una cuenta de correo electrónico anónima utilizando Proton Mail y Tor, centrándose en la privacidad y evitando introducir información personal. Destaca las limitaciones del correo tradicional y la necesidad de alternativas centradas en la privacidad."
tags: ['correo', 'anónimo', 'privacidad', 'protonmail', 'tor', 'opsec']
ShowToc: true
TocOpen: true
editPost:
    URL: "http://git.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/nihilist/blog-contributions/issues/26"
    Text: "Sugerir Cambios"
    appendFilePath: false
---

![](../../assets/img/user.png) XMRonly - 2024 / 10 / 16

# Cómo Obtener una Cuenta de Correo Electrónico Anónimamente (Servicios de Correo Electrónico)

![](0.png)

## **Introducción**

El correo electrónico es uno de los métodos más utilizados para la comunicación en línea, tanto en interacciones personales como profesionales. Con miles de millones enviados diariamente, se esperaría que el correo sea seguro, accesible y legible únicamente por el destinatario previsto. Desafortunadamente, el correo electrónico es una tecnología antigua y esto no siempre es el caso. Dado que la metadatos son visibles, los grandes proveedores de correo escanean correos electrónicos y existe la posibilidad de vigilancia gubernamental en algunas partes del mundo, no es sorprendente que el correo electrónico rara vez se considere privado. Como resultado, podrías querer enviar un correo electrónico que no esté vinculado a tu identidad real. En este artículo, exploraremos cómo registrarse para una cuenta de correo electrónica anónimamente. Específicamente, examinaremos un proveedor centrado en la privacidad, **Proton Mail**, y cómo registrarse usando Tor sin introducir ninguna información adicional.```'''

new_content_dir = f'content.{LANG}'

for root, _, files in os.walk('./content'):
    for fi in files:

        infpath = os.path.join(root, fi)
        outfpath = os.path.join(root.replace('./content', new_content_dir), fi)
        os.makedirs(os.path.dirname(outfpath), exist_ok=True)
    
        if fi != 'index.md':
            shutil.copy(infpath, outfpath)
            continue
        
        f = open(infpath, encoding='utf-8')
        fc = f.read()
        f.close()
        
        num_ctx = (int(len(fc)/(8192*2))+1)*8192

        r = requests.post(OLLAMA_HOST+'/api/generate', json={
          "model": OLLAMA_MODEL,
          "system": OLLAMA_PROMPT,
          "prompt": fc,
          "options": {"num_ctx": num_ctx, "seed": 14},
          "stream": False
        })

        resp = r.json()
        print(root, num_ctx, resp.get('prompt_eval_count', 0))
        
        fo = open(outfpath, 'w', encoding='utf-8')
        data = resp.get('response')
        startidx = data.index('</think>')+10
        fo.write(data[startidx:])
        fo.close()
