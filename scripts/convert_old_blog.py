import os
import re
import sys
import json
import shutil
import requests
import html2text

OLLAMA_HOST = 'http://ollama:11434/'
OLLAMA_PROMPT = """Analyze the blog post and give answer to following questions:
*   Who wrote it? (usually occurs at the beginning)
*   When was it written? (2001-12-30 format)
The response format should be JSON. You can not output anything else other than JSON. If the response can't be found, add `null` value. Here's an example how output should look like:
```
{"author": "nihilist", "date": "2024-03-01"}
```
Important: do not output anything else!
"""
NIHILIST_XMR = '8AUYjhQeG3D5aodJDtqG499N5jXXM71gYKD8LgSsFB9BUV1o7muLv3DXHoydRTK4SZaaUBq4EAUqpZHLrX2VZLH71Jrd9k8'
# make generation somewhat deterministic
OLLAMA_SEED = 17
OLLAMA_MODEL = 'gemma3:12b'

def is_webp(fpath: str) -> bool:
    with open(fpath, 'rb') as f:
        f.seek(8)
        return f.read(8) == b'WEBPVP8L'

def html_to_papermod(html_data: str) -> str:

    # try to find author, date and other metadata in html file
    
    h = html2text.HTML2Text()
    # disable random wrapping
    h.body_width = 0
    return h.handle(html_data)

def extract_blog_info(html_string: str) -> dict[str, str]:
    match = re.search(r'<p><img.*?<ba>(.*?)</ba>.*?<h1>(.*?)</h1>', html_string, re.DOTALL)

    user = None
    title = None
    if match:
        user = match.group(1).strip()
        title = match.group(2).strip()
    
    return user, title

def extract_git_issue_number(html_string: str) -> int:
    match = re.search(r'issues/(\d+)">git issue<', html_string)
    if match:
        return int(match.group(1))
    else:
        return 0

def extract_xmr_address(md_string: str) -> int:
    xmrs = re.findall(r":_.*([1-9A-HJ-NP-Za-km-z]{95})", md_string)
    print(xmrs)
    #xmrs = [x[-95:] for x in xmrs]
    try:
        # found 2 xmr addresses, extract the authors probable one
        if len(xmrs) == 2:
            xmrs.remove(NIHILIST_XMR)
    except:
        pass
    
    if len(xmrs) != 0:
        return xmrs[0]

    return None

def extract_blog_info_ai(md_string: str) -> dict[str, str]:
    print(f"Extracting info from {len(md_string)} bytes.")
    
    #num_ctx = 8192 if len(md_string) < (8192*2.5) else 16384
    #num_ctx = (int(len(md_string)/(8192*2.5))+1)*8192
    num_ctx = 2048
    
    r = requests.post(OLLAMA_HOST+'/api/generate', json={
      "model": OLLAMA_MODEL,
      "system": OLLAMA_PROMPT,
      "prompt": md_string[:1024],  # 1024 first bytes is enough
      "format": "json",
      "options": {"num_ctx": num_ctx, "seed": OLLAMA_SEED}, #len(md_string)//2},
      "stream": False
    })

    resp = r.json()
    if resp.get('prompt_eval_count', 0) == num_ctx:
        print('WARNING: LLM context saturated, may give wrong answer')

    return resp

# remove unnecessary header and footer, git issue reference, some other stuff
def do_markdown_fixes(md_string: str) -> str:
    
    # there are 3 paragraphs in the footer: Nihilism, My Links, About
    # some customize that tho
    for _ in range(3):
        foot_str = "#### "
        found_at = md_string.rfind(foot_str)
        #print('footer found at:', found_at)
        if found_at >= 0:
            md_string = md_string[:found_at]
        else:
            break
        
    # remove git issue reference from the issue
    git_regex = r'!\[\]\(\.\.\/logos\/daturagit\.png\).*?\s*directly!'
    md_string = re.sub(git_regex, "", md_string, flags=re.DOTALL)
        
    # remove header
    git_regex = r'\[The Nihilism Opsec Blog\].*?\s*\(\.\.\/index\.html\)'
    md_string = re.sub(git_regex, "", md_string, flags=re.DOTALL)
    
    # remove weird backticks html2text lefts sometimes after code blocks
    md_string = md_string.replace('\n`\n', '')
    
    # to make mkdocs happy, we replace all links to html to md. may break some links if external website uses index.html
    md_string = md_string.replace('/index.html', '/index.md')
    
    return md_string

def cut_until_title(md_string: str) -> str:
    return md_string[md_string.find('# '):]

def make_papermod_post(post_dir: str, md_string: str, blog_info: dict[str, str]) -> None:
    
    header = f"""---
author: {blog_info['author']}
date: {blog_info['date']}
gitea_url: "http://git.nowherejezfoltodf4jiyl6r56jnzintap5vyjlia7fkirfsnfizflqd.onion/nihilist/blog-contributions/issues/{blog_info.get('git', 0)}"
xmr: {blog_info['xmr']}
---
"""
    f = open(os.path.join(post_dir, 'index.md'), 'w', encoding='utf-8')
    f.write(header)
    f.write(md_string)
    f.close()

def walk_all_blogs(old_opsec_path: str) -> None:
    for root, _, files in os.walk(old_opsec_path):
    
        rel_name = root[root.find('opsec/')+6:]
        post_dir = os.path.join('./docs/opsec', rel_name)
        os.makedirs(post_dir, exist_ok=True)
        
        for fi in files:
            #print(fi)
            
            # skip the index site
            if os.path.basename(root) == '' and fi == 'index.html':
                continue
            
            if fi.endswith(('.png', '.jpg', '.jpeg', '.mp4')):
                #print(f"Copying asset {fi}")
                shutil.copy(os.path.join(root, fi), os.path.join(post_dir, fi))
                continue
            
            # only accept index.html at this point
            if not fi.endswith('.html'):
                continue

            f = open(os.path.join(root, fi), 'r', encoding='utf-8')
            fc = f.read()
            f.close()
            print(os.path.basename(root), extract_blog_info(fc))

            blog_info = {}
            blog_md_raw = html_to_papermod(fc)
            blog_info['git'] = extract_git_issue_number(fc)
            blog_info['xmr'] = extract_xmr_address(blog_md_raw)

            # remove unnecessary stuff we'll include anyway in hugo
            blog_md = do_markdown_fixes(blog_md_raw)
            
            ai_extract = extract_blog_info_ai(blog_md)
            print(ai_extract.get('response'), ai_extract.get('prompt_eval_count'))
            
            blog_md = cut_until_title(blog_md)
            
            try:
                blog_info.update(json.loads(ai_extract.get('response')))
                if blog_info['date'] in ('0000-00-00', None):
                    blog_info['date'] = '2001-01-30'
                # in case model acts dumb
                blog_info['date'] = blog_info['date'].replace('/', '-')
                make_papermod_post(post_dir, blog_md, blog_info)
            except Exception as e:
                print(e)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: convert_old_blog.py /path/to/blog-contributions/opsec')
        exit(1)
    old_opsec_path = sys.argv[1]
    walk_all_blogs(old_opsec_path)
