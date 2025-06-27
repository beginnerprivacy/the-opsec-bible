# this is meant to be run from blog-deploy/entry.sh script
# running it manually requires SITE_URL env variable to be set to your blog url

import os
import sys
import feedgen.feed
import datetime
import yaml

def extract_metadata(md_path):

    with open(md_path, 'r', encoding='utf-8') as f:
        content = f.read()

    parts = content.split('---', 2)
    
    if len(parts) >= 2:
        try:
            front_matter = yaml.safe_load(parts[1])
            return front_matter
        except yaml.YAMLError:
            print(f"Failed to parse markdown from file: {md_path}")

def generate_rss_feed(index_file, output_file, base_url):

    fg = feedgen.feed.FeedGenerator()
    fg.title('OPSEC Bible')
    fg.link(href=base_url, rel='alternate')
    fg.description('RSS feed for Nihilists OPSEC Bible')

    with open(index_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    for line in lines[::-1]:
        line = line.strip()
        if not line.startswith('- 20'):
            # skip line that doesnt start with date
            continue

        try:
            date_str, link_part = line[2:].split(': ', 1)
            title = link_part.split('[')[1].split(']')[0]
            end_title_pos = link_part.index(']')
            md_path = link_part[end_title_pos:].split('(')[1].split(')')[0]
        except (ValueError, IndexError):
            print(f"Skipping invalid line of index.md: {line}")
            continue

        try:
            metadata = extract_metadata(os.path.join(os.path.dirname(index_file), md_path))
        except FileNotFoundError:
            print(f"Markdown tags processing error: {md_path}")
            continue

        fe = fg.add_entry()
        fe.title(title)
        # temporary hack to deal with http paths being different from ones in fs
        midpath = os.path.dirname(index_file).replace('docs/', '')
        fe.link(href=f"{base_url}/{midpath}/{md_path.replace('.md', '.html')}")
        fe.pubDate(datetime.datetime.strptime(date_str, '%Y-%m-%d').replace(tzinfo=datetime.timezone.utc))
        
        aut = metadata.get('author', 'unknown')
        if isinstance(aut, list):
            try:
                # keep only most recent author in case there're many
                aut = aut[0]
            except:
                pass
        # feedgen treats email as primary field in author name
        # we don't use emails, only nicknames here
        fe.author({'email': aut})
        
        for tag in metadata.get('tags', []):
            fe.category(term=tag)

    fg.rss_file(output_file)
    print(f"RSS feed generated: {output_file}")


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: genrss.py /path/to/index.md /path/to/rss.xml\nNeeds SITE_URL env variable as well.")
        exit(1)
    generate_rss_feed(sys.argv[1], sys.argv[2], os.environ['SITE_URL'])

