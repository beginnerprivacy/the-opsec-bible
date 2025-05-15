#!/usr/bin/env python3
import os
import re
import argparse

def get_all_images(images_dir):
    allowed_ext = {'.png', '.jpeg', '.jpg', '.webp', '.gif'}
    image_files = set()
    
    for root, _, files in os.walk(images_dir):
        for filename in files:
            ext = os.path.splitext(filename)[1].lower()  # use lower-case
            if ext in allowed_ext:
                pth = os.path.abspath(os.path.join(root, filename))
                image_files.add(pth)
    return image_files

def get_markdown_image_references(posts_dir):
    image_refs = set()
    # regex matches: ![optional alt text](path)
    pattern = re.compile(r'!\[.*?\]\((.*?)\)')
    
    for root, _, files in os.walk(posts_dir):
        for filename in files:
            if filename.endswith('.md'):
                file_path = os.path.join(root, filename)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                except:
                    continue
                matches = pattern.findall(content)
                for match in matches:
                    ref = match.strip().strip('"').strip("'")
                    refreal = os.path.join(root, ref)
                    #print(refreal, ref, os.path.abspath(refreal))
                    image_refs.add(os.path.abspath(refreal))
    return image_refs

def main():
    parser = argparse.ArgumentParser(
        description="Find unused images (png, jpeg, jpg) that are not referenced by any Markdown post."
    )
    parser.add_argument("--docs", required=True,
                        help="main docs/ directory.")
    args = parser.parse_args()

    all_images = get_all_images(args.docs)

    image_references = get_markdown_image_references(args.docs)
    unused_images = all_images - image_references

    if unused_images:
        print("Unused images:")
        size_cum = 0
        for img in sorted(unused_images):
            size_cum += os.path.getsize(img)
            print(os.path.relpath(img, start=os.path.abspath(args.docs)))
        print(f'\nPossible savings: {round(size_cum/1024)} kB')
    else:
        print("No unused images found.")

if __name__ == "__main__":
    main()
