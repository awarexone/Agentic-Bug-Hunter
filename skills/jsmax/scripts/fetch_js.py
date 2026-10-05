import os
import sys
import requests
import hashlib
import time
from urllib.parse import urlparse

def download_js(url, dest_dir, retries=3):
    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'}, allow_redirects=True)
            if response.status_code == 200:
                parsed_url = urlparse(url)
                # Ensure unique filename using MD5 of URL
                safe_name = hashlib.md5(url.encode()).hexdigest() + "_" + os.path.basename(parsed_url.path)
                if not safe_name.endswith('.js'):
                    safe_name += '.js'
                
                file_path = os.path.join(dest_dir, safe_name)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(response.text)
                return file_path, None
            else:
                if attempt == retries - 1:
                    return None, f"Status code: {response.status_code}"
        except Exception as e:
            if attempt == retries - 1:
                return None, str(e)
        time.sleep(1) # Small delay between retries
    return None, "Unknown error"

def main():
    if len(sys.argv) < 3:
        print("Usage: python fetch_js.py <url_list_file> <dest_dir> [batch_size] [offset]")
        sys.exit(1)

    url_file = sys.argv[1]
    dest_dir = sys.argv[2]
    batch_size = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    offset = int(sys.argv[4]) if len(sys.argv) > 4 else 0

    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)

    try:
        with open(url_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"CRITICAL ERROR: Could not read URL list file: {e}")
        sys.exit(1)

    total_urls = len(urls)
    batch = urls[offset : offset + batch_size]
    
    print(f"PROGRESS|START|{offset}|{offset + len(batch)}|{total_urls}")

    for url in batch:
        path, err = download_js(url, dest_dir)
        if path:
            print(f"SUCCESS|{url}|{path}")
        else:
            print(f"FAILURE|{url}|{err}")

    print(f"PROGRESS|END|{offset + len(batch)}|{total_urls}")

if __name__ == "__main__":
    main()
