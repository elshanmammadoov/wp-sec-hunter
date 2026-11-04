import os
import shutil
import zipfile
import requests
import subprocess

TARGET_DIR = "/tmp/wp_latest_plugins"
os.makedirs(TARGET_DIR, exist_ok=True)

print("[+] WordPress API-dən ən son 10 plagin məlumatı çəkilir...")
url = "https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[browse]=updated&request[per_page]=10"
response = requests.get(url).json()

plugins = response.get("plugins", [])
print(f"[+] {len(plugins)} ədəd son plagin tapıldı.\n")

for plugin in plugins:
    slug = plugin.get("slug")
    download_link = plugin.get("download_link")
    
    if not download_link:
        continue
        
    plugin_dir = os.path.join(TARGET_DIR, slug)
    zip_path = os.path.join(TARGET_DIR, f"{slug}.zip")
    
    print(f"==================================================")
    print(f"[>] Yüklənir: {slug} ...")
    
    # Plagini endiririk
    r = requests.get(download_link, stream=True)
    with open(zip_path, 'wb') as f:
        f.write(r.content)
        
    # Zip-dən çıxarırıq
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(TARGET_DIR)
    os.remove(zip_path)
    
    # ZDH ilə skan edirik
    print(f"[>] ZDH skan edir: {slug}")
    cmd = f"python3 -m zdh.cli scan {plugin_dir}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    print(result.stdout if result.stdout else result.stderr)
    
    # Təmizlik (istəsəniz saxlaya bilərsiniz)
    shutil.rmtree(plugin_dir, ignore_errors=True)

print("[+] Bütün son 10 plagin skan olundu!")
