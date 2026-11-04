import os
import json
import shutil
import zipfile
import requests
import subprocess

TARGET_DIR = "/tmp/wp_custom_targets"
os.makedirs(TARGET_DIR, exist_ok=True)

KEYWORDS = ["custom", "form", "booking", "chat", "download", "file", "export", "import"]
plugins_to_scan = []

print("[+] WordPress API-dən xüsusi hədəf plaginlər toplanır...")

for kw in KEYWORDS:
    url = f"https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[search]={kw}&request[page]=2&request[per_page]=15"
    try:
        res = requests.get(url, timeout=10).json()
        for p in res.get("plugins", []):
            slug = p.get("slug")
            link = p.get("download_link")
            installs = p.get("active_installs", 0)
            if link and slug and 200 <= installs <= 5000:
                if slug not in [x['slug'] for x in plugins_to_scan]:
                    plugins_to_scan.append({"slug": slug, "link": link, "installs": installs})
    except:
        pass

print(f"[+] Toplam {len(plugins_to_scan)} hədəf hazırlandı.\n")

rule_file = "/root/Desktop/ZeroDayHunter-final/wp_rules.yaml"

for idx, p in enumerate(plugins_to_scan, 1):
    slug = p["slug"]
    link = p["link"]
    
    p_dir = os.path.join(TARGET_DIR, slug)
    zip_path = os.path.join(TARGET_DIR, f"{slug}.zip")
    
    print(f"[{idx}/{len(plugins_to_scan)}] Skan edilir: {slug} ...", end=" ", flush=True)
    
    try:
        r = requests.get(link, timeout=10)
        with open(zip_path, 'wb') as f:
            f.write(r.content)
            
        with zipfile.ZipFile(zip_path, 'r') as z:
            z.extractall(TARGET_DIR)
        os.remove(zip_path)
        
        # Xüsusi qaydamızla skan edirik
        cmd = f"semgrep --config={rule_file} --json {p_dir}"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if res.stdout:
            data = json.loads(res.stdout)
            results = data.get("results", [])
            if len(results) > 0:
                print(f"\n [!] DƏQİQ BAC/NONCE TAPINTISI ({len(results)} ədəd)! Plagin: {slug}")
                for r_item in results:
                    print(f"   -> Fayl: {r_item.get('path')}:{r_item.get('start', {}).get('line')}")
            else:
                print(" [ clean ]")
        else:
            print(" [ clean ]")
            
    except Exception as e:
        print(" [ Xəta ]")
        
    shutil.rmtree(p_dir, ignore_errors=True)
