import os
import json
import shutil
import zipfile
import requests
import subprocess

TARGET_DIR = "/tmp/wp_hunt_v3"
os.makedirs(TARGET_DIR, exist_ok=True)

# Yüksək zəiflik ehtimallı açar sözlər
KEYWORDS = ["form", "export", "import", "custom-fields", "manager"]
plugins_to_scan = []

print("[+] WordPress API-dən hədəf plaginlər toplanır...")

for kw in KEYWORDS:
    url = f"https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[search]={kw}&request[per_page]=10"
    res = requests.get(url).json()
    for p in res.get("plugins", []):
        if p.get("download_link") and p.get("slug") not in [x['slug'] for x in plugins_to_scan]:
            plugins_to_scan.append({"slug": p.get("slug"), "link": p.get("download_link")})

print(f"[+] Toplam {len(plugins_to_scan)} hədəf plagin skana hazırlandı.\n")

found_vulnerabilities = []

for idx, p in enumerate(plugins_to_scan, 1):
    slug = p["slug"]
    link = p["link"]
    
    p_dir = os.path.join(TARGET_DIR, slug)
    zip_path = os.path.join(TARGET_DIR, f"{slug}.zip")
    report_file = os.path.join(os.getcwd(), "reports", "local.json")
    
    if os.path.exists(report_file):
        os.remove(report_file)
        
    print(f"[{idx}/{len(plugins_to_scan)}] Skan edilir: {slug} ...", end=" ", flush=True)
    
    try:
        r = requests.get(link, timeout=10)
        with open(zip_path, 'wb') as f:
            f.write(r.content)
            
        with zipfile.ZipFile(zip_path, 'r') as z:
            z.extractall(TARGET_DIR)
        os.remove(zip_path)
        
        cmd = f"python3 -m zdh.cli scan {p_dir}"
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # JSON hesabatını doğrudan oxuyuruq
        if os.path.exists(report_file):
            with open(report_file, 'r') as rf:
                data = json.load(rf)
                findings = data if isinstance(data, list) else data.get("findings", [])
                
                if len(findings) > 0:
                    print(f" [!] {len(findings)} TAPINTI DETEKT EDİLDİ!")
                    found_vulnerabilities.append((slug, len(findings)))
                else:
                    print(" [ clean ]")
        else:
            print(" [ clean ]")
            
    except Exception as e:
        print(f" [ Xəta ]")
        
    shutil.rmtree(p_dir, ignore_errors=True)

print("\n" + "="*50)
print(f"[+] Yekun: {len(found_vulnerabilities)} plagində tapıntı çıxdı.")
for item in found_vulnerabilities:
    print(f" -> Plagin: {item[0]} | Tapıntı sayı: {item[1]}")
