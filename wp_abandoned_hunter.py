import os
import json
import shutil
import zipfile
import requests
import subprocess

TARGET_DIR = "/tmp/wp_abandoned_targets"
os.makedirs(TARGET_DIR, exist_ok=True)

# Müasir mühafizəsi az olan xüsusi kateqoriyalar
KEYWORDS = ["custom-post", "simple-slider", "contact-form", "db-manager", "shortcode", "smtp", "guestbook"]
plugins_to_scan = []

print("[+] WordPress API-dən TƏRK EDİLMİŞ və KÖHNƏ plaginlər toplanır...")

for kw in KEYWORDS:
    # Səhifələməni arxa hissədən çəkirik ki, köhnə layihələr gəlsin
    url = f"https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[search]={kw}&request[page]=4&request[per_page]=20"
    try:
        res = requests.get(url, timeout=10).json()
        for p in res.get("plugins", []):
            slug = p.get("slug")
            link = p.get("download_link")
            installs = p.get("active_installs", 0)
            
            # Yalnız 500 ilə 10.000 arası aktiv istifadəçisi olanları seçirik
            if link and slug and 500 <= installs <= 10000:
                if slug not in [x['slug'] for x in plugins_to_scan]:
                    plugins_to_scan.append({"slug": slug, "link": link, "installs": installs})
    except:
        pass

print(f"[+] Toplam {len(plugins_to_scan)} ədəd köhnə/az audit olunmuş hədəf hazırlandı.\n")

found_vulnerabilities = []

for idx, p in enumerate(plugins_to_scan, 1):
    slug = p["slug"]
    link = p["link"]
    installs = p["installs"]
    
    p_dir = os.path.join(TARGET_DIR, slug)
    zip_path = os.path.join(TARGET_DIR, f"{slug}.zip")
    report_file = os.path.join(os.getcwd(), "reports", "local.json")
    
    if os.path.exists(report_file):
        os.remove(report_file)
        
    print(f"[{idx}/{len(plugins_to_scan)}] [{installs} inst.] Skan edilir: {slug} ...", end=" ", flush=True)
    
    try:
        r = requests.get(link, timeout=10)
        with open(zip_path, 'wb') as f:
            f.write(r.content)
            
        with zipfile.ZipFile(zip_path, 'r') as z:
            z.extractall(TARGET_DIR)
        os.remove(zip_path)
        
        cmd = f"python3 -m zdh.cli scan {p_dir}"
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
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
        print(" [ Xəta ]")
        
    shutil.rmtree(p_dir, ignore_errors=True)

print("\n" + "="*50)
print(f"[+] Yekun: {len(found_vulnerabilities)} plagində tapıntı çıxdı.")
for item in found_vulnerabilities:
    print(f" -> Plagin: {item[0]} | Tapıntı sayı: {item[1]}")
