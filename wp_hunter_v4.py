import os
import json
import shutil
import zipfile
import requests
import subprocess

TARGET_DIR = "/tmp/wp_hunt_v4"
os.makedirs(TARGET_DIR, exist_ok=True)

# Açar sözlər üzrə az tanınan və köhnə plaginləri hədəfləyirik
KEYWORDS = ["booking", "gallery", "directory", "appointment", "quiz", "invoice", "chat"]
plugins_to_scan = []

print("[+] WordPress API-dən AZ TANINAN hədəf plaginlər toplanır...")

for kw in KEYWORDS:
    # Page 2 və 3-dən çəkirik ki, ilk səhifədəki populyarlar gəlməsin
    for page in [2, 3]:
        url = f"https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[search]={kw}&request[page]={page}&request[per_page]=15"
        try:
            res = requests.get(url, timeout=10).json()
            for p in res.get("plugins", []):
                slug = p.get("slug")
                link = p.get("download_link")
                # Yalnız aktiv quraşdırması 20,000-dən az olanları seçirik
                active_installs = p.get("active_installs", 0)
                if link and slug and active_installs < 20000:
                    if slug not in [x['slug'] for x in plugins_to_scan]:
                        plugins_to_scan.append({"slug": slug, "link": link, "installs": active_installs})
        except:
            pass

print(f"[+] Toplam {len(plugins_to_scan)} az tanınan hədəf hazırlandı.\n")

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
