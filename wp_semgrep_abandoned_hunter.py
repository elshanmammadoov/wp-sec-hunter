import os
import json
import shutil
import zipfile
import requests
import subprocess

TARGET_DIR = "/tmp/wp_abandoned_semgrep"
os.makedirs(TARGET_DIR, exist_ok=True)

# Təhlükəsizliyi adətən zəif olan funksional kateqoriyalar
KEYWORDS = ["slider", "gallery", "guestbook", "contact-form", "testimonial", "quiz", "chat", "csv", "backup"]
plugins_to_scan = []

print("[+] WordPress API-dən TƏRK EDİLMİŞ və KÖHNƏ plaginlər axtarılır...")

for kw in KEYWORDS:
    # Arxa səhifələri çəkirik ki, populyarlar tam kənarda qalsın
    for page in [3, 4, 5]:
        url = f"https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[search]={kw}&request[page]={page}&request[per_page]=20"
        try:
            res = requests.get(url, timeout=10).json()
            for p in res.get("plugins", []):
                slug = p.get("slug")
                link = p.get("download_link")
                installs = p.get("active_installs", 0)
                
                # Yalnız 300 ilə 8,000 arası instalı olan az tanınan plaginlər
                if link and slug and 300 <= installs <= 8000:
                    if slug not in [x['slug'] for x in plugins_to_scan]:
                        plugins_to_scan.append({"slug": slug, "link": link, "installs": installs})
        except:
            pass

print(f"[+] Toplam {len(plugins_to_scan)} ədəd köhnə/abandoned hədəf tapıldı.\n")

vulnerable_plugins = []

for idx, p in enumerate(plugins_to_scan, 1):
    slug = p["slug"]
    link = p["link"]
    installs = p["installs"]
    
    p_dir = os.path.join(TARGET_DIR, slug)
    zip_path = os.path.join(TARGET_DIR, f"{slug}.zip")
    
    print(f"[{idx}/{len(plugins_to_scan)}] [{installs} inst.] Avto-yüklənir və Semgrep ilə skan edilir: {slug} ...", end=" ", flush=True)
    
    try:
        r = requests.get(link, timeout=12)
        with open(zip_path, 'wb') as f:
            f.write(r.content)
            
        with zipfile.ZipFile(zip_path, 'r') as z:
            z.extractall(TARGET_DIR)
        os.remove(zip_path)
        
        # Semgrep ilə Unauthenticated AJAX / Missing Auth / XSS analizi
        semgrep_cmd = f"semgrep --config=p/php --config=p/wordpress --json {p_dir}"
        res = subprocess.run(semgrep_cmd, shell=True, capture_output=True, text=True)
        
        findings = []
        if res.stdout:
            try:
                sg_json = json.loads(res.stdout)
                results = sg_json.get("results", [])
                for item in results:
                    check_id = item.get("check_id", "")
                    # Yüksək siqnallı xətaları süzürük
                    if any(v in check_id.lower() for v in ["xss", "sqli", "auth", "nonce", "permission", "file"]):
                        path = item.get("path", "")
                        line = item.get("start", {}).get("line", 0)
                        findings.append((check_id, path, line))
            except:
                pass

        if len(findings) > 0:
            print(f"\n [!] TAPINTI ÇIXDI ({len(findings)} ədəd)! Plagin: {slug}")
            for f in findings[:5]:
                print(f"   -> [{f[0]}] Fayl: {f[1]}:{f[2]}")
            vulnerable_plugins.append(slug)
        else:
            print(" [ clean ]")
            
    except Exception as e:
        print(" [ Xəta ]")
        
    shutil.rmtree(p_dir, ignore_errors=True)

print("\n" + "="*60)
print(f"[+] Skan Yekunlaşdı! Zəiflik tapılan plaginlər ({len(vulnerable_plugins)} ədəd):")
for v in vulnerable_plugins:
    print(f" -> {v}")
