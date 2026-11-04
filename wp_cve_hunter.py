import os
import json
import shutil
import zipfile
import requests

TARGET_DIR = "/tmp/wp_cve_targets"
os.makedirs(TARGET_DIR, exist_ok=True)

# Xüsusilə form, slider, booking və gallery kimi idarəetmə plaginləri
KEYWORDS = ["booking", "slider", "gallery", "testimonial", "event", "contact"]
plugins_to_scan = []

print("[+] WordPress API-dən CVE potensiallı hədəflər toplanır...")

for kw in KEYWORDS:
    url = f"https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[search]={kw}&request[page]=3&request[per_page]=20"
    try:
        res = requests.get(url, timeout=10).json()
        for p in res.get("plugins", []):
            slug = p.get("slug")
            link = p.get("download_link")
            installs = p.get("active_installs", 0)
            if link and slug and 500 <= installs <= 10000:
                if slug not in [x['slug'] for x in plugins_to_scan]:
                    plugins_to_scan.append({"slug": slug, "link": link, "installs": installs})
    except:
        pass

print(f"[+] Toplam {len(plugins_to_scan)} hədəf hazırlandı.\n")

vulnerable_found = []

for idx, p in enumerate(plugins_to_scan, 1):
    slug = p["slug"]
    link = p["link"]
    installs = p["installs"]
    p_dir = os.path.join(TARGET_DIR, slug)
    zip_path = os.path.join(TARGET_DIR, f"{slug}.zip")
    
    try:
        r = requests.get(link, timeout=10)
        with open(zip_path, 'wb') as f:
            f.write(r.content)
            
        with zipfile.ZipFile(zip_path, 'r') as z:
            z.extractall(TARGET_DIR)
        os.remove(zip_path)
        
        findings = []
        for root_dir, _, files in os.walk(p_dir):
            for file in files:
                if file.endswith('.php'):
                    filepath = os.path.join(root_dir, file)
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        for line_num, line in enumerate(lines, 1):
                            # Sırf wp_ajax_ işlədilən və yoxlaması çatmayan sətirləri tuturuq
                            if 'wp_ajax_' in line:
                                content_around = "".join(lines[max(0, line_num-5):min(len(lines), line_num+35)])
                                if ('update_option' in content_around or 'add_option' in content_around or 'delete_option' in content_around) and ('current_user_can' not in content_around):
                                    rel_path = os.path.relpath(filepath, p_dir)
                                    findings.append((rel_path, line_num))

        if len(findings) > 0:
            print(f"\n[!] [{installs} inst.] POTENSİAL CVE ÇIXDI! Plagin: {slug}")
            for f in findings:
                print(f"   -> Fayl: {f[0]} | Sətir: {f[1]}")
            vulnerable_found.append((slug, findings))
        else:
            print(f"[{idx}/{len(plugins_to_scan)}] [{installs} inst.] Skan edilir: {slug} ... [ clean ]")
            
    except Exception as e:
        print(f"[{idx}/{len(plugins_to_scan)}] Xəta")
        
    shutil.rmtree(p_dir, ignore_errors=True)

print("\n" + "="*50)
print(f"[+] Skan Bitdi! Potensial BAC olan plaginlər: {len(vulnerable_found)}")
