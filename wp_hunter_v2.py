import os
import shutil
import zipfile
import requests
import subprocess

TARGET_DIR = "/tmp/wp_hunt_targets"
os.makedirs(TARGET_DIR, exist_ok=True)

# browse=new vasitəsilə ən YENİ çıxmış 50 plagini çəkirik
print("[+] WordPress API-dən ən YENİ 50 plagin məlumatı çəkilir...")
url = "https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[browse]=new&request[per_page]=50"
response = requests.get(url).json()

plugins = response.get("plugins", [])
print(f"[+] {len(plugins)} ədəd yeni plagin tapıldı.\n")

vulnerable_found = []

for idx, plugin in enumerate(plugins, 1):
    slug = plugin.get("slug")
    download_link = plugin.get("download_link")
    
    if not download_link:
        continue
        
    plugin_dir = os.path.join(TARGET_DIR, slug)
    zip_path = os.path.join(TARGET_DIR, f"{slug}.zip")
    
    print(f"[{idx}/50] Yüklənir və skan olunur: {slug} ...", end=" ", flush=True)
    
    try:
        r = requests.get(download_link, stream=True, timeout=10)
        with open(zip_path, 'wb') as f:
            f.write(r.content)
            
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(TARGET_DIR)
        os.remove(zip_path)
        
        cmd = f"python3 -m zdh.cli scan {plugin_dir}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        output = result.stdout
        if "Findings: 0" not in output and "Findings:" in output:
            print(" [!] TAPINTI VAR!")
            print(output)
            vulnerable_found.append(slug)
        else:
            print(" [ clean ]")
            
    except Exception as e:
        print(f" [ Xəta: {e} ]")
        
    shutil.rmtree(plugin_dir, ignore_errors=True)

print("\n==================================================")
print(f"[+] Skan Yekunlaşdı! Tapıntı çıxan plaginlər: {len(vulnerable_found)}")
for v in vulnerable_found:
    print(f" -> {v}")
