import os
import re
import shutil
import subprocess
import requests

TARGET_DIR = "/tmp/wp_svn_targets"
os.makedirs(TARGET_DIR, exist_ok=True)

print("[+] WordPress Trac SVN-dən son dəyişiklik edilən plaginlər çəkilir...")
# Trac RSS feed üzərindən son dəyişən plaginlərin siyahısı
url = "https://plugins.trac.wordpress.org/timeline?changeset=on&max=30&daysback=1&format=rss"
res = requests.get(url).text

slugs = list(set(re.findall(r'/browser/([^/?#]+)', res)))
print(f"[+] Son 24 saatda koda dəyişiklik edilmiş {len(slugs)} plagin tapıldı.\n")

for idx, slug in enumerate(slugs, 1):
    if slug in ['INDEX', '']: continue
    
    print(f"[{idx}/{len(slugs)}] SVN Checkout/Download: {slug} ...", end=" ", flush=True)
    p_dir = os.path.join(TARGET_DIR, slug)
    
    # SVN trunk-ı çəkirik (hələ rəsmi buraxılmayan ən son kod)
    svn_cmd = f"svn checkout https://plugins.svn.wordpress.org/{slug}/trunk {p_dir} --quiet --non-interactive"
    ret = subprocess.run(svn_cmd, shell=True)
    
    if ret.returncode == 0 and os.path.exists(p_dir):
        cmd = f"python3 -m zdh.cli scan {p_dir}"
        scan_res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if "Findings: 0" not in scan_res.stdout and "Findings:" in scan_res.stdout:
            print(" [!] TƏZƏ DƏYİŞİKLİKDƏ TAPINTI XƏBƏRDARLIĞI!")
            print(scan_res.stdout)
        else:
            print(" [ clean ]")
    else:
        print(" [ SVN Xətası ]")
        
    shutil.rmtree(p_dir, ignore_errors=True)
