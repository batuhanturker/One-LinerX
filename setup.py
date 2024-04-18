import subprocess

commands = [
    "sudo apt-get update && sudo apt-get upgrade",
    "apt install moreutils",
    "apt install parallel",
    "sudo apt install golang",
    "go install -v github.com/lc/gau/v2/cmd/gau@latest",
    "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "go install -v github.com/jaeles-project/gospider@latest",
    "go install -v github.com/hahwul/dalfox/v2@latest",
    "pip3 install uro",
    "go install -v github.com/tomnomnom/waybackurls@latest",
    "go install -v github.com/003random/getJS@latest",
    "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
    "git clone https://github.com/LewisArdern/bXSS.git",
    "cd bXSS && npm install",
    "go install -v github.com/KathanP19/Gxss@latest",
    "go install -v github.com/tomnomnom/gf@latest",
    "cd .. && mkdir Tools && cd Tools && mkdir Test && cd Test",
    "git clone https://github.com/projectdiscovery/nuclei-templates",
    "git clone https://github.com/projectdiscovery/fuzzing-templates",
    "sudo apt autoremove",
    "sudo apt-get update && sudo apt-get upgrade",
    "npm audit fix --force",
    "cp -r /root/go/bin /usr/bin",
    "pip3 install -r requirements.txt"
]
for command in commands:
    subprocess.run(command, shell=True)
