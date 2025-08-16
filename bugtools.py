#!/usr/bin/env python3
import os
import subprocess
import shutil
import time
from pathlib import Path

# Configurações
USER_HOME = Path.home()
TOOLS_DIR = USER_HOME / "tools"
BIN_DIR = TOOLS_DIR / "bin"
GO_BIN = USER_HOME / "go" / "bin"

# Criar diretórios
TOOLS_DIR.mkdir(parents=True, exist_ok=True)
BIN_DIR.mkdir(parents=True, exist_ok=True)
GO_BIN.mkdir(parents=True, exist_ok=True)

# Listas de ferramentas
apt_packages = [
    "nmap", "sqlmap", "git", "python3-pip", "whois", "dnsutils", "jq", "curl",
    "unzip", "httpie", "wget", "hydra", "nikto", "wapiti", "netcat", "zmap",
    "masscan", "mitmproxy", "tor", "proxychains4", "libpcap-dev", "build-essential",
    "golang", "dirsearch"
]

snap_packages = ["amass", "httpx"]

tool_checks = {
    "subfinder": {"go": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    "httpx": {"snap": "httpx", "go": "github.com/projectdiscovery/httpx/cmd/httpx@latest"},
    "nuclei": {"go": "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"},
    "naabu": {"go": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"},
    "katana": {"go": "github.com/projectdiscovery/katana/cmd/katana@latest"},
    "assetfinder": {"go": "github.com/tomnomnom/assetfinder@latest"},
    "amass": {"snap": "amass", "go": "github.com/owasp-amass/amass/v3/...@latest"},
    "gau": {"go": "github.com/lc/gau/v2/cmd/gau@latest"},
    "waybackurls": {"go": "github.com/tomnomnom/waybackurls@latest"},
    "gf": {"go": "github.com/tomnomnom/gf@latest"},
    "qsreplace": {"go": "github.com/tomnomnom/qsreplace@latest"},
    "unfurl": {"go": "github.com/tomnomnom/unfurl@latest"},
    "interactsh-client": {"go": "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"},
}

git_tools = {
    "XSStrike": {"url": "https://github.com/s0md3v/XSStrike.git", "update_cmd": "git pull"},
    "dalfox": {"url": "https://github.com/hahwul/dalfox.git", "update_cmd": "git pull"},
    "ParamSpider": {"url": "https://github.com/devanshbatham/ParamSpider.git", "update_cmd": "git pull"},
    "LinkFinder": {"url": "https://github.com/GerbenJavado/LinkFinder.git", "update_cmd": "git pull"},
    "JSParser": {"url": "https://github.com/nahamsec/JSParser.git", "update_cmd": "git pull"},
    "fuzzing-templates": {"url": "https://github.com/projectdiscovery/fuzzing-templates.git", "update_cmd": "git pull"},
    "SecLists": {"url": "https://github.com/danielmiessler/SecLists.git", "update_cmd": "git pull"},
    "PayloadsAllTheThings": {"url": "https://github.com/swisskyrepo/PayloadsAllTheThings.git", "update_cmd": "git pull"},
}

def colorful_log(msg, category=None):
    colors = {
        "header": "\033[95m", "blue": "\033[94m", "cyan": "\033[96m",
        "green": "\033[92m", "yellow": "\033[93m", "red": "\033[91m",
        "end": "\033[0m", "bold": "\033[1m",
    }
    
    icons = {
        "success": "✓", "error": "✗", "warning": "!", "info": "i",
        "update": "🔄", "install": "📦", "found": "🔍"
    }
    
    if category in icons:
        print(f"{colors.get(category, '')}[{icons[category]}] {msg}{colors['end']}")
    elif category == "header":
        print(f"\n{colors['header']}{'='*50}{colors['end']}")
        print(f"{colors['bold']}{colors['header']}{msg.center(50)}{colors['end']}")
        print(f"{colors['header']}{'='*50}{colors['end']}\n")
    else:
        print(f"[+] {msg}")

def run(cmd, sudo=False):
    try:
        if sudo:
            result = subprocess.run(f"sudo {cmd}", shell=True, check=True, 
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            result = subprocess.run(cmd, shell=True, check=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True, result.stdout.decode().strip()
    except subprocess.CalledProcessError as e:
        return False, e.stderr.decode().strip()

def is_installed(command):
    return shutil.which(command) is not None

def check_apt_updates():
    colorful_log("Verificando atualizações do sistema...", "info")
    success, output = run("apt list --upgradable", sudo=True)
    if success and output:
        colorful_log("Atualizações disponíveis:", "update")
        print(output)
        return True
    return False

def update_apt_packages():
    colorful_log("Atualizando todos os pacotes APT...", "update")
    run("sudo apt update && sudo apt upgrade -y", sudo=True)

def check_snap_updates(pkg):
    success, output = run(f"snap refresh {pkg} --list", sudo=True)
    if success and "latest" not in output:
        colorful_log(f"Atualização disponível para {pkg}: {output}", "update")
        return True
    return False

def update_snap_packages():
    colorful_log("Atualizando pacotes Snap...", "update")
    run("sudo snap refresh", sudo=True)

def check_go_updates(tool, go_path):
    success, output = run(f"go install {go_path}@latest")
    if success:
        colorful_log(f"{tool} está atualizado", "success")
    return success

def check_git_updates(tool_path):
    # Verifica se há commits novos no repositório
    success, _ = run(f"git -C {tool_path} remote update")
    success, local = run(f"git -C {tool_path} rev-parse @")
    success, remote = run(f"git -C {tool_path} rev-parse @{{u}}")
    success, base = run(f"git -C {tool_path} merge-base @ @{{u}}")
    
    if local == remote:
        return False  # Atualizado
    elif local == base:
        return True   # Precisa atualizar
    else:
        return False  # Divergente

def add_to_path(path):
    path = str(path)
    bashrc = USER_HOME / ".bashrc"
    path_line = f'export PATH="{path}:$PATH"'
    
    with open(bashrc, "r") as f:
        content = f.read()
    
    if path_line not in content:
        with open(bashrc, "a") as f:
            f.write(f"\n{path_line}\n")
    
    os.environ["PATH"] = f"{path}:{os.environ['PATH']}"

def install_apt():
    print_category("Ferramentas Básicas (APT)")
    check_apt_updates()
    
    for pkg in apt_packages:
        if is_installed(pkg.split('/')[0]):
            colorful_log(f"{pkg} já instalado. Verificando atualização xD", "found")
            continue
        
        colorful_log(f"Instalando {pkg}...", "install")
        run(f"apt install -y {pkg}", sudo=True)

def install_snap():
    print_category("Ferramentas via Snap")
    for pkg in snap_packages:
        if is_installed(pkg):
            colorful_log(f"{pkg} já instalado. Verificando atualização xD", "found")
            if check_snap_updates(pkg):
                run(f"snap refresh {pkg}", sudo=True)
            continue
        
        colorful_log(f"Instalando {pkg}...", "install")
        run(f"snap install {pkg}", sudo=True)

def install_go_tools():
    print_category("Ferramentas Go")
    add_to_path(GO_BIN)
    add_to_path(BIN_DIR)
    
    if not is_installed("go"):
        colorful_log("Instalando Go...", "install")
        run("apt install -y golang", sudo=True)
    
    for name, info in tool_checks.items():
        if is_installed(name):
            colorful_log(f"{name} encontrado. Atualizando", "update")
            check_go_updates(name, info["go"])
            continue
        
        if "go" in info:
            colorful_log(f"Instalando {name}...", "install")
            run(f"go install {info['go']}")

def install_git_tools():
    print_category("Ferramentas Git")
    for name, info in git_tools.items():
        dest = TOOLS_DIR / name
        if dest.exists():
            colorful_log(f"{name} encontrado. \!/ Verificando atualização.", "found")
            if check_git_updates(dest):
                colorful_log(f"Atualizando {name}", "update")
                run(f"git -C {dest} pull")
            continue
        
        colorful_log(f"Clonando {name}", "install")
        run(f"git clone {info['url']} {dest}")

def print_category(title):
    colorful_log(title, "header")

def main():
    colorful_log("🛠️ BugBounty Toolkit Manager 🛠️", "header")
    colorful_log("Instala e atualiza todas as ferramentas essenciais", "info")
    
    # Atualizações globais primeiro
    update_apt_packages()
    update_snap_packages()
    
    # Instalação/atualização específica
    install_apt()
    install_snap()
    install_go_tools()
    install_git_tools()
    
    colorful_log("Todas as instalações e atualizações concluídas \!/", "success")
    colorful_log("Execute 'source ~/.bashrc' para atualizar seu PATH", "info")

if __name__ == "__main__":
    main()