# 0xArsenal

> Meu arsenal pessoal de hacking. Algumas ferramentas e exploits que uso para bug bounty e testes de segurança.  
> “Control. Chaos. Code.” 

---

## Overview

**0xArsenal** é um repositório com algumas das minhas ferramentas e exploits favoritas pra caçar e explorar vulnerabilidades.  
O script principal, `bugtools.py`, automatiza a instalação dessas ferramentas, usando **APT**, **Snap** e **Go**, e configura o PATH para que você possa chamá-las diretamente no terminal.

---

## Ferramentas incluídas

- Recon: `subfinder`, `assetfinder`, `amass`, `gau`, `waybackurls`, `httpx`  
- Scanners & Templates: `nuclei`, `naabu`, `katana`  
- Fuzzing & Exploits: `XSStrike`, `dalfox`, `ParamSpider`, `LinkFinder`, `JSParser`, `dirsearch`  
- Utilitários: `gf`, `qsreplace`, `unfurl`, `interactsh-client`  

> Nota: Nem todas as ferramentas e exploits estão aqui. É apenas uma seleção do meu arsenal pessoal.

---

## Instalação

```bash
git clone https://github.com/rillxn/0xArsenal.git
cd 0xArsenal
sudo python3 bugtools.py
source ~/.bashrc
