<div align="center">
  <img src="assets/banner.svg" alt="MAUL - Brother Program of Vader" width="100%"/>

  <br/>

  <img src="assets/darth_maul.png" alt="Darth Maul" width="300"/>
</div>

---

### *By a Star Wars Nerd*

> **"Fear is my ally."** - Darth Maul

Infrastructure mapping and enumeration tool. Takes IPs/domains from **Vader** and maps infrastructure via PTR records, SSL certs, subdomain/directory bruteforcing.

**Core Features:** IP-to-Domain mapping • SSL cert extraction • Subdomain enumeration • Directory scanning • Multi-threaded

---

## Installation

```bash
git clone https://github.com/nsm-barii/maul.git
cd maul/src
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

**Map IPs to domains:**
```bash
sudo venv/bin/python main.py -i ips.txt
```

**Subdomain scan:**
```bash
sudo venv/bin/python main.py -u example.com --sub-wordlist large.txt
```

**Full workflow:**
```bash
sudo venv/bin/python main.py -i vader_ips.txt --sub-wordlist large.txt --save
```

---

## Key Arguments

| Flag | Description |
|------|-------------|
| `-i` | IP list from Vader (auto does PTR + SSL cert extraction) |
| `-u` | Single domain |
| `-d` | Domain list file |
| `-t` | Max threads (default: 250) |
| `--ptr-only` | Only PTR lookups (skip SSL certs) |
| `--cert-only` | Only SSL certs (skip PTR) |
| `--sub-wordlist` | `tiny`, `small`, `medium`, `large` |
| `--dir-wordlist` | `tiny`, `small`, `medium`, `large` |
| `--save` | Save results |

---

## About

Created by **NSM-Barii** - Star Wars nerd | Cybersecurity enthusiast

**NSM Toolset:**
- **Vader** - Recon & discovery
- **Maul** - Infrastructure mapping

---

**Disclaimer:** Authorized testing only. Unauthorized scanning is illegal.

MIT License
