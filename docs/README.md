# Maul Reverse DNS Documentation

```diff
+   ██████   █████  ██████  ████████ ██   ██     ███    ███  █████  ██    ██ ██
+   ██   ██ ██   ██ ██   ██    ██    ██   ██     ████  ████ ██   ██ ██    ██ ██
+   ██   ██ ███████ ██████     ██    ███████     ██ ████ ██ ███████ ██    ██ ██
+   ██   ██ ██   ██ ██   ██    ██    ██   ██     ██  ██  ██ ██   ██ ██    ██ ██
+   ██████  ██   ██ ██   ██    ██    ██   ██     ██      ██ ██   ██  ██████  ███████
```

<div align="center">

  ### 🔴 *"Fear. Fear attracts the fearful... the IPs."* 🔴

</div>

---

## What This Is

This directory contains simple text explanations of how Maul's reverse DNS enumeration works.

## Documentation Files

### Core Methods
- **`SOCKET_EXPLAINED.txt`** - How socket.gethostbyaddr() reverse lookup works
- **`PTR_EXPLAINED.txt`** - How DNS PTR record lookups work
- **`SSL_EXPLAINED.txt`** - How SSL certificate domain extraction works

### Understanding the Full Picture
- **`PTR_AND_SSL_TOGETHER.txt`** - How PTR and SSL work together to find domains from IPs

## Quick Summary

**What Maul Does:**
- Takes a list of IP addresses
- Runs PTR DNS lookups (finds what DNS says owns the IP)
- Scans SSL certificates on port 443 (finds all domains hosted on the IP)
- Combines results to give you maximum domain discovery

**Why It Works:**
- PTR finds official hostnames
- SSL finds all domains in the certificate (can be 50+ domains per IP)
- Together they cover each other's weaknesses

## Read This First

Start with `PTR_AND_SSL_TOGETHER.txt` to understand the full workflow.

Then read the individual method files if you want deeper technical details.

## Use Case

Perfect for:
- Infrastructure mapping
- Finding domains from IP ranges
- Reconnaissance before subdomain enumeration
- Feeding results to other tools (ffuf, subfinder, etc.)

---

*"Now you will experience the full power of the Dark Side... of DNS enumeration."*
