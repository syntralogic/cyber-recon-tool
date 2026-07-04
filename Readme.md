# 🔍 Subdomain Recon + Admin Panel Finder v3.0

A powerful Python-based reconnaissance tool for cybersecurity learning and authorized penetration testing.  
It helps in discovering subdomains, detecting misconfigurations, analyzing HTTP responses, and finding exposed admin panels.

⚠️ **Disclaimer:** This tool is strictly for educational purposes and authorized security testing only. Do not use on any target without permission.

---

## 👨‍💻 Author

Muhammad Alee  
Cybersecurity Enthusiast | Ethical Hacking Learner 

## 🚀 Features

### 🔹 Subdomain Enumeration
- Brute-force subdomain discovery using built-in wordlist
- Fast multithreaded scanning

### 🔹 DNS & IP Analysis
- Resolves IP addresses of subdomains
- Detects private/internal IP exposure
- Cloudflare protection detection

### 🔹 HTTP/HTTPS Analysis
- Checks response status codes
- Server header detection
- Cloudflare origin exposure detection

### 🔹 Direct IP Access Testing
- Detects misconfigured servers allowing direct IP access
- Identifies bypass possibilities

### 🔹 MX Record Lookup
- Fetches mail exchange records of target domain

### 🔹 Admin Panel Finder
- Scans common admin paths like:
  - `/admin`
  - `/login`
  - `/dashboard`
  - `/cpanel`
  - `/wp-admin`
- Detects:
  - 200 OK (Accessible)
  - 403 Forbidden (Exists but blocked)
  - Redirects
  - Hidden panels

### 🔹 Cloudflare Bypass Detection
- Identifies possible origin server exposure
- Detects misconfigured security setups

---

## 📁 Project Structure
