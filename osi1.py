#!/usr/bin/env python3
# hi_spam_checker_extended.py
# Requires: requests, python-whois
# Dataset: ~/Downloads/domains.txt (CSV: domain,first_seen,last_seen,spam_flag)

import socket, ssl, csv
from urllib.parse import urlparse
import requests
import whois
import datetime
from pathlib import Path

DEFAULT_TIMEOUT = 6
DATASET_PATH = Path.home() / "Downloads" / "domains.txt"

# ------------------------------
# Load dataset
# ------------------------------
def load_dataset():
    domains = {}
    if DATASET_PATH.exists():
        if DATASET_PATH.is_dir():
            print(f"Warning: Dataset path {DATASET_PATH} is a directory, not a file.")
            return domains
        try:
            with open(DATASET_PATH, "r", newline='', encoding='utf-8') as f:
                first_line = f.readline()
                f.seek(0)
                if ',' in first_line:
                    reader = csv.DictReader(f)
                    for row in reader:
                        domain = row['domain'].lower()
                        domains[domain] = {
                            'first_seen': row.get('first_seen',''),
                            'last_seen': row.get('last_seen',''),
                            'spam_flag': row.get('spam_flag','0')
                        }
                else:
                    for line in f:
                        domain = line.strip().lower()
                        if domain:
                            domains[domain] = {'first_seen':'', 'last_seen':'', 'spam_flag':'0'}
        except Exception as e:
            print(f"Error reading dataset: {e}")
    else:
        try:
            DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(DATASET_PATH, "w", newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['domain','first_seen','last_seen','spam_flag'])
                writer.writeheader()
        except Exception as e:
            print(f"Error creating dataset file: {e}")
    return domains

def save_dataset(domains):
    try:
        DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(DATASET_PATH, "w", newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['domain','first_seen','last_seen','spam_flag'])
            writer.writeheader()
            for d, info in domains.items():
                writer.writerow({'domain': d, **info})
    except Exception as e:
        print(f"Error saving dataset: {e}")

domains_dataset = load_dataset()
print(f"Loaded {len(domains_dataset)} domains from dataset.")

# ------------------------------
# Utility functions
# ------------------------------
def normalize_url(url):
    url = url.strip()
    if not url:
        return None
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
    return url

def get_registrable_domain(hostname: str) -> str:
    host = hostname.split(':')[0].lower()
    if host.startswith("www."):
        host = host[4:]
    return host

def parse_date(date_str):
    try:
        return datetime.datetime.fromisoformat(date_str)
    except:
        return None

def date_in_range(first, last, check_date):
    first_dt = parse_date(first)
    last_dt = parse_date(last)
    if not first_dt and not last_dt:
        return False
    if first_dt and last_dt:
        return first_dt <= check_date <= last_dt
    if first_dt:
        return check_date >= first_dt
    if last_dt:
        return check_date <= last_dt
    return False

# ------------------------------
# Network & WHOIS functions
# ------------------------------
def check_reachable(url):
    try:
        resp = requests.head(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        if resp.status_code >= 400:
            resp = requests.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        return True, resp.status_code
    except:
        return False, None

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": w.creation_date,
            "expiration_date": w.expiration_date
        }
    except:
        return {"registrar": None, "creation_date": None, "expiration_date": None}

def get_dns_cert(domain):
    info = {}
    try:
        info['ip'] = socket.gethostbyname(domain)
    except:
        info['ip'] = None
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain,443))
            cert = s.getpeercert()
            info['ssl_notAfter'] = cert.get('notAfter')
    except:
        info['ssl_notAfter'] = None
    return info

# ------------------------------
# Main analyzer
# ------------------------------
def analyze(url_raw):
    url = normalize_url(url_raw)
    if not url:
        print("Empty URL")
        return
    parsed = urlparse(url)
    domain = get_registrable_domain(parsed.netloc)

    # ------------------------------
    # Check user-provided date
    # ------------------------------
    date_input = input("Enter date to check (YYYY-MM-DD) or leave empty for today: ").strip()
    if not date_input:
        check_date = datetime.datetime.now()
    else:
        try:
            check_date = datetime.datetime.fromisoformat(date_input)
        except:
            print("Invalid date format, using today.")
            check_date = datetime.datetime.now()

    # ------------------------------
    # Check dataset
    # ------------------------------
    spam_flag = "0"
    first_seen = last_seen = ''
    if domain in domains_dataset:
        data = domains_dataset[domain]
        first_seen, last_seen = data['first_seen'], data['last_seen']
        if date_in_range(first_seen, last_seen, check_date):
            spam_flag = data['spam_flag']
        print(f"Dataset info: first_seen={first_seen}, last_seen={last_seen}, spam_flag={spam_flag}")
    else:
        print("Domain not found in dataset.")

    if spam_flag == "1":
        print(f"❌ ALERT: {domain} is considered SPAM on {check_date.date()}")
    else:
        print(f"✅ {domain} is not considered SPAM on {check_date.date()}")

    # ------------------------------
    # Reachable, DNS, SSL, WHOIS
    # ------------------------------
    reachable, status = check_reachable(url)
    print(f"[REACHABLE] HTTP status: {status}" if reachable else "[NOT REACHABLE]")

    dns_cert = get_dns_cert(domain)
    print(f"IP: {dns_cert.get('ip')}, SSL expiry: {dns_cert.get('ssl_notAfter')}")

    whois_info = get_whois_info(domain)
    print(f"WHOIS: Registrar={whois_info.get('registrar')}, Creation={whois_info.get('creation_date')}, Expiration={whois_info.get('expiration_date')}")

    # ------------------------------
    # Heuristics
    # ------------------------------
    heuristics = []
    if '@' in url_raw:
        heuristics.append("contains '@' (suspicious)")
    if '-' in domain:
        heuristics.append("dash in domain name")
    if heuristics:
        print("Heuristics flags:", heuristics)

    # ------------------------------
    # User can mark domain as spam/not spam
    # ------------------------------
    choice = input("Do you want to mark this domain as spam? (y/n/skip): ").strip().lower()
    if choice == 'y':
        domains_dataset[domain] = {
            'first_seen': check_date.date().isoformat(),
            'last_seen': check_date.date().isoformat(),
            'spam_flag': '1'
        }
        print(f"{domain} marked as SPAM in dataset.")
    elif choice == 'n':
        domains_dataset[domain] = {
            'first_seen': check_date.date().isoformat(),
            'last_seen': check_date.date().isoformat(),
            'spam_flag': '0'
        }
        print(f"{domain} marked as NOT SPAM in dataset.")
    else:
        print("No changes made to dataset.")

    save_dataset(domains_dataset)
    print("-"*60)

# ------------------------------
# Main loop
# ------------------------------
if __name__ == "__main__":
    print("Enter URL to check (type 'exit' to quit)")
    while True:
        u = input("URL> ").strip()
        if not u or u.lower() in ('exit','quit'):
            break
        analyze(u)