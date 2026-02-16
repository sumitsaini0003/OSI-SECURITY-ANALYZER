#!/usr/bin/env python3
"""
Flask Web Application for Domain Spam Checker
Provides a web interface for the OSI domain analysis tool
"""

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import socket
import ssl
import csv
from urllib.parse import urlparse
import requests
import whois
import datetime
from pathlib import Path
from detection_engine import detection_engine
from email_analyzer import email_analyzer
from intelligence_gatherer import intelligence_gatherer
from url_analyzer import url_analyzer
from unified_scorer import unified_scorer

app = Flask(__name__)
CORS(app)

DEFAULT_TIMEOUT = 6
DATASET_PATH = Path.home() / "Downloads" / "domains.txt"

# ------------------------------
# Dataset Functions
# ------------------------------
def load_dataset():
    """Load domains dataset from CSV file"""
    domains = {}
    if DATASET_PATH.exists():
        if DATASET_PATH.is_dir():
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
                            'first_seen': row.get('first_seen', ''),
                            'last_seen': row.get('last_seen', ''),
                            'spam_flag': row.get('spam_flag', '0')
                        }
                else:
                    for line in f:
                        domain = line.strip().lower()
                        if domain:
                            domains[domain] = {'first_seen': '', 'last_seen': '', 'spam_flag': '0'}
        except Exception as e:
            print(f"Error reading dataset: {e}")
    else:
        try:
            DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(DATASET_PATH, "w", newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['domain', 'first_seen', 'last_seen', 'spam_flag'])
                writer.writeheader()
        except Exception as e:
            print(f"Error creating dataset file: {e}")
    return domains

def save_dataset(domains):
    """Save domains dataset to CSV file"""
    try:
        DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(DATASET_PATH, "w", newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['domain', 'first_seen', 'last_seen', 'spam_flag'])
            writer.writeheader()
            for d, info in domains.items():
                writer.writerow({'domain': d, **info})
        return True
    except Exception as e:
        print(f"Error saving dataset: {e}")
        return False

# ------------------------------
# Utility Functions
# ------------------------------
def normalize_url(url):
    """Normalize URL by adding https:// if missing"""
    url = url.strip()
    if not url:
        return None
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
    return url

def get_registrable_domain(hostname: str) -> str:
    """Extract registrable domain from hostname"""
    host = hostname.split(':')[0].lower()
    if host.startswith("www."):
        host = host[4:]
    return host

def parse_date(date_str):
    """Parse ISO format date string"""
    try:
        return datetime.datetime.fromisoformat(date_str)
    except:
        return None

def date_in_range(first, last, check_date):
    """Check if a date is within the spam date range"""
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
# Network & WHOIS Functions
# ------------------------------
def check_reachable(url):
    """Check if URL is reachable and return HTTP status"""
    try:
        resp = requests.head(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        if resp.status_code >= 400:
            resp = requests.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        return True, resp.status_code
    except Exception as e:
        return False, str(e)

def get_whois_info(domain):
    """Fetch WHOIS information for domain"""
    try:
        w = whois.whois(domain)
        return {
            "registrar": str(w.registrar) if w.registrar else None,
            "creation_date": str(w.creation_date) if w.creation_date else None,
            "expiration_date": str(w.expiration_date) if w.expiration_date else None
        }
    except Exception as e:
        return {
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "error": str(e)
        }

def get_dns_cert(domain):
    """Get DNS and SSL certificate information"""
    info = {}
    try:
        info['ip'] = socket.gethostbyname(domain)
    except Exception as e:
        info['ip'] = None
        info['ip_error'] = str(e)
    
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            info['ssl_notAfter'] = cert.get('notAfter')
    except Exception as e:
        info['ssl_notAfter'] = None
        info['ssl_error'] = str(e)
    
    return info

def analyze_heuristics(url_raw, domain):
    """Analyze URL for suspicious patterns"""
    heuristics = []
    if '@' in url_raw:
        heuristics.append("Contains '@' character (suspicious)")
    if '-' in domain:
        heuristics.append("Contains dash in domain name")
    if len(domain) > 30:
        heuristics.append("Domain name is very long")
    if domain.count('.') > 3:
        heuristics.append("Multiple subdomains detected")
    return heuristics

# ------------------------------
# Flask Routes
# ------------------------------
@app.route('/')
def index():
    """Render the main page"""
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze_domain():
    """Analyze a domain and return comprehensive results"""
    try:
        data = request.json
        url_raw = data.get('url', '').strip()
        date_input = data.get('date', '').strip()
        
        if not url_raw:
            return jsonify({'error': 'URL is required'}), 400
        
        # Normalize URL
        url = normalize_url(url_raw)
        if not url:
            return jsonify({'error': 'Invalid URL'}), 400
        
        parsed = urlparse(url)
        domain = get_registrable_domain(parsed.netloc)
        
        # Parse check date
        if not date_input:
            check_date = datetime.datetime.now()
        else:
            try:
                check_date = datetime.datetime.fromisoformat(date_input)
            except:
                check_date = datetime.datetime.now()
        
        # Load dataset
        domains_dataset = load_dataset()
        
        # Check dataset for spam info
        spam_flag = "0"
        first_seen = last_seen = ''
        dataset_found = False
        
        if domain in domains_dataset:
            dataset_found = True
            data_entry = domains_dataset[domain]
            first_seen, last_seen = data_entry['first_seen'], data_entry['last_seen']
            if date_in_range(first_seen, last_seen, check_date):
                spam_flag = data_entry['spam_flag']
        
        is_spam = spam_flag == "1"
        
        # Check reachability
        reachable, status = check_reachable(url)
        
        # Get DNS and SSL info
        dns_cert = get_dns_cert(domain)
        
        # Get WHOIS info
        whois_info = get_whois_info(domain)
        
        # Analyze heuristics (old method for backward compatibility)
        heuristics = analyze_heuristics(url_raw, domain)
        
        # ADVANCED DETECTION: Use new detection engine
        advanced_analysis = detection_engine.analyze_domain(domain, whois_info)
        
        # COMPREHENSIVE URL ANALYSIS (optional - can be slow)
        url_analysis_data = None
        include_url_analysis = data.get('include_url_analysis', False)
        if include_url_analysis:
            try:
                url_analysis_data = url_analyzer.analyze_url(url)
            except:
                pass
        
        # UNIFIED THREAT SCORING
        unified_score = unified_scorer.calculate_unified_score(
            domain=domain,
            whois_info=whois_info,
            url=url,
            include_url_analysis=include_url_analysis
        )
        
        # Combine old spam flag with new risk score
        # If dataset says it's spam, boost risk score
        if is_spam:
            advanced_analysis['risk_score'] = max(advanced_analysis['risk_score'], 85)
            unified_score['total_score'] = max(unified_score['total_score'], 85)
            if 'KNOWN_SPAM' not in advanced_analysis['flags']:
                advanced_analysis['flags'].append('USER_MARKED_SPAM')
                advanced_analysis['warnings'].append('Marked as spam by user in local dataset')
        
        # Determine final spam status based on unified score
        final_is_spam = is_spam or unified_score['total_score'] >= 60
        
        # OPTIONAL: Gather intelligence (can be disabled for faster response)
        include_intelligence = request.json.get('include_intelligence', False)
        intelligence_data = None
        if include_intelligence:
            try:
                intelligence_data = intelligence_gatherer.gather_intelligence(domain)
            except:
                pass
        
        # Build response
        response = {
            'domain': domain,
            'url': url,
            'check_date': check_date.date().isoformat(),
            'is_spam': final_is_spam,
            'dataset_found': dataset_found,
            'dataset_info': {
                'first_seen': first_seen,
                'last_seen': last_seen,
                'spam_flag': spam_flag
            },
            'reachability': {
                'reachable': reachable,
                'status': status
            },
            'dns_cert': dns_cert,
            'whois': whois_info,
            'heuristics': heuristics,
            # Advanced detection results (legacy)
            'risk_score': advanced_analysis['risk_score'],
            'threat_level': advanced_analysis['threat_level'],
            'detection_flags': advanced_analysis['flags'],
            'warnings': advanced_analysis['warnings'],
            'patterns_matched': advanced_analysis['patterns_matched'],
            # NEW: Unified threat scoring
            'unified_score': unified_score,
            # NEW: URL analysis (if requested)
            'url_analysis': url_analysis_data
        }
        
        # Add intelligence if requested
        if intelligence_data:
            response['intelligence'] = intelligence_data
        
        return jsonify(response)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/mark_spam', methods=['POST'])
def mark_spam():
    """Mark a domain as spam or not spam"""
    try:
        data = request.json
        domain = data.get('domain', '').strip().lower()
        is_spam = data.get('is_spam', False)
        date_str = data.get('date', '')
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        # Parse date
        if date_str:
            try:
                check_date = datetime.datetime.fromisoformat(date_str)
            except:
                check_date = datetime.datetime.now()
        else:
            check_date = datetime.datetime.now()
        
        # Load and update dataset
        domains_dataset = load_dataset()
        domains_dataset[domain] = {
            'first_seen': check_date.date().isoformat(),
            'last_seen': check_date.date().isoformat(),
            'spam_flag': '1' if is_spam else '0'
        }
        
        # Save dataset
        if save_dataset(domains_dataset):
            return jsonify({
                'success': True,
                'message': f'Domain marked as {"SPAM" if is_spam else "NOT SPAM"}'
            })
        else:
            return jsonify({'error': 'Failed to save dataset'}), 500
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dataset/stats', methods=['GET'])
def dataset_stats():
    """Get statistics about the dataset"""
    try:
        domains_dataset = load_dataset()
        spam_count = sum(1 for d in domains_dataset.values() if d['spam_flag'] == '1')
        
        return jsonify({
            'total_domains': len(domains_dataset),
            'spam_domains': spam_count,
            'clean_domains': len(domains_dataset) - spam_count
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze/email', methods=['POST'])
def analyze_email():
    """Analyze email headers for phishing and spoofing"""
    try:
        data = request.json
        headers = data.get('headers', '').strip()
        
        if not headers:
            return jsonify({'error': 'Email headers are required'}), 400
        
        # Analyze headers
        result = email_analyzer.analyze_headers(headers)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/intelligence/<domain>', methods=['GET'])
def get_intelligence(domain):
    """Get comprehensive domain intelligence"""
    try:
        # Gather intelligence
        intelligence = intelligence_gatherer.gather_intelligence(domain)
        
        return jsonify(intelligence)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("Starting Domain Spam Checker Web Server...")
    print("Access the application at: http://localhost:5001")
    app.run(debug=True, host='0.0.0.0', port=5001)
