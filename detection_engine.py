#!/usr/bin/env python3
"""
Advanced Detection Engine for Domain Spam Checker
Implements sophisticated algorithms for detecting phishing, typosquatting, and malicious domains
"""

import re
import difflib
from pathlib import Path
from datetime import datetime, timedelta
import json
from typing import Dict, List, Tuple
import unicodedata

# Suspicious TLDs (commonly used for phishing)
SUSPICIOUS_TLDS = [
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'click', 'link',
    'bid', 'country', 'stream', 'download', 'racing', 'loan', 'win', 'cricket',
    'accountant', 'date', 'faith', 'science', 'party', 'trade'
]

# High-value brands to check for typosquatting
PROTECTED_BRANDS = [
    'google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 'netflix',
    'instagram', 'twitter', 'linkedin', 'dropbox', 'github', 'yahoo', 'ebay',
    'walmart', 'target', 'bestbuy', 'chase', 'wellsfargo', 'bankofamerica',
    'citibank', 'americanexpress', 'visa', 'mastercard', 'stripe', 'square'
]

# Phishing keywords
PHISHING_KEYWORDS = [
    'verify', 'account', 'suspended', 'locked', 'security', 'update',
    'confirm', 'login', 'banking', 'paypal', 'alert', 'urgent', 'secure',
    'validate', 'restore', 'limited', 'unusual', 'activity', 'notification'
]

# Homograph lookalike characters (confusables)
HOMOGRAPH_MAP = {
    'a': ['а', 'ạ', 'ă', 'ȧ', 'ą'],  # Latin a vs Cyrillic а
    'c': ['с', 'ϲ', 'ⅽ'],
    'e': ['е', 'ė', 'ę', 'ě'],
    'o': ['о', 'ο', 'о', '0', 'օ'],
    'p': ['р', 'ρ'],
    'x': ['х', 'ҳ', 'ⅹ'],
    'y': ['у', 'ỿ'],
    'i': ['і', 'ı', '1', 'l'],
    's': ['ѕ', '$'],
    'h': ['һ'],
    'b': ['Ь', 'ḃ'],
    'n': ['п'],
    'm': ['м', 'ṁ'],
    'g': ['ɡ'],
    'l': ['1', 'ı', 'і'],
    'd': ['ԁ'],
    'u': ['υ', 'ս'],
    'v': ['ν', 'ѵ'],
    'w': ['ω', 'ẁ'],
    'z': ['ẓ'],
}

class DetectionEngine:
    """Advanced detection engine for analyzing domains"""
    
    def __init__(self):
        self.datasets_dir = Path(__file__).parent / "datasets"
        self.spam_domains = self._load_list('spam_domains.txt')
        self.legitimate_domains = self._load_list('legitimate_domains.txt')
        self.suspicious_patterns = self._load_patterns()
    
    def _load_list(self, filename: str) -> set:
        """Load a domain list from file"""
        filepath = self.datasets_dir / filename
        if filepath.exists():
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    return {line.strip().lower() for line in f if line.strip() and not line.startswith('#')}
            except Exception as e:
                print(f"Error loading {filename}: {e}")
        return set()
    
    def _load_patterns(self) -> dict:
        """Load suspicious patterns from JSON"""
        filepath = self.datasets_dir / 'suspicious_patterns.json'
        if filepath.exists():
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading patterns: {e}")
        return {}
    
    def analyze_domain(self, domain: str, whois_info: dict = None) -> Dict:
        """
        Comprehensive domain analysis
        Returns a dictionary with risk score and detected threats
        """
        domain = domain.lower().strip()
        results = {
            'risk_score': 0,
            'threat_level': 'low',  # low, medium, high, critical
            'flags': [],
            'warnings': [],
            'patterns_matched': []
        }
        
        # Check against spam database
        if domain in self.spam_domains:
            results['risk_score'] += 90
            results['flags'].append('KNOWN_SPAM')
            results['warnings'].append('Domain found in spam database')
        
        # Check against legitimate database
        if domain in self.legitimate_domains:
            results['risk_score'] = max(0, results['risk_score'] - 50)
            results['flags'].append('KNOWN_LEGITIMATE')
        
        # Typosquatting detection
        typo_result = self.check_typosquatting(domain)
        if typo_result['is_typosquatting']:
            results['risk_score'] += 70
            results['flags'].append('TYPOSQUATTING')
            results['warnings'].append(f"Possible typosquatting of '{typo_result['target_brand']}'")
            results['patterns_matched'].append(typo_result)
        
        # Homograph attack detection
        homograph_result = self.check_homograph_attack(domain)
        if homograph_result['is_homograph']:
            results['risk_score'] += 80
            results['flags'].append('HOMOGRAPH_ATTACK')
            results['warnings'].append(f"Unicode homograph attack detected: {homograph_result['details']}")
            results['patterns_matched'].append(homograph_result)
        
        # Suspicious TLD
        tld = domain.split('.')[-1] if '.' in domain else ''
        if tld in SUSPICIOUS_TLDS:
            results['risk_score'] += 30
            results['flags'].append('SUSPICIOUS_TLD')
            results['warnings'].append(f"TLD '.{tld}' is commonly used for phishing")
        
        # Phishing keywords
        keyword_matches = self.check_phishing_keywords(domain)
        if keyword_matches:
            results['risk_score'] += len(keyword_matches) * 15
            results['flags'].append('PHISHING_KEYWORDS')
            results['warnings'].append(f"Contains phishing keywords: {', '.join(keyword_matches)}")
        
        # URL structure analysis
        structure_score = self.analyze_url_structure(domain)
        results['risk_score'] += structure_score['score']
        if structure_score['flags']:
            results['flags'].extend(structure_score['flags'])
            results['warnings'].extend(structure_score['warnings'])
        
        # Domain age analysis (if WHOIS available)
        if whois_info and whois_info.get('creation_date'):
            age_score = self.analyze_domain_age(whois_info['creation_date'])
            results['risk_score'] += age_score['score']
            if age_score['warning']:
                results['warnings'].append(age_score['warning'])
                results['flags'].append('NEW_DOMAIN')
        
        # Cap risk score at 100
        results['risk_score'] = min(100, results['risk_score'])
        
        # Determine threat level
        if results['risk_score'] >= 80:
            results['threat_level'] = 'critical'
        elif results['risk_score'] >= 60:
            results['threat_level'] = 'high'
        elif results['risk_score'] >= 35:
            results['threat_level'] = 'medium'
        else:
            results['threat_level'] = 'low'
        
        return results
    
    def check_typosquatting(self, domain: str) -> Dict:
        """Check if domain is typosquatting a known brand"""
        domain_base = domain.split('.')[0] if '.' in domain else domain
        
        for brand in PROTECTED_BRANDS:
            # Check exact match
            if domain_base == brand:
                continue
            
            # Check similarity ratio
            similarity = difflib.SequenceMatcher(None, domain_base, brand).ratio()
            
            # Common typosquatting techniques
            techniques_detected = []
            
            # 1. Character substitution (o->0, i->1, etc.)
            if self._check_char_substitution(domain_base, brand):
                techniques_detected.append('character_substitution')
            
            # 2. Missing character
            if len(domain_base) == len(brand) - 1 and brand in domain_base:
                techniques_detected.append('character_omission')
            
            # 3. Extra character
            if len(domain_base) == len(brand) + 1 and all(c in domain_base for c in brand):
                techniques_detected.append('character_insertion')
            
            # 4. Transposition
            if sorted(domain_base) == sorted(brand):
                techniques_detected.append('character_transposition')
            
            # 5. High similarity
            if similarity > 0.75 and domain_base != brand:
                techniques_detected.append('high_similarity')
            
            if techniques_detected:
                return {
                    'is_typosquatting': True,
                    'target_brand': brand,
                    'similarity': similarity,
                    'techniques': techniques_detected
                }
        
        return {'is_typosquatting': False}
    
    def _check_char_substitution(self, domain: str, brand: str) -> bool:
        """Check for common character substitutions"""
        substitutions = {
            '0': 'o', '1': 'i', '1': 'l', '3': 'e', '4': 'a',
            '5': 's', '7': 't', '8': 'b', '@': 'a', '$': 's'
        }
        
        normalized_domain = domain
        for num, letter in substitutions.items():
            normalized_domain = normalized_domain.replace(num, letter)
        
        return normalized_domain == brand
    
    def check_homograph_attack(self, domain: str) -> Dict:
        """Detect Unicode homograph attacks"""
        # Check for non-ASCII characters
        has_unicode = any(ord(char) > 127 for char in domain)
        
        if not has_unicode:
            return {'is_homograph': False}
        
        # Try to find which characters are lookalikes
        confusable_chars = []
        for i, char in enumerate(domain):
            if ord(char) > 127:
                # Check if it's a lookalike
                for latin, lookalikes in HOMOGRAPH_MAP.items():
                    if char in lookalikes:
                        confusable_chars.append({
                            'position': i,
                            'char': char,
                            'lookalike_for': latin,
                            'unicode_name': unicodedata.name(char, 'UNKNOWN')
                        })
                        break
        
        if confusable_chars:
            # Try to reconstruct with Latin characters
            latin_version = domain
            for entry in confusable_chars:
                latin_version = latin_version.replace(entry['char'], entry['lookalike_for'])
            
            return {
                'is_homograph': True,
                'confusable_chars': confusable_chars,
                'details': f"Uses lookalike characters, possibly mimicking '{latin_version}'",
                'latin_equivalent': latin_version
            }
        elif has_unicode:
            return {
                'is_homograph': True,
                'confusable_chars': [],
                'details': 'Contains non-Latin characters (IDN domain)',
                'latin_equivalent': None
            }
        
        return {'is_homograph': False}
    
    def check_phishing_keywords(self, domain: str) -> List[str]:
        """Check for phishing-related keywords in domain"""
        matches = []
        domain_lower = domain.lower()
        
        for keyword in PHISHING_KEYWORDS:
            if keyword in domain_lower:
                matches.append(keyword)
        
        return matches
    
    def analyze_url_structure(self, domain: str) -> Dict:
        """Analyze URL structure for suspicious patterns"""
        score = 0
        flags = []
        warnings = []
        
        # Multiple subdomains
        parts = domain.split('.')
        if len(parts) > 3:
            score += 20
            flags.append('MANY_SUBDOMAINS')
            warnings.append(f"Domain has {len(parts) - 1} subdomains (suspicious)")
        
        # Very long domain
        if len(domain) > 30:
            score += 15
            flags.append('LONG_DOMAIN')
            warnings.append(f"Domain is unusually long ({len(domain)} characters)")
        
        # Contains IP address pattern
        if re.search(r'\d{1,3}[-_.]\d{1,3}[-_.]\d{1,3}[-_.]\d{1,3}', domain):
            score += 40
            flags.append('IP_IN_DOMAIN')
            warnings.append("Domain contains IP address pattern")
        
        # Excessive hyphens
        hyphen_count = domain.count('-')
        if hyphen_count > 2:
            score += 10 * hyphen_count
            flags.append('EXCESSIVE_HYPHENS')
            warnings.append(f"Domain has {hyphen_count} hyphens")
        
        # Contains @ symbol
        if '@' in domain:
            score += 50
            flags.append('AT_SYMBOL')
            warnings.append("Domain contains '@' symbol (highly suspicious)")
        
        # Digit percentage
        digit_count = sum(c.isdigit() for c in domain)
        if digit_count > len(domain) * 0.3:
            score += 20
            flags.append('MANY_DIGITS')
            warnings.append("Domain contains many digits")
        
        return {
            'score': score,
            'flags': flags,
            'warnings': warnings
        }
    
    def analyze_domain_age(self, creation_date_str: str) -> Dict:
        """Analyze domain age from WHOIS creation date"""
        try:
            # Handle various date formats
            if isinstance(creation_date_str, str):
                # Remove array brackets if present
                creation_date_str = creation_date_str.replace('[', '').replace(']', '').split(',')[0].strip().strip("'\"")
                
                # Try parsing
                try:
                    creation_date = datetime.fromisoformat(creation_date_str.replace('Z', '+00:00'))
                except:
                    # Try other common formats
                    for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%d-%m-%Y']:
                        try:
                            creation_date = datetime.strptime(creation_date_str.split()[0], fmt)
                            break
                        except:
                            continue
                    else:
                        return {'score': 0, 'warning': None}
            else:
                creation_date = creation_date_str
            
            age_days = (datetime.now() - creation_date).days
            
            # Very new domains are suspicious
            if age_days < 30:
                return {
                    'score': 40,
                    'warning': f"Domain is very new ({age_days} days old)"
                }
            elif age_days < 90:
                return {
                    'score': 20,
                    'warning': f"Domain is relatively new ({age_days} days old)"
                }
            else:
                return {'score': 0, 'warning': None}
        
        except Exception as e:
            print(f"Error parsing date: {e}")
            return {'score': 0, 'warning': None}

# Singleton instance
detection_engine = DetectionEngine()
