#!/usr/bin/env python3
"""
Domain Intelligence Gatherer
Comprehensive DNS analysis and domain intelligence collection
"""

import socket
import dns.resolver
import dns.reversename
import ssl
import OpenSSL
from datetime import datetime
from typing import Dict, List
import re

class IntelligenceGatherer:
    """Gather comprehensive intelligence about a domain"""
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
    
    def gather_intelligence(self, domain: str) -> Dict:
        """
        Gather comprehensive intelligence about a domain
        Returns DNS records, SSL info, and reputation indicators
        """
        intelligence = {
            'domain': domain,
            'dns_records': {},
            'ssl_certificate': {},
            'reputation_indicators': {},
            'security_features': {}
        }
        
        # DNS Records Analysis
        intelligence['dns_records'] = self.analyze_dns_records(domain)
        
        # SSL Certificate Analysis
        intelligence['ssl_certificate'] = self.analyze_ssl_certificate(domain)
        
        # Email Security Features
        intelligence['security_features'] = self.analyze_email_security(domain)
        
        # Reputation Indicators
        intelligence['reputation_indicators'] = self.calculate_reputation_indicators(intelligence)
        
        return intelligence
    
    def analyze_dns_records(self, domain: str) -> Dict:
        """Analyze various DNS records"""
        records = {
            'a_records': [],
            'aaaa_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'cname_records': [],
            'soa_record': None
        }
        
        # A Records (IPv4)
        try:
            answers = self.resolver.resolve(domain, 'A')
            records['a_records'] = [str(rdata) for rdata in answers]
        except:
            pass
        
        # AAAA Records (IPv6)
        try:
            answers = self.resolver.resolve(domain, 'AAAA')
            records['aaaa_records'] = [str(rdata) for rdata in answers]
        except:
            pass
        
        # MX Records (Mail Servers)
        try:
            answers = self.resolver.resolve(domain, 'MX')
            records['mx_records'] = [
                {'priority': rdata.preference, 'server': str(rdata.exchange)}
                for rdata in answers
            ]
        except:
            pass
        
        # NS Records (Name Servers)
        try:
            answers = self.resolver.resolve(domain, 'NS')
            records['ns_records'] = [str(rdata) for rdata in answers]
        except:
            pass
        
        # TXT Records (SPF, DKIM, DMARC, etc.)
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            records['txt_records'] = [str(rdata).strip('"') for rdata in answers]
        except:
            pass
        
        # CNAME Record
        try:
            answers = self.resolver.resolve(domain, 'CNAME')
            records['cname_records'] = [str(rdata) for rdata in answers]
        except:
            pass
        
        # SOA Record
        try:
            answers = self.resolver.resolve(domain, 'SOA')
            for rdata in answers:
                records['soa_record'] = {
                    'primary_ns': str(rdata.mname),
                    'admin': str(rdata.rname),
                    'serial': rdata.serial,
                    'refresh': rdata.refresh,
                    'retry': rdata.retry,
                    'expire': rdata.expire,
                    'minimum': rdata.minimum
                }
                break
        except:
            pass
        
        return records
    
    def analyze_ssl_certificate(self, domain: str) -> Dict:
        """Analyze SSL certificate details"""
        cert_info = {
            'valid': False,
            'issuer': None,
            'subject': None,
            'san_list': [],
            'not_before': None,
            'not_after': None,
            'days_until_expiry': None,
            'self_signed': False,
            'version': None
        }
        
        try:
            # Connect and get certificate
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as sock:
                sock.settimeout(5)
                sock.connect((domain, 443))
                cert_bin = sock.getpeercert(binary_form=True)
                cert_pem = ssl.DER_cert_to_PEM_cert(cert_bin)
                
                # Parse with OpenSSL
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
                
                # Extract issuer
                issuer = x509.get_issuer()
                cert_info['issuer'] = {
                    'CN': issuer.CN if hasattr(issuer, 'CN') else None,
                    'O': issuer.O if hasattr(issuer, 'O') else None,
                    'C': issuer.C if hasattr(issuer, 'C') else None
                }
                
                # Extract subject
                subject = x509.get_subject()
                cert_info['subject'] = {
                    'CN': subject.CN if hasattr(subject, 'CN') else None,
                    'O': subject.O if hasattr(subject, 'O') else None,
                    'C': subject.C if hasattr(subject, 'C') else None
                }
                
                # Check if self-signed
                cert_info['self_signed'] = (cert_info['issuer']['CN'] == cert_info['subject']['CN'])
                
                # Get SAN (Subject Alternative Names)
                for i in range(x509.get_extension_count()):
                    ext = x509.get_extension(i)
                    if 'subjectAltName' in str(ext.get_short_name()):
                        san_str = str(ext)
                        cert_info['san_list'] = re.findall(r'DNS:([^,\s]+)', san_str)
                
                # Get validity dates
                not_before = datetime.strptime(x509.get_notBefore().decode('utf-8'), '%Y%m%d%H%M%SZ')
                not_after = datetime.strptime(x509.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%SZ')
                
                cert_info['not_before'] = not_before.isoformat()
                cert_info['not_after'] = not_after.isoformat()
                
                # Calculate days until expiry
                days_left = (not_after - datetime.now()).days
                cert_info['days_until_expiry'] = days_left
                
                # Version
                cert_info['version'] = x509.get_version()
                cert_info['valid'] = True
                
        except Exception as e:
            cert_info['error'] = str(e)
        
        return cert_info
    
    def analyze_email_security(self, domain: str) -> Dict:
        """Analyze email security features (SPF, DMARC, DKIM)"""
        security = {
            'spf': {'exists': False, 'record': None, 'valid': False},
            'dmarc': {'exists': False, 'record': None, 'policy': None},
            'dkim_selector_found': False
        }
        
        # Check for SPF record in TXT records
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith('v=spf1'):
                    security['spf']['exists'] = True
                    security['spf']['record'] = txt
                    security['spf']['valid'] = True
        except:
            pass
        
        # Check for DMARC record
        try:
            dmarc_domain = f'_dmarc.{domain}'
            answers = self.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith('v=DMARC1'):
                    security['dmarc']['exists'] = True
                    security['dmarc']['record'] = txt
                    
                    # Extract policy
                    policy_match = re.search(r'p=([^;]+)', txt)
                    if policy_match:
                        security['dmarc']['policy'] = policy_match.group(1)
        except:
            pass
        
        # Try common DKIM selectors
        common_selectors = ['default', 'google', 'k1', 's1', 'selector1', 'selector2']
        for selector in common_selectors:
            try:
                dkim_domain = f'{selector}._domainkey.{domain}'
                answers = self.resolver.resolve(dkim_domain, 'TXT')
                if answers:
                    security['dkim_selector_found'] = True
                    break
            except:
                continue
        
        return security
    
    def calculate_reputation_indicators(self, intelligence: Dict) -> Dict:
        """Calculate reputation indicators based on gathered intelligence"""
        indicators = {
            'email_configured': False,
            'security_score': 0,
            'ssl_score': 0,
            'dns_health': 'unknown',
            'trust_level': 'low'
        }
        
        # Check if email is configured
        if intelligence['dns_records'].get('mx_records'):
            indicators['email_configured'] = True
        
        # Calculate security score (0-100)
        score = 0
        
        # SPF (+30)
        if intelligence['security_features']['spf']['exists']:
            score += 30
        
        # DMARC (+30)
        if intelligence['security_features']['dmarc']['exists']:
            score += 30
            # Extra points for strict policy
            policy = intelligence['security_features']['dmarc'].get('policy', '')
            if policy == 'reject':
                score += 10
            elif policy == 'quarantine':
                score += 5
        
        # DKIM (+20)
        if intelligence['security_features']['dkim_selector_found']:
            score += 20
        
        # SSL certificate (+20)
        ssl_info = intelligence['ssl_certificate']
        if ssl_info.get('valid'):
            score += 10
            if not ssl_info.get('self_signed'):
                score += 10
        
        indicators['security_score'] = min(score, 100)
        
        # SSL Score
        ssl_score = 0
        if ssl_info.get('valid'):
            ssl_score += 50
            if not ssl_info.get('self_signed'):
                ssl_score += 30
            
            days_left = ssl_info.get('days_until_expiry', 0)
            if days_left > 30:
                ssl_score += 20
            elif days_left > 7:
                ssl_score += 10
        
        indicators['ssl_score'] = ssl_score
        
        # DNS Health
        dns = intelligence['dns_records']
        if dns.get('a_records') and dns.get('ns_records'):
            if dns.get('mx_records'):
                indicators['dns_health'] = 'good'
            else:
                indicators['dns_health'] = 'fair'
        else:
            indicators['dns_health'] = 'poor'
        
        # Trust Level
        if indicators['security_score'] >= 70:
            indicators['trust_level'] = 'high'
        elif indicators['security_score'] >= 40:
            indicators['trust_level'] = 'medium'
        else:
            indicators['trust_level'] = 'low'
        
        return indicators

# Singleton instance
intelligence_gatherer = IntelligenceGatherer()
