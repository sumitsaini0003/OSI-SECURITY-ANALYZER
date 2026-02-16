#!/usr/bin/env python3
"""
Email Header Analyzer for Domain Spam Checker
Analyzes email headers for phishing, spoofing, and authentication issues
"""

import re
from typing import Dict, List, Tuple
from email.parser import HeaderParser
from datetime import datetime

class EmailAnalyzer:
    """Analyze email headers for security threats"""
    
    def __init__(self):
        self.risk_score = 0
        self.warnings = []
        self.flags = []
    
    def analyze_headers(self, raw_headers: str) -> Dict:
        """
        Analyze raw email headers
        Returns comprehensive analysis with threat assessment
        """
        self.risk_score = 0
        self.warnings = []
        self.flags = []
        
        try:
            # Parse headers
            parser = HeaderParser()
            headers = parser.parsestr(raw_headers)
            
            # Extract key fields
            from_header = headers.get('From', '')
            reply_to = headers.get('Reply-To', '')
            return_path = headers.get('Return-Path', '')
            received_headers = headers.get_all('Received', [])
            auth_results = headers.get('Authentication-Results', '')
            
            # Extract domains
            from_domain = self.extract_domain(from_header)
            reply_to_domain = self.extract_domain(reply_to) if reply_to else None
            return_path_domain = self.extract_domain(return_path) if return_path else None
            
            # Analyze components
            self.check_sender_mismatch(from_header, from_domain, reply_to_domain, return_path_domain)
            self.analyze_authentication(auth_results, from_domain)
            self.analyze_received_path(received_headers)
            self.check_suspicious_patterns(from_header, headers.get('Subject', ''))
            
            # Determine threat level
            threat_level = self.calculate_threat_level()
            
            return {
                'from_address': from_header,
                'from_domain': from_domain,
                'reply_to': reply_to,
                'reply_to_domain': reply_to_domain,
                'return_path': return_path,
                'return_path_domain': return_path_domain,
                'authentication': self.parse_authentication(auth_results),
                'received_path': self.extract_received_ips(received_headers),
                'risk_score': self.risk_score,
                'threat_level': threat_level,
                'warnings': self.warnings,
                'flags': self.flags,
                'is_suspicious': self.risk_score >= 60
            }
        
        except Exception as e:
            return {
                'error': f'Failed to parse headers: {str(e)}',
                'risk_score': 0,
                'threat_level': 'unknown'
            }
    
    def extract_domain(self, email_field: str) -> str:
        """Extract domain from email address"""
        # Match email pattern: user@domain.com
        match = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', email_field)
        if match:
            return match.group(1).lower()
        return ''
    
    def check_sender_mismatch(self, from_header: str, from_domain: str, 
                             reply_to_domain: str, return_path_domain: str):
        """Check for sender address mismatches"""
        
        # Display name vs actual email mismatch
        if '<' in from_header and '>' in from_header:
            display_part = from_header.split('<')[0].strip()
            # Check if display name contains different domain
            domain_in_display = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', display_part)
            if domain_in_display and domain_in_display.group(1).lower() != from_domain:
                self.risk_score += 40
                self.flags.append('DISPLAY_NAME_MISMATCH')
                self.warnings.append(f'Display name contains different domain than actual sender')
        
        # Reply-To mismatch
        if reply_to_domain and reply_to_domain != from_domain:
            self.risk_score += 30
            self.flags.append('REPLY_TO_MISMATCH')
            self.warnings.append(f'Reply-To domain ({reply_to_domain}) differs from sender domain ({from_domain})')
        
        # Return-Path mismatch
        if return_path_domain and return_path_domain != from_domain:
            self.risk_score += 25
            self.flags.append('RETURN_PATH_MISMATCH')
            self.warnings.append(f'Return-Path domain ({return_path_domain}) differs from sender domain ({from_domain})')
    
    def parse_authentication(self, auth_results: str) -> Dict:
        """Parse Authentication-Results header"""
        result = {
            'spf': 'none',
            'dkim': 'none',
            'dmarc': 'none'
        }
        
        if not auth_results:
            return result
        
        auth_lower = auth_results.lower()
        
        # SPF
        if 'spf=pass' in auth_lower:
            result['spf'] = 'pass'
        elif 'spf=fail' in auth_lower:
            result['spf'] = 'fail'
        elif 'spf=softfail' in auth_lower:
            result['spf'] = 'softfail'
        elif 'spf=neutral' in auth_lower:
            result['spf'] = 'neutral'
        
        # DKIM
        if 'dkim=pass' in auth_lower:
            result['dkim'] = 'pass'
        elif 'dkim=fail' in auth_lower:
            result['dkim'] = 'fail'
        elif 'dkim=neutral' in auth_lower:
            result['dkim'] = 'neutral'
        
        # DMARC
        if 'dmarc=pass' in auth_lower:
            result['dmarc'] = 'pass'
        elif 'dmarc=fail' in auth_lower:
            result['dmarc'] = 'fail'
        
        return result
    
    def analyze_authentication(self, auth_results: str, from_domain: str):
        """Analyze email authentication results"""
        auth = self.parse_authentication(auth_results)
        
        # SPF failure
        if auth['spf'] == 'fail':
            self.risk_score += 50
            self.flags.append('SPF_FAIL')
            self.warnings.append('SPF authentication failed - sender not authorized')
        elif auth['spf'] == 'softfail':
            self.risk_score += 25
            self.flags.append('SPF_SOFTFAIL')
            self.warnings.append('SPF soft fail - sender verification inconclusive')
        elif auth['spf'] == 'none':
            self.risk_score += 15
            self.warnings.append('No SPF record found for sender domain')
        
        # DKIM failure
        if auth['dkim'] == 'fail':
            self.risk_score += 45
            self.flags.append('DKIM_FAIL')
            self.warnings.append('DKIM signature validation failed - email may be tampered')
        elif auth['dkim'] == 'none':
            self.risk_score += 10
            self.warnings.append('No DKIM signature present')
        
        # DMARC failure
        if auth['dmarc'] == 'fail':
            self.risk_score += 40
            self.flags.append('DMARC_FAIL')
            self.warnings.append('DMARC policy check failed - likely spoofed email')
        elif auth['dmarc'] == 'none':
            self.risk_score += 10
            self.warnings.append('No DMARC policy found for domain')
    
    def extract_received_ips(self, received_headers: List[str]) -> List[Dict]:
        """Extract IP addresses and servers from Received headers"""
        path = []
        
        for received in received_headers[:5]:  # Limit to first 5 hops
            # Extract IP
            ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', received)
            # Extract server name
            from_match = re.search(r'from\s+([a-zA-Z0-9.-]+)', received, re.IGNORECASE)
            
            hop = {}
            if ip_match:
                hop['ip'] = ip_match.group(1)
            if from_match:
                hop['server'] = from_match.group(1)
            
            if hop:
                path.append(hop)
        
        return path
    
    def analyze_received_path(self, received_headers: List[str]):
        """Analyze the email routing path"""
        if not received_headers:
            self.risk_score += 20
            self.warnings.append('No Received headers found - unusual for legitimate email')
            return
        
        # Too many hops can indicate relay through suspicious servers
        if len(received_headers) > 10:
            self.risk_score += 15
            self.flags.append('MANY_HOPS')
            self.warnings.append(f'Email passed through {len(received_headers)} servers (suspicious)')
    
    def check_suspicious_patterns(self, from_header: str, subject: str):
        """Check for common phishing patterns"""
        
        # Freemail domains (when impersonating companies)
        freemail_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 
                           'aol.com', 'mail.com', 'protonmail.com']
        
        from_lower = from_header.lower()
        
        # Check for business impersonation from freemail
        business_keywords = ['bank', 'paypal', 'amazon', 'microsoft', 'apple', 
                            'support', 'security', 'admin', 'service']
        
        for keyword in business_keywords:
            if keyword in from_lower:
                for freemail in freemail_domains:
                    if freemail in from_lower:
                        self.risk_score += 35
                        self.flags.append('FREEMAIL_IMPERSONATION')
                        self.warnings.append(f'Business-related sender using free email service')
                        break
        
        # Urgent subject lines
        urgent_keywords = ['urgent', 'immediate', 'action required', 'suspended', 
                          'verify', 'confirm', 'expires', 'limited time']
        
        subject_lower = subject.lower()
        for keyword in urgent_keywords:
            if keyword in subject_lower:
                self.risk_score += 10
                break
    
    def calculate_threat_level(self) -> str:
        """Calculate threat level based on risk score"""
        if self.risk_score >= 80:
            return 'critical'
        elif self.risk_score >= 60:
            return 'high'
        elif self.risk_score >= 35:
            return 'medium'
        else:
            return 'low'

# Singleton instance
email_analyzer = EmailAnalyzer()
