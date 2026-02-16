#!/usr/bin/env python3
"""
URL Analyzer - Redirect Chain Mapping and Webpage Inspection
Tracks redirect chains and inspects webpage content for threats
"""

import requests
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Tuple
import re
from bs4 import BeautifulSoup

class URLAnalyzer:
    """Analyze URLs for redirects and inspect webpage content"""
    
    def __init__(self):
        self.max_redirects = 10
        self.timeout = 10
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    
    def analyze_url(self, url: str) -> Dict:
        """
        Complete URL analysis including redirects and content inspection
        """
        result = {
            'original_url': url,
            'redirect_chain': [],
            'final_url': None,
            'total_redirects': 0,
            'suspicious_redirects': False,
            'webpage_analysis': {},
            'risk_factors': []
        }
        
        # Map redirect chain
        redirect_chain = self.map_redirect_chain(url)
        result['redirect_chain'] = redirect_chain
        result['total_redirects'] = len(redirect_chain) - 1
        
        if redirect_chain:
            result['final_url'] = redirect_chain[-1]['url']
            
            # Check for suspicious redirect patterns
            result['suspicious_redirects'] = self.check_suspicious_redirects(redirect_chain)
            
            # Inspect final webpage
            try:
                result['webpage_analysis'] = self.inspect_webpage(result['final_url'])
            except:
                pass
        
        # Calculate risk factors
        result['risk_factors'] = self.calculate_risk_factors(result)
        
        return result
    
    def map_redirect_chain(self, url: str) -> List[Dict]:
        """
        Map the complete redirect chain
        Returns list of redirect hops with status codes
        """
        chain = []
        current_url = url
        
        try:
            session = requests.Session()
            session.max_redirects = 0  # Handle redirects manually
            session.headers['User-Agent'] = self.user_agent
            
            for hop in range(self.max_redirects):
                try:
                    response = session.get(
                        current_url,
                        allow_redirects=False,
                        timeout=self.timeout,
                        verify=False  # Skip SSL verification for analysis
                    )
                    
                    hop_info = {
                        'hop': hop + 1,
                        'url': current_url,
                        'status_code': response.status_code,
                        'domain': urlparse(current_url).netloc,
                        'is_redirect': response.status_code in [301, 302, 303, 307, 308]
                    }
                    
                    chain.append(hop_info)
                    
                    # Check if this is a redirect
                    if response.status_code in [301, 302, 303, 307, 308]:
                        # Get redirect location
                        location = response.headers.get('Location', '')
                        if not location:
                            break
                        
                        # Handle relative URLs
                        if not location.startswith('http'):
                            location = urljoin(current_url, location)
                        
                        current_url = location
                    else:
                        # Final destination reached
                        break
                
                except requests.exceptions.RequestException:
                    break
        
        except Exception as e:
            pass
        
        return chain
    
    def check_suspicious_redirects(self, chain: List[Dict]) -> bool:
        """
        Check for suspicious redirect patterns
        """
        if len(chain) < 2:
            return False
        
        # Too many redirects
        if len(chain) > 5:
            return True
        
        # Check for domain changes
        domains = [hop['domain'] for hop in chain]
        unique_domains = set(domains)
        
        # Multiple domain changes are suspicious
        if len(unique_domains) > 3:
            return True
        
        # Check for http -> https downgrades
        for i in range(len(chain) - 1):
            current_url = chain[i]['url']
            next_url = chain[i + 1]['url']
            
            if current_url.startswith('https://') and next_url.startswith('http://'):
                return True  # HTTPS to HTTP downgrade is very suspicious
        
        return False
    
    def inspect_webpage(self, url: str) -> Dict:
        """
        Inspect webpage content for threats
        """
        analysis = {
            'title': None,
            'meta_description': None,
            'forms': 0,
            'password_fields': 0,
            'external_links': 0,
            'iframes': 0,
            'suspicious_keywords': [],
            'javascript_suspicious': False,
            'content_length': 0
        }
        
        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                headers={'User-Agent': self.user_agent},
                verify=False
            )
            
            analysis['content_length'] = len(response.content)
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract title
            if soup.title:
                analysis['title'] = soup.title.string
            
            # Meta description
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            if meta_desc:
                analysis['meta_description'] = meta_desc.get('content', '')
            
            # Count forms
            forms = soup.find_all('form')
            analysis['forms'] = len(forms)
            
            # Count password fields (phishing indicator)
            password_inputs = soup.find_all('input', attrs={'type': 'password'})
            analysis['password_fields'] = len(password_inputs)
            
            # Count external links
            domain = urlparse(url).netloc
            links = soup.find_all('a', href=True)
            external_count = 0
            for link in links:
                href = link['href']
                if href.startswith('http') and domain not in href:
                    external_count += 1
            analysis['external_links'] = external_count
            
            # Count iframes (often used in attacks)
            iframes = soup.find_all('iframe')
            analysis['iframes'] = len(iframes)
            
            # Check for suspicious keywords
            page_text = soup.get_text().lower()
            suspicious_words = [
                'verify account', 'suspended account', 'confirm identity',
                'update payment', 'verify payment', 'click here immediately',
                'account will be closed', 'unusual activity', 'verification required',
                'confirm your identity', 'urgent action required'
            ]
            
            found_keywords = []
            for word in suspicious_words:
                if word in page_text:
                    found_keywords.append(word)
            
            analysis['suspicious_keywords'] = found_keywords
            
            # Check JavaScript for suspicious patterns
            scripts = soup.find_all('script')
            js_suspicious_patterns = [
                'eval(', 'document.write', 'innerHTML', 
                'fromCharCode', 'unescape', 'atob'
            ]
            
            for script in scripts:
                script_text = script.string or ''
                for pattern in js_suspicious_patterns:
                    if pattern in script_text:
                        analysis['javascript_suspicious'] = True
                        break
        
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def calculate_risk_factors(self, analysis_result: Dict) -> List[str]:
        """
        Calculate risk factors from analysis
        """
        risks = []
        
        # Redirect risks
        if analysis_result['total_redirects'] > 5:
            risks.append(f"Excessive redirects ({analysis_result['total_redirects']} hops)")
        
        if analysis_result['suspicious_redirects']:
            risks.append("Suspicious redirect pattern detected")
        
        # Domain changes in redirect chain
        if analysis_result['redirect_chain']:
            domains = set(hop['domain'] for hop in analysis_result['redirect_chain'])
            if len(domains) > 3:
                risks.append(f"Multiple domain changes ({len(domains)} different domains)")
        
        # Webpage content risks
        webpage = analysis_result.get('webpage_analysis', {})
        
        if webpage.get('password_fields', 0) > 0:
            risks.append(f"{webpage['password_fields']} password field(s) detected")
        
        if webpage.get('iframes', 0) > 3:
            risks.append(f"Multiple iframes ({webpage['iframes']}) - possible clickjacking")
        
        if webpage.get('suspicious_keywords'):
            risks.append(f"Suspicious keywords found: {', '.join(webpage['suspicious_keywords'][:3])}")
        
        if webpage.get('javascript_suspicious'):
            risks.append("Suspicious JavaScript patterns detected")
        
        return risks

# Singleton instance
url_analyzer = URLAnalyzer()
