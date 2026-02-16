#!/usr/bin/env python3
"""
Unified Threat Scoring System
Combines all detection modules into a single comprehensive threat assessment
"""

from typing import Dict, List
from detection_engine import detection_engine
from email_analyzer import email_analyzer
from intelligence_gatherer import intelligence_gatherer
from url_analyzer import url_analyzer

class UnifiedScorer:
    """Calculate unified threat score from all analysis modules"""
    
    def __init__(self):
        # Scoring weights (must sum to 100)
        self.weights = {
            'pattern_detection': 30,    # Typosquatting, homographs, patterns
            'url_analysis': 25,          # Redirects, webpage content
            'domain_intelligence': 20,   # DNS, SSL, email security
            'reputation': 15,            # Spam database, known threats
            'domain_age': 10             # WHOIS age analysis
        }
    
    def calculate_unified_score(self, domain: str, whois_info: Dict = None, 
                               url: str = None, include_url_analysis: bool = False) -> Dict:
        """
        Calculate comprehensive unified threat score
        
        Returns:
            score_breakdown: individual category scores
            total_score: weighted average (0-100)
            threat_level: low/medium/high/critical
            confidence: confidence level in assessment
            contributing_factors: list of risk contributors
        """
        
        scores = {}
        contributing_factors = []
        
        # 1. Pattern Detection Score (30%)
        pattern_result = detection_engine.analyze_domain(domain, whois_info or {})
        scores['pattern_detection'] = min(pattern_result['risk_score'], 100)
        
        if pattern_result['flags']:
            contributing_factors.extend([
                f"Pattern: {flag}" for flag in pattern_result['flags'][:3]
            ])
        
        # 2. URL Analysis Score (25%) - optional
        scores['url_analysis'] = 0
        if include_url_analysis and url:
            try:
                url_result = url_analyzer.analyze_url(url)
                url_score = self._calculate_url_score(url_result)
                scores['url_analysis'] = url_score
                
                if url_result['risk_factors']:
                    contributing_factors.extend([
                        f"URL: {factor}" for factor in url_result['risk_factors'][:2]
                    ])
            except:
                pass
        
        # 3. Domain Intelligence Score (20%)
        intelligence_score = 0
        try:
            intel = intelligence_gatherer.gather_intelligence(domain)
            intelligence_score = self._calculate_intelligence_score(intel)
            scores['domain_intelligence'] = intelligence_score
            
            # Add contributing factors
            if intel['reputation_indicators']['security_score'] < 50:
                contributing_factors.append(f"Intelligence: Low security score ({intel['reputation_indicators']['security_score']}/100)")
        except:
            scores['domain_intelligence'] = 50  # Neutral if can't analyze
        
        # 4. Reputation Score (15%)
        # Check if domain appears in spam database
        reputation_score = 0
        if 'KNOWN_SPAM' in pattern_result['flags']:
            reputation_score = 100
            contributing_factors.append("Reputation: Found in spam database")
        elif 'KNOWN_LEGITIMATE' in pattern_result['flags']:
            reputation_score = 0
            contributing_factors.append("Reputation: Verified legitimate domain")
        else:
            reputation_score = 50  # Unknown
        
        scores['reputation'] = reputation_score
        
        # 5. Domain Age Score (10%)
        age_score = 0
        if whois_info and whois_info.get('creation_date'):
            age_score = self._calculate_age_score(whois_info)
        else:
            age_score = 50  # Unknown age = neutral
        
        scores['domain_age'] = age_score
        
        # Calculate weighted total score
        total_score = 0
        for category, score in scores.items():
            weight = self.weights.get(category, 0)
            total_score += (score * weight / 100)
        
        # Determine threat level
        threat_level = self._determine_threat_level(total_score)
        
        # Calculate confidence
        confidence = self._calculate_confidence(scores, include_url_analysis)
        
        return {
            'score_breakdown': scores,
            'weights': self.weights,
            'total_score': round(total_score, 1),
            'threat_level': threat_level,
            'confidence': confidence,
            'contributing_factors': contributing_factors[:8],  # Limit to top 8
            'assessment_summary': self._generate_summary(total_score, threat_level, confidence)
        }
    
    def _calculate_url_score(self, url_result: Dict) -> int:
        """Calculate risk score from URL analysis"""
        score = 0
        
        # Redirect count
        redirects = url_result.get('total_redirects', 0)
        if redirects > 5:
            score += 40
        elif redirects > 2:
            score += 20
        
        # Suspicious redirects
        if url_result.get('suspicious_redirects'):
            score += 30
        
        # Webpage analysis
        webpage = url_result.get('webpage_analysis', {})
        
        # Password fields (phishing indicator)
        if webpage.get('password_fields', 0) > 0:
            score += 25
        
        # Suspicious keywords
        keywords = webpage.get('suspicious_keywords', [])
        score += min(len(keywords) * 10, 30)
        
        # Suspicious JavaScript
        if webpage.get('javascript_suspicious'):
            score += 15
        
        # Many iframes
        if webpage.get('iframes', 0) > 3:
            score += 20
        
        return min(score, 100)
    
    def _calculate_intelligence_score(self, intel: Dict) -> int:
        """Calculate risk score from domain intelligence (inverse of security)"""
        security_score = intel['reputation_indicators'].get('security_score', 50)
        
        # Invert security score to risk score
        # High security = low risk
        risk_score = 100 - security_score
        
        # Adjustments
        if intel['reputation_indicators'].get('trust_level') == 'high':
            risk_score = max(0, risk_score - 20)
        elif intel['reputation_indicators'].get('trust_level') == 'low':
            risk_score = min(100, risk_score + 20)
        
        return risk_score
    
    def _calculate_age_score(self, whois_info: Dict) -> int:
        """Calculate risk score based on domain age"""
        from datetime import datetime
        
        try:
            creation_date_str = str(whois_info.get('creation_date', ''))
            
            # Parse date
            if '[' in creation_date_str:
                creation_date_str = creation_date_str.replace('[', '').replace(']', '').replace("'", "").split(',')[0].strip()
            
            creation_date = datetime.fromisoformat(creation_date_str.split(' ')[0])
            age_days = (datetime.now() - creation_date).days
            
            # Scoring based on age
            if age_days < 30:
                return 80  # Very new = high risk
            elif age_days < 90:
                return 60  # Recent = medium-high risk
            elif age_days < 365:
                return 40  # Less than a year = medium risk
            elif age_days < 365 * 3:
                return 20  # 1-3 years = low-medium risk
            else:
                return 10  # Older than 3 years = low risk
        
        except:
            return 50  # Unknown age = neutral
    
    def _determine_threat_level(self, score: float) -> str:
        """Determine threat level from score"""
        if score >= 80:
            return 'critical'
        elif score >= 60:
            return 'high'
        elif score >= 35:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_confidence(self, scores: Dict, has_url_analysis: bool) -> str:
        """Calculate confidence in the assessment"""
        # Count how many scores are not neutral (50)
        decisive_scores = sum(1 for score in scores.values() if abs(score - 50) > 20)
        
        total_factors = len(scores)
        
        if has_url_analysis:
            total_factors += 1  # URL analysis adds confidence
        
        confidence_ratio = decisive_scores / total_factors
        
        if confidence_ratio >= 0.7:
            return 'high'
        elif confidence_ratio >= 0.4:
            return 'medium'
        else:
            return 'low'
    
    def _generate_summary(self, score: float, threat_level: str, confidence: str) -> str:
        """Generate human-readable assessment summary"""
        if threat_level == 'critical':
            return f"CRITICAL THREAT detected with {confidence} confidence. Immediate action recommended."
        elif threat_level == 'high':
            return f"HIGH RISK domain with {confidence} confidence. Exercise extreme caution."
        elif threat_level == 'medium':
            return f"MEDIUM RISK detected with {confidence} confidence. Verify legitimacy before proceeding."
        else:
            return f"LOW RISK assessment with {confidence} confidence. Domain appears safe."

# Singleton instance
unified_scorer = UnifiedScorer()
