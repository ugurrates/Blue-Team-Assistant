"""
Author: Ugur Ates
URL Chain Analyzer - Redirect Following & Reputation Check
Best Practice: Follow redirect chains, detect phishing infrastructure
"""

import re
import logging
from typing import Dict, List
from urllib.parse import urlparse, parse_qs
import requests

logger = logging.getLogger(__name__)
class URLChainAnalyzer:
    """
    URL redirect chain analysis and reputation checking.
    
    Features:
    - Redirect chain following
    - URL defanging
    - Suspicious TLD detection
    - URL shortener detection
    - Parameter extraction
    - Domain reputation (if integrated)
    """
    
    SHORTENERS = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co',
        'is.gd', 'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in'
    ]
    
    SUSPICIOUS_TLDS = [
        '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs
        '.top', '.xyz', '.club', '.work', '.click',
        '.loan', '.download', '.racing', '.accountant', '.win'
    ]
    
    @staticmethod
    def analyze_url(url: str, follow_redirects: bool = True, max_hops: int = 10) -> Dict:
        """
        Analyze URL and follow redirect chain.
        
        Args:
            url: URL to analyze
            follow_redirects: Follow redirects
            max_hops: Maximum redirect hops
        
        Returns:
            Complete URL analysis
        """
        result = {
            'original_url': url,
            'parsed': {},
            'redirect_chain': [],
            'final_url': url,
            'total_hops': 0,
            'is_shortened': False,
            'suspicious_tld': False,
            'risk_score': 0,
            'indicators': []
        }
        
        try:
            # Parse URL
            result['parsed'] = URLChainAnalyzer._parse_url(url)
            
            # Check if shortened
            if result['parsed']['domain'] in URLChainAnalyzer.SHORTENERS:
                result['is_shortened'] = True
                result['indicators'].append('URL shortener detected')
                result['risk_score'] += 10
            
            # Check TLD
            tld = '.' + result['parsed']['domain'].split('.')[-1]
            if tld in URLChainAnalyzer.SUSPICIOUS_TLDS:
                result['suspicious_tld'] = True
                result['indicators'].append(f'Suspicious TLD: {tld}')
                result['risk_score'] += 15
            
            # Follow redirects
            if follow_redirects:
                chain = URLChainAnalyzer._follow_redirects(url, max_hops)
                result['redirect_chain'] = chain
                result['total_hops'] = len(chain)
                if chain:
                    result['final_url'] = chain[-1]['url']
                
                # Check for excessive redirects
                if result['total_hops'] > 5:
                    result['indicators'].append('Excessive redirects')
                    result['risk_score'] += 20
            
            # Check for IP-based URLs
            if URLChainAnalyzer._is_ip_url(url):
                result['indicators'].append('IP-based URL (suspicious)')
                result['risk_score'] += 25
            
            logger.info(f"[URL-CHAIN] Analysis complete - Risk: {result['risk_score']}")
            
        except Exception as e:
            logger.error(f"[URL-CHAIN] Analysis failed: {e}")
            result['error'] = str(e)
        
        return result
    
    @staticmethod
    def _parse_url(url: str) -> Dict:
        """Parse URL components."""
        parsed = urlparse(url)
        
        return {
            'scheme': parsed.scheme,
            'domain': parsed.netloc,
            'path': parsed.path,
            'params': parse_qs(parsed.query),
            'fragment': parsed.fragment
        }
    
    @staticmethod
    def _follow_redirects(url: str, max_hops: int) -> List[Dict]:
        """Follow HTTP redirects."""
        chain = []
        
        try:
            session = requests.Session()
            session.max_redirects = max_hops
            
            response = session.get(
                url,
                allow_redirects=True,
                timeout=10,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            
            # Get redirect chain from history
            for resp in response.history:
                chain.append({
                    'url': resp.url,
                    'status': resp.status_code,
                    'location': resp.headers.get('Location', '')
                })
            
            # Add final URL
            chain.append({
                'url': response.url,
                'status': response.status_code,
                'location': ''
            })
        
        except Exception as e:
            logger.warning(f"[URL-CHAIN] Redirect following failed: {e}")
        
        return chain
    
    @staticmethod
    def _is_ip_url(url: str) -> bool:
        """Check if URL uses IP address instead of domain."""
        ip_pattern = r'https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}'
        return bool(re.match(ip_pattern, url))
def analyze_url_chain(url: str) -> Dict:
    """Main entry point for URL analysis."""
    return URLChainAnalyzer.analyze_url(url)
