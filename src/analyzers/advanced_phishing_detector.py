"""
Author: Ugur Ates
Advanced Phishing Detection Engine
Integrated from Blue Team Tools (Sooty, ThePhish patterns)
 Enhancement
"""

import re
import logging
from typing import Dict, List, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)
class AdvancedPhishingDetector:
    """
    Advanced phishing detection using Blue Team patterns.
    
    Integrated from:
    - Sooty phishing analysis
    - ThePhish indicators
    - Email-header-analyzer patterns
    """
    
    # Phishing keywords (from Sooty + expanded)
    PHISHING_KEYWORDS = [
        'verify', 'account', 'suspended', 'click here', 'urgent', 
        'immediate action', 'confirm', 'update', 'secure', 'password',
        'bank', 'credit card', 'social security', 'tax', 'refund',
        'expire', 'locked', 'unusual activity', 'verify identity',
        'congratulations', 'winner', 'prize', 'claim', 'free',
        'act now', 'limited time', 'don\'t delay', 're:',
        'payment', 'invoice', 'transfer', 'bitcoin', 'cryptocurrency',
        'covid', 'vaccine', 'pandemic', 'donation', 'charity'
    ]
    
    # Suspicious TLDs
    SUSPICIOUS_TLDS = [
        '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs
        '.top', '.xyz', '.club', '.work', '.click',
        '.loan', '.download', '.racing', '.accountant'
    ]
    
    # Brand impersonation patterns
    BRAND_PATTERNS = [
        r'paypal', r'amazon', r'microsoft', r'apple', r'google',
        r'facebook', r'netflix', r'dropbox', r'adobe', r'bank',
        r'fedex', r'ups', r'dhl', r'usps', r'irs', r'security',
        r'support', r'helpdesk', r'admin', r'noreply'
    ]
    
    @staticmethod
    def analyze_email_for_phishing(email_data: Dict) -> Dict:
        """
        Comprehensive phishing analysis.
        
        Args:
            email_data: Email analysis data
        
        Returns:
            Phishing analysis results
        """
        result = {
            'phishing_score': 0,
            'indicators': [],
            'risk_level': 'LOW',
            'reasons': []
        }
        
        try:
            score = 0
            
            # 1. Subject Analysis
            subject_score, subject_indicators = AdvancedPhishingDetector._analyze_subject(
                email_data.get('subject', '')
            )
            score += subject_score
            result['indicators'].extend(subject_indicators)
            
            # 2. Sender Analysis
            sender_score, sender_indicators = AdvancedPhishingDetector._analyze_sender(
                email_data.get('from', ''),
                email_data.get('reply_to', '')
            )
            score += sender_score
            result['indicators'].extend(sender_indicators)
            
            # 3. Body Analysis
            body_score, body_indicators = AdvancedPhishingDetector._analyze_body(
                email_data.get('body', '')
            )
            score += body_score
            result['indicators'].extend(body_indicators)
            
            # 4. URL Analysis
            url_score, url_indicators = AdvancedPhishingDetector._analyze_urls(
                email_data.get('urls', [])
            )
            score += url_score
            result['indicators'].extend(url_indicators)
            
            # 5. Attachment Analysis
            attachment_score, attachment_indicators = AdvancedPhishingDetector._analyze_attachments(
                email_data.get('attachments', [])
            )
            score += attachment_score
            result['indicators'].extend(attachment_indicators)
            
            # 6. Header Analysis
            header_score, header_indicators = AdvancedPhishingDetector._analyze_headers(
                email_data.get('headers', {})
            )
            score += header_score
            result['indicators'].extend(header_indicators)
            
            # Calculate final score
            result['phishing_score'] = min(score, 100)
            
            # Determine risk level
            if result['phishing_score'] >= 70:
                result['risk_level'] = 'CRITICAL'
            elif result['phishing_score'] >= 50:
                result['risk_level'] = 'HIGH'
            elif result['phishing_score'] >= 30:
                result['risk_level'] = 'MEDIUM'
            else:
                result['risk_level'] = 'LOW'
            
            # Generate reasons
            result['reasons'] = [ind['reason'] for ind in result['indicators']]
            
        except Exception as e:
            logger.error(f"[PHISHING] Analysis failed: {e}")
            result['error'] = str(e)
        
        return result
    
    @staticmethod
    def _analyze_subject(subject: str) -> Tuple[int, List[Dict]]:
        """Analyze email subject for phishing indicators."""
        score = 0
        indicators = []
        
        subject_lower = subject.lower()
        
        # Check for phishing keywords
        for keyword in AdvancedPhishingDetector.PHISHING_KEYWORDS:
            if keyword in subject_lower:
                score += 5
                indicators.append({
                    'type': 'SUBJECT_KEYWORD',
                    'keyword': keyword,
                    'reason': f'Phishing keyword in subject: "{keyword}"'
                })
        
        # Check for urgency indicators
        urgency_patterns = [
            r'urgent', r'immediate', r'action required', r'expires?',
            r'suspended', r'locked', r'verify now'
        ]
        for pattern in urgency_patterns:
            if re.search(pattern, subject_lower):
                score += 10
                indicators.append({
                    'type': 'URGENCY',
                    'pattern': pattern,
                    'reason': f'Urgency indicator in subject'
                })
        
        # Check for fake Re:
        if subject.lower().startswith('re:') and 'fwd' not in subject.lower():
            score += 8
            indicators.append({
                'type': 'FAKE_REPLY',
                'reason': 'Suspicious "Re:" without previous conversation'
            })
        
        return score, indicators
    
    @staticmethod
    def _analyze_sender(sender: str, reply_to: str) -> Tuple[int, List[Dict]]:
        """Analyze sender for phishing indicators."""
        score = 0
        indicators = []
        
        sender_lower = sender.lower()
        
        # Check for brand impersonation
        for pattern in AdvancedPhishingDetector.BRAND_PATTERNS:
            if re.search(pattern, sender_lower):
                # Check if it's actually from that brand
                if not (pattern in sender_lower and '@' + pattern in sender_lower):
                    score += 15
                    indicators.append({
                        'type': 'BRAND_IMPERSONATION',
                        'brand': pattern,
                        'reason': f'Possible {pattern} impersonation'
                    })
        
        # Check for sender/reply-to mismatch
        if reply_to and sender != reply_to:
            score += 10
            indicators.append({
                'type': 'SENDER_MISMATCH',
                'reason': 'Sender and Reply-To addresses differ'
            })
        
        # Check for suspicious sender patterns
        if re.search(r'\d{5,}', sender):  # Many numbers in email
            score += 5
            indicators.append({
                'type': 'SUSPICIOUS_SENDER',
                'reason': 'Sender contains excessive numbers'
            })
        
        return score, indicators
    
    @staticmethod
    def _analyze_body(body: str) -> Tuple[int, List[Dict]]:
        """Analyze email body for phishing indicators."""
        score = 0
        indicators = []
        
        body_lower = body.lower()
        
        # Check for credential harvesting
        credential_patterns = [
            r'enter.*password', r'verify.*account', r'confirm.*identity',
            r'click.*link', r'update.*information', r'reset.*password'
        ]
        for pattern in credential_patterns:
            if re.search(pattern, body_lower):
                score += 15
                indicators.append({
                    'type': 'CREDENTIAL_HARVESTING',
                    'pattern': pattern,
                    'reason': 'Potential credential harvesting attempt'
                })
        
        # Check for threats/urgency
        threat_patterns = [
            r'account.*suspend', r'will.*close', r'within.*hours',
            r'immediate.*action', r'verify.*now'
        ]
        for pattern in threat_patterns:
            if re.search(pattern, body_lower):
                score += 10
                indicators.append({
                    'type': 'THREAT',
                    'pattern': pattern,
                    'reason': 'Threatening or urgent language'
                })
        
        return score, indicators
    
    @staticmethod
    def _analyze_urls(urls: List[str]) -> Tuple[int, List[Dict]]:
        """Analyze URLs for phishing indicators."""
        score = 0
        indicators = []
        
        for url in urls:
            url_lower = url.lower()
            
            # Check for suspicious TLDs
            for tld in AdvancedPhishingDetector.SUSPICIOUS_TLDS:
                if tld in url_lower:
                    score += 10
                    indicators.append({
                        'type': 'SUSPICIOUS_TLD',
                        'tld': tld,
                        'url': url,
                        'reason': f'Suspicious TLD: {tld}'
                    })
            
            # Check for IP address URLs
            if re.search(r'http://\d+\.\d+\.\d+\.\d+', url):
                score += 20
                indicators.append({
                    'type': 'IP_URL',
                    'url': url,
                    'reason': 'URL uses IP address instead of domain'
                })
            
            # Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly']
            if any(short in url_lower for short in shorteners):
                score += 8
                indicators.append({
                    'type': 'URL_SHORTENER',
                    'url': url,
                    'reason': 'URL shortener detected (obscures destination)'
                })
        
        return score, indicators
    
    @staticmethod
    def _analyze_attachments(attachments: List[str]) -> Tuple[int, List[Dict]]:
        """Analyze attachments for phishing indicators."""
        score = 0
        indicators = []
        
        suspicious_extensions = [
            '.exe', '.scr', '.bat', '.cmd', '.vbs', '.js',
            '.jar', '.com', '.pif', '.lnk', '.hta'
        ]
        
        for attachment in attachments:
            attachment_lower = attachment.lower()
            
            # Check for suspicious extensions
            for ext in suspicious_extensions:
                if attachment_lower.endswith(ext):
                    score += 25
                    indicators.append({
                        'type': 'SUSPICIOUS_ATTACHMENT',
                        'extension': ext,
                        'filename': attachment,
                        'reason': f'Potentially malicious attachment: {ext}'
                    })
            
            # Check for double extensions
            if attachment.count('.') > 1:
                score += 15
                indicators.append({
                    'type': 'DOUBLE_EXTENSION',
                    'filename': attachment,
                    'reason': 'Double extension (possible file type obfuscation)'
                })
        
        return score, indicators
    
    @staticmethod
    def _analyze_headers(headers: Dict) -> Tuple[int, List[Dict]]:
        """Analyze email headers for phishing indicators."""
        score = 0
        indicators = []
        
        # Check for missing SPF/DKIM/DMARC
        if not headers.get('spf_pass'):
            score += 15
            indicators.append({
                'type': 'SPF_FAIL',
                'reason': 'SPF authentication failed'
            })
        
        if not headers.get('dkim_pass'):
            score += 15
            indicators.append({
                'type': 'DKIM_FAIL',
                'reason': 'DKIM authentication failed'
            })
        
        # Check for suspicious received headers
        received_count = headers.get('received_count', 0)
        if received_count > 10:
            score += 10
            indicators.append({
                'type': 'EXCESSIVE_HOPS',
                'count': received_count,
                'reason': f'Excessive mail hops ({received_count})'
            })
        
        return score, indicators
def detect_phishing(email_data: Dict) -> Dict:
    """
    Main entry point for phishing detection.
    
    Args:
        email_data: Email analysis data
    
    Returns:
        Phishing analysis results
    """
    return AdvancedPhishingDetector.analyze_email_for_phishing(email_data)
