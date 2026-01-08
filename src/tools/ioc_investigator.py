"""
Blue Team Assistant - IOC Investigation Tool

Multi-source threat intelligence lookup for IPs, domains, URLs, and hashes.

Author: Ugur Ates
"""

import asyncio
from typing import Dict
import logging
from ..integrations.threat_intel import ThreatIntelligence
from ..integrations.llm_analyzer import LLMAnalyzer
from ..utils.ioc_extractor import IOCExtractor
from ..utils.helpers import determine_verdict
from ..scoring.intelligent_scoring import IntelligentScoring
from ..detection.rule_generator import RuleGenerator
from ..reporting.html_report_generator import HTMLReportGenerator

logger = logging.getLogger(__name__)

# Trusted infrastructure - NEVER flag as malicious
TRUSTED_DOMAINS = {
    # Certificate Authorities
    'digicert.com', 'verisign.com', 'letsencrypt.org', 'comodo.com',
    'godaddy.com', 'globalsign.com', 'entrust.com', 'thawte.com',
    'geotrust.com', 'rapidssl.com', 'sectigo.com', 'comodoca.com',
    'usertrust.com', 'trustwave.com', 'symantec.com', 'pki.goog',
    # Microsoft
    'microsoft.com', 'windows.com', 'windowsupdate.com', 'azure.com',
    'msft.net', 'msn.com', 'live.com', 'office.com', 'office365.com',
    # Google
    'google.com', 'googleapis.com', 'gstatic.com', 'google-analytics.com',
    # CDNs
    'akamai.net', 'akamaiedge.net', 'cloudflare.com', 'fastly.net',
    'cloudfront.net', 'azureedge.net', 'edgecastcdn.net',
    # Other trusted
    'apple.com', 'mozilla.org', 'adobe.com',
}

class IOCInvestigator:
    """
    IOC Investigation Tool.
    
    Investigates IPs, domains, URLs, and hashes using 20+ threat intelligence sources.
    """
    
    def __init__(self, config: Dict):
        """Initialize IOC investigator."""
        self.config = config
        self.threat_intel = ThreatIntelligence(config)
        self.llm_analyzer = LLMAnalyzer(config)
    
    def _is_trusted_infrastructure(self, ioc: str, ioc_type: str) -> bool:
        """Check if IOC belongs to trusted infrastructure."""
        ioc_lower = ioc.lower()
        
        if ioc_type == 'domain':
            for trusted in TRUSTED_DOMAINS:
                if ioc_lower == trusted or ioc_lower.endswith('.' + trusted):
                    return True
        elif ioc_type == 'url':
            for trusted in TRUSTED_DOMAINS:
                if trusted in ioc_lower:
                    return True
        
        return False
    
    async def investigate(self, ioc: str) -> Dict:
        """
        Investigate IOC.
        
        Args:
            ioc: Indicator to investigate
        
        Returns:
            Investigation results
        """
        logger.info(f"[IOC] Starting investigation: {ioc}")
        
        # Detect IOC type
        ioc_type = IOCExtractor.categorize_ioc(ioc)
        
        if ioc_type == 'unknown':
            return {'error': f'Unable to categorize IOC: {ioc}'}
        
        # Check if trusted infrastructure - skip heavy investigation
        if self._is_trusted_infrastructure(ioc, ioc_type):
            logger.info(f"[IOC] Skipping trusted infrastructure: {ioc}")
            return {
                'ioc': ioc,
                'ioc_type': ioc_type,
                'threat_score': 0,
                'verdict': 'CLEAN',
                'sources': {},
                'sources_checked': 0,
                'sources_flagged': 0,
                'note': 'Trusted infrastructure (Certificate Authority / CDN / Major vendor)',
                'recommendations': ['No action required - legitimate infrastructure'],
            }
        
        # Run threat intelligence checks
        intel_results = await self.threat_intel.investigate_ioc_comprehensive(ioc, ioc_type)
        
        # Calculate threat score
        threat_score = IntelligentScoring.calculate_ioc_score(intel_results)
        verdict = determine_verdict(threat_score)
        
        # Get LLM analysis if enabled
        llm_analysis = {}
        if self.config.get('analysis', {}).get('enable_llm', True):
            llm_analysis = await self.llm_analyzer.analyze_ioc_results(ioc, ioc_type, intel_results)
        
        # Generate detection rules
        detection_rules = RuleGenerator.generate_ioc_rules(ioc, ioc_type, {'verdict': verdict})
        
        # Generate recommendations
        recommendations = self._generate_recommendations(verdict, intel_results)
        
        result = {
            'ioc': ioc,
            'ioc_type': ioc_type,
            'threat_score': threat_score,
            'verdict': verdict,
            # Standardized keys
            'sources': intel_results.get('sources', {}),  # Direct 'sources' key for consistency
            'sources_checked': intel_results.get('sources_checked', 0),
            'sources_flagged': intel_results.get('sources_flagged', 0),
            # Legacy compatibility aliases
            'threat_intel_results': intel_results.get('sources', {}),  # Backward compat
            'threat_intelligence': {
                'sources': intel_results.get('sources', {}),
                'sources_checked': intel_results.get('sources_checked', 0),
                'sources_flagged': intel_results.get('sources_flagged', 0)
            },
            'llm_analysis': llm_analysis,
            'detection_rules': detection_rules,
            'recommendations': recommendations
        }
        
        logger.info(f"[IOC] Investigation complete: {ioc} → {verdict} ({threat_score}/100)")
        
        return result
    
    def _generate_recommendations(self, verdict: str, intel_results: Dict) -> list:
        """Generate action recommendations based on verdict."""
        if verdict == 'MALICIOUS':
            return [
                '🚨 Block IOC at firewall/proxy immediately',
                '🔍 Hunt for connections to this IOC in logs (last 30 days)',
                '💻 Isolate any affected hosts from network',
                '📋 Create incident ticket for IR team',
                '🔐 Reset credentials on affected systems'
            ]
        elif verdict == 'SUSPICIOUS':
            return [
                '⚠️ Add IOC to monitoring watchlist',
                '🔍 Review logs for any connections',
                '📊 Correlate with other suspicious activity',
                '👀 Monitor for additional indicators'
            ]
        elif verdict == 'LOW_RISK':
            return [
                '📝 Document finding',
                '👁️ Passive monitoring recommended',
                '✅ No immediate action required'
            ]
        else:
            return [
                '✅ No threats detected',
                '📋 Document for reference'
            ]
    
    def generate_html_report(self, investigation_result: Dict, ioc: str, output_path: str):
        """Generate HTML report."""
        generator = HTMLReportGenerator()
        return generator.generate_ioc_report(investigation_result, ioc, output_path)
