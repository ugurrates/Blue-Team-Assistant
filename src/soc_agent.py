"""Blue Team Assistant - Main CLI Interface.

Author: Ugur Ates
Version: 1.0.0
"""

import asyncio
import argparse
import sys
from pathlib import Path
import logging

from .tools import IOCInvestigator, EmailAnalyzer, MalwareAnalyzer
from .utils.config import load_config
from .reporting.soc_output_formatter import SOCOutputFormatter  

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


USE_V55_OUTPUT = True
def print_header(title: str):
    """Print formatted header."""
    print("\n" + "="*80)
    print(title)
    print("="*80 + "\n")
def print_ioc_results(result: dict, ioc: str):
    """Print IOC investigation results with DETAILED source breakdown (ALL 22 SOURCES)."""
    
    # Use v1.0.0 professional output if enabled
    if USE_V55_OUTPUT:
        try:
            professional_output = SOCOutputFormatter.format_ioc_report(result, ioc)
            print(professional_output)
            return
        except Exception as e:
            logger.warning(f"[OUTPUT] v1.0.0 formatter failed, using legacy: {e}")
    
    # Legacy output (fallback)
    print_header(f"IOC Investigation: {ioc}")
    
    # Verdict and Score
    verdict = result.get('verdict', 'UNKNOWN')
    score = result.get('threat_score', 0)
    ioc_type = result.get('ioc_type', 'Unknown')
    
    verdict_emoji = {
        'MALICIOUS': '🚨',
        'SUSPICIOUS': '⚠️',
        'CLEAN': '✅',
        'UNKNOWN': '❓'
    }
    
    print(f"{verdict_emoji.get(verdict, '')} Verdict: {verdict}")
    print(f"Threat Score: {score}/100")
    print(f"IOC Type: {ioc_type}\n")
    
    # Threat Intelligence Sources - EVERY SINGLE SOURCE DETAILED
    #  FIX: Try multiple key paths for backward compatibility
    sources = (
        result.get('sources', {}) or
        result.get('threat_intel_results', {}) or
        result.get('threat_intelligence', {}).get('sources', {})
    )
    sources_checked = (
        result.get('sources_checked', 0) or
        result.get('threat_intelligence', {}).get('sources_checked', 0)
    )
    sources_flagged = (
        result.get('sources_flagged', 0) or
        result.get('threat_intelligence', {}).get('sources_flagged', 0)
    )
    
    print(f"╔══════════════════════════════════════════════════════════════╗")
    print(f"║  THREAT INTELLIGENCE SOURCES - DETAILED BREAKDOWN (22 Total) ║")
    print(f"╚══════════════════════════════════════════════════════════════╝")
    print(f"  Sources Checked: {sources_checked}")
    print(f"  Sources Flagged: {sources_flagged}\n")
    
    # ========== SOURCE 1: VirusTotal ==========
    vt = sources.get('virustotal', {})
    print(f"┌─ SOURCE 1: VirusTotal")
    if vt and not vt.get('error'):
        detections = vt.get('detections', 0)
        total = vt.get('total_engines', 0)
        if detections > 0:
            print(f"│  Status: 🚨 FLAGGED")
            print(f"│  Detections: {detections}/{total} vendors")
            vendors = vt.get('detecting_vendors', [])
            if vendors:
                print(f"│  Top Vendors: {', '.join(vendors[:5])}")
            print(f"│  Details: {detections} security vendors flagged this as malicious")
        else:
            print(f"│  Status: ✅ CLEAN")
            print(f"│  Detections: 0/{total} vendors")
            print(f"│  Details: No vendors flagged this IOC")
    else:
        print(f"│  Status: ⚠️ {vt.get('error', 'No API key or error')}")
    print(f"└─────────────────────────────────────────────────────────────\n")
    
    # ========== SOURCE 2: AbuseIPDB ==========
    abuseipdb = sources.get('abuseipdb', {})
    print(f"┌─ SOURCE 2: AbuseIPDB (IP Reputation)")
    if abuseipdb and not abuseipdb.get('error'):
        abuse_score = abuseipdb.get('abuse_confidence_score', 0)
        reports = abuseipdb.get('total_reports', 0)
        if abuse_score > 0:
            print(f"│  Status: 🚨 FLAGGED")
            print(f"│  Abuse Score: {abuse_score}%")
            print(f"│  Total Reports: {reports}")
            categories = abuseipdb.get('categories', [])
            if categories:
                print(f"│  Categories: {', '.join(categories[:3])}")
            print(f"│  Details: Reported {reports} times with {abuse_score}% confidence")
        else:
            print(f"│  Status: ✅ CLEAN")
            print(f"│  Reports: 0")
            print(f"│  Details: No abuse reports found")
    else:
        print(f"│  Status: ⚠️ {abuseipdb.get('error', 'No API key or error')}")
    print(f"└─────────────────────────────────────────────────────────────\n")
    
    # ========== SOURCE 3: Shodan ==========
    shodan = sources.get('shodan', {})
    print(f"┌─ SOURCE 3: Shodan (Internet Scanning)")
    if shodan and not shodan.get('error'):
        if shodan.get('found'):
            print(f"│  Status: ℹ️  FOUND")
            print(f"│  Open Ports: {shodan.get('ports', 'Unknown')}")
            print(f"│  Organization: {shodan.get('org', 'Unknown')}")
            print(f"│  Country: {shodan.get('country', 'Unknown')}")
            vulns = shodan.get('vulns', [])
            if vulns:
                print(f"│  Vulnerabilities: {', '.join(vulns[:3])}")
            print(f"│  Details: Internet-facing services detected")
        else:
            print(f"│  Status: ✅ NOT FOUND")
            print(f"│  Details: No Shodan records")
    else:
        print(f"│  Status: ⚠️ {shodan.get('error', 'No API key or error')}")
    print(f"└─────────────────────────────────────────────────────────────\n")
    
    # ========== SOURCE 4: AlienVault OTX ==========
    alienvault = sources.get('alienvault', {})
    print(f"┌─ SOURCE 4: AlienVault OTX (Threat Exchange)")
    if alienvault and not alienvault.get('error'):
        pulse_count = alienvault.get('pulse_count', 0)
        if pulse_count > 0:
            print(f"│  Status: 🚨 FLAGGED")
            print(f"│  Threat Pulses: {pulse_count}")
            tags = alienvault.get('tags', [])
            if tags:
                print(f"│  Tags: {', '.join(tags[:5])}")
            print(f"│  Details: Found in {pulse_count} threat intelligence pulses")
        else:
            print(f"│  Status: ✅ CLEAN")
            print(f"│  Pulses: 0")
            print(f"│  Details: Not found in OTX pulses")
    else:
        print(f"│  Status: ⚠️ {alienvault.get('error', 'No API key or error')}")
    print(f"└─────────────────────────────────────────────────────────────\n")
    
    # ========== SOURCE 5: URLhaus ==========
    urlhaus = sources.get('urlhaus', {})
    print(f"┌─ SOURCE 5: URLhaus (Malware URLs)")
    if urlhaus and not urlhaus.get('error'):
        if urlhaus.get('found'):
            print(f"│  Status: 🚨 FLAGGED")
            print(f"│  Threat: {urlhaus.get('threat', 'Unknown')}")
            print(f"│  Tags: {urlhaus.get('tags', 'Unknown')}")
            print(f"│  Details: Known malware distribution URL")
        else:
            print(f"│  Status: ✅ CLEAN")
            print(f"│  Details: Not found in URLhaus database")
    else:
        print(f"│  Status: ⚠️ No data")
    print(f"└─────────────────────────────────────────────────────────────\n")
    
    # ========== SOURCE 6: FeodoTracker ==========
    feodo = sources.get('feodotracker', {})
    print(f"┌─ SOURCE 6: FeodoTracker (Botnet C2)")
    if feodo and not feodo.get('error'):
        if feodo.get('found'):
            print(f"│  Status: 🚨 FLAGGED")
            print(f"│  Botnet: {feodo.get('botnet', 'Unknown')}")
            print(f"│  Malware: {feodo.get('malware', 'Unknown')}")
            print(f"│  Status: {feodo.get('status', 'Unknown')}")
            print(f"│  Details: Known botnet command & control server")
        else:
            print(f"│  Status: ✅ CLEAN")
            print(f"│  Details: Not found in Feodo Tracker")
    else:
        print(f"│  Status: ⚠️ No data")
    print(f"└─────────────────────────────────────────────────────────────\n")
    
    # ========== SOURCE 7: ThreatFox ==========
    threatfox = sources.get('threatfox', {})
    print(f"┌─ SOURCE 7: ThreatFox (IOC Database)")
    if threatfox and not threatfox.get('error'):
        if threatfox.get('found'):
            print(f"│  Status: 🚨 FLAGGED")
            print(f"│  Malware: {threatfox.get('malware', 'Unknown')}")
            print(f"│  Confidence: {threatfox.get('confidence', 0)}%")
            print(f"│  Tags: {threatfox.get('tags', 'Unknown')}")
            print(f"│  Details: IOC reported to ThreatFox")
        else:
            print(f"│  Status: ✅ CLEAN")
            print(f"│  Details: Not found in ThreatFox")
    else:
        print(f"│  Status: ⚠️ No data")
    print(f"└─────────────────────────────────────────────────────────────\n")
    
    # ========== SOURCE 8: MalwareBazaar ==========
    malwarebazaar = sources.get('malwarebazaar', {})
    print(f"┌─ SOURCE 8: MalwareBazaar (Malware Samples)")
    if malwarebazaar and not malwarebazaar.get('error'):
        if malwarebazaar.get('found'):
            print(f"│  Status: 🚨 FLAGGED")
            print(f"│  Signature: {malwarebazaar.get('signature', 'Unknown')}")
            print(f"│  File Type: {malwarebazaar.get('file_type', 'Unknown')}")
            print(f"│  Details: Known malware sample")
        else:
            print(f"│  Status: ✅ CLEAN")
            print(f"│  Details: Not found in MalwareBazaar")
    else:
        print(f"│  Status: ⚠️ No data")
    print(f"└─────────────────────────────────────────────────────────────\n")
    
    # ========== SOURCE 9: C2 Trackers ==========
    c2_trackers = sources.get('c2_trackers', {})
    print(f"┌─ SOURCE 9: C2 Trackers (Command & Control)")
    if c2_trackers and not c2_trackers.get('error'):
        if c2_trackers.get('found'):
            print(f"│  Status: 🚨 FLAGGED")
            families = c2_trackers.get('malware_families', [])
            print(f"│  Malware Families: {', '.join(families[:3])}")
            print(f"│  Details: Known C2 infrastructure")
        else:
            print(f"│  Status: ✅ CLEAN")
            print(f"│  Details: Not found in C2 trackers")
    else:
        print(f"│  Status: ⚠️ No data")
    print(f"└─────────────────────────────────────────────────────────────\n")
    
    # ========== SOURCE 10: Tor Exit Nodes ==========
    tor = sources.get('tor_exit_nodes', {})
    print(f"┌─ SOURCE 10: Tor Exit Nodes")
    if tor and not tor.get('error'):
        if tor.get('is_tor_exit'):
            print(f"│  Status: ⚠️  TOR EXIT NODE")
            print(f"│  Details: This is a Tor exit node (anonymity network)")
        else:
            print(f"│  Status: ✅ NOT TOR")
            print(f"│  Details: Not a Tor exit node")
    else:
        print(f"│  Status: ⚠️ No data")
    print(f"└─────────────────────────────────────────────────────────────\n")
    
    # ========== SOURCE 11: SSL Blacklist ==========
    ssl_blacklist = sources.get('ssl_blacklist', {})
    print(f"┌─ SOURCE 11: SSL Blacklist")
    if ssl_blacklist and not ssl_blacklist.get('error'):
        if ssl_blacklist.get('found'):
            print(f"│  Status: 🚨 FLAGGED")
            print(f"│  Reason: {ssl_blacklist.get('reason', 'Unknown')}")
            print(f"│  Details: Malicious SSL certificate detected")
        else:
            print(f"│  Status: ✅ CLEAN")
            print(f"│  Details: Not in SSL blacklist")
    else:
        print(f"│  Status: ⚠️ No data")
    print(f"└─────────────────────────────────────────────────────────────\n")
    
    # ========== SOURCE 12: USOM ==========
    usom = sources.get('usom', {})
    print(f"┌─ SOURCE 12: USOM (Turkey CERT)")
    if usom and not usom.get('error'):
        if usom.get('found'):
            print(f"│  Status: 🚨 FLAGGED")
            print(f"│  Details: Listed in USOM threat feed")
        else:
            print(f"│  Status: ✅ CLEAN")
            print(f"│  Details: Not found in USOM")
    else:
        print(f"│  Status: ⚠️ No data")
    print(f"└─────────────────────────────────────────────────────────────\n")
    
    # ========== SOURCE 13: GreyNoise ==========
    greynoise = sources.get('greynoise', {})
    print(f"┌─ SOURCE 13: GreyNoise (Internet Scanner Detection)")
    if greynoise and not greynoise.get('error'):
        if greynoise.get('found'):
            print(f"│  Status: ℹ️  DETECTED")
            print(f"│  Classification: {greynoise.get('classification', 'Unknown')}")
            print(f"│  Name: {greynoise.get('name', 'Unknown')}")
            print(f"│  Last Seen: {greynoise.get('last_seen', 'Unknown')}")
            print(f"│  Details: Internet scanning activity detected")
        else:
            print(f"│  Status: ✅ CLEAN")
            print(f"│  Details: No scanning activity detected")
    else:
        print(f"│  Status: ⚠️ {greynoise.get('status', 'No API key')}")
    print(f"└─────────────────────────────────────────────────────────────\n")
    
    # ========== SOURCE 14: Censys ==========
    censys = sources.get('censys', {})
    print(f"┌─ SOURCE 14: Censys (Internet-wide Scan Data)")
    if censys and not censys.get('error'):
        if censys.get('found'):
            print(f"│  Status: ℹ️  FOUND")
            print(f"│  Services: {censys.get('services', 'Unknown')}")
            print(f"│  Location: {censys.get('location', 'Unknown')}")
            print(f"│  ASN: {censys.get('autonomous_system', 'Unknown')}")
            print(f"│  Details: Internet-facing services indexed")
        else:
            print(f"│  Status: ✅ NOT FOUND")
            print(f"│  Details: No Censys records")
    else:
        print(f"│  Status: ⚠️ {censys.get('status', 'No API key')}")
    print(f"└─────────────────────────────────────────────────────────────\n")
    
    # ========== SOURCE 15: Talos Intelligence ==========
    talos = sources.get('talos', {})
    print(f"┌─ SOURCE 15: Talos Intelligence (Cisco)")
    if talos and not talos.get('error'):
        print(f"│  Status: ℹ️  MANUAL CHECK")
        print(f"│  URL: {talos.get('url', 'Unknown')}")
        print(f"│  Details: Visit URL for reputation check")
    else:
        print(f"│  Status: ⚠️ No API available")
    print(f"└─────────────────────────────────────────────────────────────\n")
    
    # ========== SOURCE 16: Pulsedive ==========
    pulsedive = sources.get('pulsedive', {})
    print(f"┌─ SOURCE 16: Pulsedive (Community Threat Intel)")
    if pulsedive and not pulsedive.get('error'):
        if pulsedive.get('found'):
            print(f"│  Status: 🚨 FLAGGED")
            print(f"│  Risk: {pulsedive.get('risk', 'Unknown')}")
            threats = pulsedive.get('threats', [])
            if threats:
                print(f"│  Threats: {', '.join(threats[:3])}")
            print(f"│  First Seen: {pulsedive.get('stamp_seen', 'Unknown')}")
            print(f"│  Details: Community-reported threat")
        else:
            print(f"│  Status: ✅ CLEAN")
            print(f"│  Details: Not found in Pulsedive")
    else:
        print(f"│  Status: ⚠️ {pulsedive.get('status', 'No API key')}")
    print(f"└─────────────────────────────────────────────────────────────\n")
    
    # ========== SOURCE 17: ThreatCrowd ==========
    threatcrowd = sources.get('threatcrowd', {})
    print(f"┌─ SOURCE 17: ThreatCrowd (DNS/WHOIS Intel)")
    if threatcrowd and not threatcrowd.get('error'):
        if threatcrowd.get('found'):
            print(f"│  Status: ℹ️  FOUND")
            print(f"│  Votes: {threatcrowd.get('votes', 0)}")
            print(f"│  Hashes: {threatcrowd.get('hashes', 0)}")
            print(f"│  References: {threatcrowd.get('references', 0)}")
            print(f"│  Details: DNS/WHOIS records found")
        else:
            print(f"│  Status: ✅ NOT FOUND")
            print(f"│  Details: No ThreatCrowd data")
    else:
        print(f"│  Status: ⚠️ {threatcrowd.get('status', 'Error')}")
    print(f"└─────────────────────────────────────────────────────────────\n")
    
    # ========== SOURCE 18: Criminal IP ==========
    criminalip = sources.get('criminalip', {})
    print(f"┌─ SOURCE 18: Criminal IP (Threat Scoring)")
    if criminalip and not criminalip.get('error'):
        if criminalip.get('found'):
            print(f"│  Status: ℹ️  SCORED")
            print(f"│  Score: {criminalip.get('score', 0)}/100")
            print(f"│  Country: {criminalip.get('country', 'Unknown')}")
            print(f"│  VPN: {criminalip.get('is_vpn', False)}")
            print(f"│  Proxy: {criminalip.get('is_proxy', False)}")
            print(f"│  Details: Threat score assessment")
        else:
            print(f"│  Status: ✅ NOT FOUND")
    else:
        print(f"│  Status: ⚠️ {criminalip.get('status', 'No API key')}")
    print(f"└─────────────────────────────────────────────────────────────\n")
    
    # ========== SOURCE 19: IPQualityScore ==========
    ipqs = sources.get('ipqualityscore', {})
    print(f"┌─ SOURCE 19: IPQualityScore (Fraud Detection)")
    if ipqs and not ipqs.get('error'):
        if ipqs.get('found'):
            print(f"│  Status: ℹ️  ANALYZED")
            print(f"│  Fraud Score: {ipqs.get('fraud_score', 0)}/100")
            print(f"│  Proxy: {ipqs.get('proxy', False)}")
            print(f"│  VPN: {ipqs.get('vpn', False)}")
            print(f"│  Tor: {ipqs.get('tor', False)}")
            print(f"│  Bot: {ipqs.get('bot_status', False)}")
            print(f"│  Details: Fraud/abuse analysis")
        else:
            print(f"│  Status: ✅ CLEAN")
    else:
        print(f"│  Status: ⚠️ {ipqs.get('status', 'No API key')}")
    print(f"└─────────────────────────────────────────────────────────────\n")
    
    # ========== SOURCE 20: Spamhaus ==========
    spamhaus = sources.get('spamhaus', {})
    print(f"┌─ SOURCE 20: Spamhaus (Spam/Malware Tracking)")
    if spamhaus and not spamhaus.get('error'):
        if spamhaus.get('listed'):
            print(f"│  Status: 🚨 LISTED")
            print(f"│  Details: IP is on Spamhaus blocklist (spam/malware)")
        else:
            print(f"│  Status: ✅ NOT LISTED")
            print(f"│  Details: Not on Spamhaus blocklist")
    else:
        print(f"│  Status: ⚠️ {spamhaus.get('status', 'Error')}")
    print(f"└─────────────────────────────────────────────────────────────\n")
    
    # ========== SOURCE 21: PhishTank ==========
    phishtank = sources.get('phishtank', {})
    print(f"┌─ SOURCE 21: PhishTank (Phishing Database)")
    if phishtank and not phishtank.get('error'):
        if phishtank.get('found'):
            print(f"│  Status: 🚨 PHISHING")
            print(f"│  Verified: {phishtank.get('verified', False)}")
            print(f"│  Phish ID: {phishtank.get('phish_id', 'Unknown')}")
            print(f"│  Details: Known phishing URL")
        else:
            print(f"│  Status: ✅ CLEAN")
            print(f"│  Details: Not in PhishTank database")
    else:
        print(f"│  Status: ⚠️ {phishtank.get('status', 'No API key')}")
    print(f"└─────────────────────────────────────────────────────────────\n")
    
    # ========== SOURCE 22: CIRCL ==========
    circl = sources.get('circl', {})
    print(f"┌─ SOURCE 22: CIRCL (Passive DNS/SSL)")
    if circl and not circl.get('error'):
        if circl.get('found'):
            print(f"│  Status: ℹ️  FOUND")
            print(f"│  Records: {circl.get('records', 0)}")
            print(f"│  Details: Passive DNS records available")
        else:
            print(f"│  Status: ✅ NOT FOUND")
            print(f"│  Details: No CIRCL records")
    else:
        print(f"│  Status: ⚠️ {circl.get('status', 'Error')}")
    print(f"└─────────────────────────────────────────────────────────────\n")
    
    print()
    
    # LLM Analysis (MAIN OUTPUT)
    llm_analysis = result.get('llm_analysis', {})
    if llm_analysis and llm_analysis.get('analysis'):
        provider = llm_analysis.get('provider', 'Unknown')
        model = llm_analysis.get('model', 'Unknown')
        
        print(f"╔══════════════════════════════════════════════════════════════╗")
        print(f"║  AI-POWERED ANALYSIS ({provider} - {model})                   ")
        print(f"╚══════════════════════════════════════════════════════════════╝")
        print(f"{llm_analysis['analysis']}\n")
        
        # Recommendations from LLM
        recommendations = llm_analysis.get('recommendations', [])
        if recommendations:
            print("╔══════════════════════════════════════════════════════════════╗")
            print("║  RECOMMENDED ACTIONS                                          ")
            print("╚══════════════════════════════════════════════════════════════╝")
            for i, rec in enumerate(recommendations, 1):
                print(f"  {i}. {rec}")
            print()
        
        # Detection Rules from LLM
        detection_rules = llm_analysis.get('detection_rules')
        if detection_rules:
            print("╔══════════════════════════════════════════════════════════════╗")
            print("║  DETECTION RULES GENERATED                                    ")
            print("╚══════════════════════════════════════════════════════════════╝")
            for rule_type, rule_content in detection_rules.items():
                if rule_content:
                    print(f"\n  [{rule_type.upper()}]")
                    print(f"  {rule_content[:300]}...")  # First 300 chars
            print()
def print_email_results(result: dict, email_path: str):
    """Print email analysis results in clean format."""
    
    # Use v1.0.0 professional output if enabled
    if USE_V55_OUTPUT:
        try:
            professional_output = SOCOutputFormatter.format_email_report(result, email_path)
            print(professional_output)
            return
        except Exception as e:
            logger.warning(f"[OUTPUT] v1.0.0 formatter failed, using legacy: {e}")
    
    # Legacy output (fallback)
    print_header(f"Email Analysis: {Path(email_path).name}")
    
    # Verdict and Scores
    verdict = result.get('verdict', 'UNKNOWN')
    base_score = result.get('base_phishing_score', 0)
    composite_score = result.get('composite_score', 0)
    
    verdict_emoji = {
        'PHISHING': '🎣',
        'SUSPICIOUS': '⚠️',
        'SPAM': '📧',
        'CLEAN': '✅'
    }
    
    print(f"{verdict_emoji.get(verdict, '')} Verdict: {verdict}")
    print(f"Base Score: {base_score}/100")
    print(f"Composite Score: {composite_score}/100\n")
    
    # Quick Summary
    email_data = result.get('email_data', {})
    print(f"From: {email_data.get('from', 'Unknown')}")
    print(f"Subject: {email_data.get('subject', 'Unknown')}\n")
    
    # Advanced Analysis Summary
    advanced = result.get('advanced_analysis', {})
    header_analysis = advanced.get('header_analysis', {})
    anomalies = header_analysis.get('anomalies', [])
    
    if anomalies:
        print(f"Header Anomalies: ({len(anomalies)} found)")
        for anomaly in anomalies[:5]:
            print(f"  🚨 {anomaly}")
        print()
    
    # Link/Domain Issues - DETAILED
    link_mismatches = advanced.get('link_mismatches', [])
    lookalike_domains = advanced.get('lookalike_domains', [])
    brand_impersonation = advanced.get('brand_impersonation', [])
    
    if link_mismatches:
        print(f"Link-Text Mismatches: ({len(link_mismatches)} found)")
        for mismatch in link_mismatches[:5]:
            displayed = mismatch.get('displayed_url', 'Unknown')
            actual = mismatch.get('actual_url', 'Unknown')
            print(f"  🚨 Displayed: {displayed}")
            print(f"     Actual:    {actual}")
        print()
    
    if lookalike_domains:
        print(f"Lookalike Domains: ({len(lookalike_domains)} found)")
        for domain in lookalike_domains[:5]:
            domain_name = domain.get('domain', 'Unknown')
            legitimate = domain.get('legitimate', 'Unknown')
            similarity = domain.get('similarity', 0)
            technique = domain.get('technique', 'Unknown')
            print(f"  🚨 {domain_name}")
            print(f"     Impersonating: {legitimate} (Similarity: {similarity:.1%})")
            print(f"     Technique: {technique}")
        print()
    
    # HTML Obfuscation
    html_obfuscation = advanced.get('html_obfuscation', {})
    if html_obfuscation:
        risk_score = html_obfuscation.get('risk_score', 0)
        if risk_score > 30:
            print(f"HTML Obfuscation: (Risk Score: {risk_score}/100)")
            techniques = html_obfuscation.get('techniques', {})
            if techniques.get('zero_size_fonts', 0) > 0:
                print(f"  🚨 Zero-size fonts: {techniques['zero_size_fonts']} instances")
            if techniques.get('hidden_elements', 0) > 0:
                print(f"  🚨 Hidden elements: {techniques['hidden_elements']} instances")
            if techniques.get('white_on_white', 0) > 0:
                print(f"  🚨 White-on-white text: {techniques['white_on_white']} instances")
            print()
    
    # QR Codes
    qr_codes = advanced.get('qr_codes', [])
    if qr_codes:
        print(f"QR Codes: ({len(qr_codes)} detected) ⚠️ HIGH RISK")
        for qr in qr_codes[:3]:
            location = qr.get('location', 'Unknown')
            print(f"  🚨 Location: {location}")
        print()
    
    if brand_impersonation:
        print(f"Brand Impersonation: ({len(brand_impersonation)} detected)")
        for imp in brand_impersonation[:5]:
            brand = imp.get('brand', 'Unknown')
            risk = imp.get('risk', 'UNKNOWN')
            reason = imp.get('reason', 'Unknown')
            print(f"  🚨 Brand: {brand} - {risk}")
            print(f"     Reason: {reason}")
        print()
    
    # IOCs and Attachments - DETAILED
    ioc_analysis = result.get('ioc_analysis', {})
    attachment_analysis = result.get('attachment_analysis', {})
    
    print(f"IOC Analysis:")
    print(f"  Total IOCs: {ioc_analysis.get('total_iocs', 0)}")
    print(f"  Malicious: {ioc_analysis.get('malicious_iocs', 0)}")
    print(f"  Suspicious: {ioc_analysis.get('suspicious_iocs', 0)}")
    
    # Detailed IOC breakdown
    ioc_results = ioc_analysis.get('ioc_results', {})
    if ioc_results:
        urls = ioc_results.get('urls', [])
        malicious_urls = [u for u in urls if u.get('verdict') == 'MALICIOUS']
        if malicious_urls:
            print(f"\n  🚨 Malicious URLs: ({len(malicious_urls)} found)")
            for url in malicious_urls[:3]:
                ioc = url.get('ioc', 'Unknown')
                score = url.get('threat_score', 0)
                sources = url.get('flagged_sources', [])
                print(f"    • {ioc[:80]}")
                print(f"      Score: {score}/100, Sources: {', '.join(sources[:2])}")
        
        domains = ioc_results.get('domains', [])
        malicious_domains = [d for d in domains if d.get('verdict') == 'MALICIOUS']
        if malicious_domains:
            print(f"\n  🚨 Malicious Domains: ({len(malicious_domains)} found)")
            for domain in malicious_domains[:3]:
                ioc = domain.get('ioc', 'Unknown')
                score = domain.get('threat_score', 0)
                sources = domain.get('flagged_sources', [])
                print(f"    • {ioc} (Score: {score}/100)")
                print(f"      Sources: {', '.join(sources[:2])}")
    
    print()
    
    if attachment_analysis.get('total_attachments', 0) > 0:
        print(f"Attachment Analysis:")
        print(f"  Total: {attachment_analysis.get('total_attachments', 0)}")
        print(f"  Malicious: {attachment_analysis.get('malicious_attachments', 0)}")
        print(f"  Suspicious: {attachment_analysis.get('suspicious_attachments', 0)}")
        
        # Detailed attachment results
        attachments = attachment_analysis.get('attachments', [])
        for att in attachments:
            filename = att.get('filename', 'Unknown')
            verdict = att.get('verdict', 'UNKNOWN')
            score = att.get('composite_score', 0)
            
            emoji = '🦠' if verdict == 'MALICIOUS' else '⚠️' if verdict == 'SUSPICIOUS' else '✅'
            print(f"\n  {emoji} {filename}")
            print(f"     Verdict: {verdict} (Score: {score}/100)")
            
            # File type and size
            file_info = att.get('file_info', {})
            if file_info:
                print(f"     Type: {file_info.get('mime_type', 'Unknown')}, Size: {file_info.get('size_bytes', 0):,} bytes")
            
            # Hash score
            hash_score = att.get('hash_score', 0)
            if hash_score > 0:
                print(f"     Hash Score: {hash_score}/100 (known malware)")
            
            # YARA matches
            yara = att.get('yara_analysis', {})
            if yara and yara.get('matches'):
                families = yara.get('interpretation', {}).get('malware_families', [])
                if families:
                    print(f"     Malware Family: {', '.join(families)}")
            
            # Embedded IOCs
            iocs = att.get('ioc_analysis', {})
            if iocs.get('malicious_iocs', 0) > 0:
                print(f"     Embedded IOCs: {iocs.get('malicious_iocs', 0)} malicious")
        
        print()
    
    # ==================== DFIR-GRADE EMAIL FORENSICS ====================
    forensics = result.get('forensics', {})
    if forensics:
        print(f"╔══════════════════════════════════════════════════════════════╗")
        print(f"║  DFIR-GRADE EMAIL FORENSICS                                   ")
        print(f"╚══════════════════════════════════════════════════════════════╝")
        print(f"Forensics Score: {forensics.get('forensics_score', 0)}/100\n")
        
        # 1. Header Timeline
        timeline = forensics.get('timeline', [])
        if timeline:
            print(f"┌─ EMAIL DELIVERY TIMELINE ({len(timeline)} hops)")
            for hop in timeline[:5]:  # Show first 5 hops
                hop_num = hop.get('hop_number', '?')
                from_server = hop.get('from_server', 'Unknown')
                from_ip = hop.get('from_ip', 'Unknown')
                timestamp = hop.get('timestamp', 'Unknown')
                
                print(f"│  Hop {hop_num}: {from_server}")
                if from_ip != 'Unknown':
                    print(f"│    IP: {from_ip}")
                print(f"│    Time: {timestamp}")
                print(f"│")
            
            if len(timeline) > 5:
                print(f"│  ... {len(timeline) - 5} more hops")
            print(f"└─────────────────────────────────────────────────────────────\n")
        
        # 2. Authentication Results
        auth = forensics.get('authentication', {})
        if auth:
            print(f"┌─ AUTHENTICATION RESULTS")
            print(f"│  Authentication Score: {auth.get('authentication_score', 0)}/100")
            print(f"│")
            
            spf = auth.get('spf', {})
            print(f"│  SPF: {spf.get('status', 'UNKNOWN')}")
            if spf.get('details'):
                print(f"│    {spf.get('details')}")
            
            dkim = auth.get('dkim', {})
            print(f"│  DKIM: {dkim.get('status', 'UNKNOWN')}")
            if dkim.get('domain'):
                print(f"│    Domain: {dkim.get('domain')}")
            
            dmarc = auth.get('dmarc', {})
            print(f"│  DMARC: {dmarc.get('status', 'UNKNOWN')}")
            if dmarc.get('from_domain'):
                print(f"│    From: {dmarc.get('from_domain')}")
            
            overall = "✅ PASS" if auth.get('overall_pass') else "🚨 FAIL"
            print(f"│")
            print(f"│  Overall: {overall}")
            print(f"└─────────────────────────────────────────────────────────────\n")
        
        # 3. Relay Path Analysis
        relay = forensics.get('relay_analysis', {})
        if relay:
            suspicious_hops = relay.get('suspicious_hops', [])
            time_anomalies = relay.get('time_anomalies', [])
            
            if suspicious_hops or time_anomalies:
                print(f"┌─ RELAY PATH ANOMALIES")
                
                if suspicious_hops:
                    print(f"│  🚨 Suspicious Hops: {len(suspicious_hops)}")
                    for sh in suspicious_hops[:3]:
                        print(f"│    Hop {sh.get('hop')}: {', '.join(sh.get('reasons', []))}")
                
                if time_anomalies:
                    print(f"│  🚨 Time Anomalies: {len(time_anomalies)}")
                    for ta in time_anomalies[:3]:
                        print(f"│    {ta.get('hops')}: {ta.get('issue')}")
                
                print(f"└─────────────────────────────────────────────────────────────\n")
        
        # 4. Sender Reputation
        reputation = forensics.get('sender_reputation', {})
        if reputation:
            risk_score = reputation.get('risk_score', 0)
            suspicious_patterns = reputation.get('suspicious_patterns', [])
            
            print(f"┌─ SENDER REPUTATION")
            print(f"│  Risk Score: {risk_score}/100")
            print(f"│  From: {reputation.get('from_address', 'Unknown')}")
            print(f"│  Domain: {reputation.get('from_domain', 'Unknown')}")
            
            if suspicious_patterns:
                print(f"│")
                print(f"│  🚨 Suspicious Patterns:")
                for pattern in suspicious_patterns[:5]:
                    print(f"│    • {pattern}")
            
            if reputation.get('is_free_provider'):
                print(f"│  ℹ️  Free email provider detected")
            
            print(f"└─────────────────────────────────────────────────────────────\n")
        
        # 5. Mail Infrastructure
        infra = forensics.get('infrastructure', {})
        if infra:
            print(f"┌─ MAIL INFRASTRUCTURE")
            
            if infra.get('mua'):
                print(f"│  Mail Client: {infra.get('mua')}")
            
            if infra.get('x_mailer'):
                print(f"│  X-Mailer: {infra.get('x_mailer')}")
            
            if infra.get('message_id_domain'):
                print(f"│  Message-ID Domain: {infra.get('message_id_domain')}")
            
            suspicious_headers = infra.get('suspicious_headers', [])
            if suspicious_headers:
                print(f"│")
                print(f"│  🚨 Suspicious Headers: {len(suspicious_headers)}")
                for sh in suspicious_headers[:3]:
                    print(f"│    {sh.get('header')}: {sh.get('value')[:50]}...")
            
            print(f"└─────────────────────────────────────────────────────────────\n")
    
    # LLM Analysis (MAIN OUTPUT)
    llm_analysis = result.get('llm_analysis', {})
    if llm_analysis and llm_analysis.get('analysis'):
        provider = llm_analysis.get('provider', 'Unknown')
        
        print(f"[Analysis - {provider}]")
        print(f"{llm_analysis['analysis']}\n")
        
        # Recommendations from LLM
        recommendations = llm_analysis.get('recommendations', [])
        if recommendations:
            print("Recommendations:")
            for i, rec in enumerate(recommendations, 1):
                print(f"  {i}. {rec}")
            print()
def print_file_results(result: dict, file_path: str):
    """Print file analysis results in clean format."""
    
    # Use v1.0.0 professional output if enabled
    if USE_V55_OUTPUT:
        try:
            professional_output = SOCOutputFormatter.format_file_report(result, file_path)
            print(professional_output)
            return
        except Exception as e:
            logger.warning(f"[OUTPUT] v1.0.0 formatter failed, using legacy: {e}")
    
    # Legacy output (fallback)
    print_header(f"File Analysis: {Path(file_path).name}")
    
    # Verdict and Scores
    verdict = result.get('verdict', 'UNKNOWN')
    hash_score = result.get('hash_score', 0)
    composite_score = result.get('composite_score', 0)
    
    verdict_emoji = {
        'MALICIOUS': '🦠',
        'SUSPICIOUS': '⚠️',
        'CLEAN': '✅',
        'UNKNOWN': '❓'
    }
    
    print(f"{verdict_emoji.get(verdict, '')} Verdict: {verdict}")
    print(f"Hash Score: {hash_score}/100")
    print(f"Composite Score: {composite_score}/100\n")
    
    # File Info
    file_info = result.get('file_info', {})
    hashes = result.get('hashes', {})
    
    print(f"File Info:")
    print(f"  Size: {file_info.get('size', 0):,} bytes ({file_info.get('size_mb', 0)} MB)")
    print(f"  Type: {file_info.get('extension', 'Unknown')}")
    print(f"  SHA256: {hashes.get('sha256', 'Unknown')[:32]}...\n")
    
    # Static Analysis Summary
    static = result.get('static_analysis', {})
    
    # PE-specific DETAILED ANALYSIS
    if static.get('file_type') == 'PE':
        print(f"╔══════════════════════════════════════════════════════════════╗")
        print(f"║  PE STATIC ANALYSIS - DETAILED                               ║")
        print(f"╚══════════════════════════════════════════════════════════════╝\n")
        
        print(f"File Type: {static.get('pe_type', 'Unknown')} ({static.get('architecture', 'Unknown')})")
        print(f"Compile Time: {static.get('compile_time', 'Unknown')}")
        print(f"Entry Point: {static.get('entry_point', 'Unknown')}")
        print(f"Subsystem: {static.get('subsystem', 'Unknown')}")
        
        sig = static.get('signature', {})
        print(f"Signed: {sig.get('signed', False)}")
        if sig.get('signed'):
            print(f"  Signer: {sig.get('signer', 'Unknown')}")
            print(f"  Valid: {sig.get('valid', False)}")
        
        # Entropy Analysis - DETAILED
        entropy_analysis = static.get('entropy_analysis', {})
        if entropy_analysis:
            file_entropy = entropy_analysis.get('file_entropy', {})
            overall_entropy = file_entropy.get('overall_entropy', 0)
            interpretation = file_entropy.get('interpretation', {})
            entropy_cat = interpretation.get('category', 'unknown')
            entropy_desc = interpretation.get('description', '')
            
            print(f"\n┌─ ENTROPY ANALYSIS")
            print(f"│  Overall Entropy: {overall_entropy:.2f} ({entropy_cat.upper()})")
            if entropy_desc:
                print(f"│  Classification: {entropy_desc}")
            print(f"└─────────────────────────────────────────────────────────────\n")
        
        # Packer Detection - DETAILED
        packer = static.get('packer_detection', {})
        if packer.get('packed'):
            print(f"┌─ PACKER DETECTION")
            print(f"│  Detected: {packer.get('packer', 'Unknown')} ({packer.get('confidence', 'UNKNOWN')} confidence)")
            indicators = packer.get('indicators', [])
            if indicators:
                print(f"│  Indicators: {', '.join(indicators[:5])}")
            print(f"└─────────────────────────────────────────────────────────────\n")
        
        # PE Sections - DETAILED TABLE
        sections = static.get('sections', [])
        if sections:
            print(f"┌─ SECTIONS ({len(sections)} total)")
            for section in sections[:12]:  # Show top 12
                name = section.get('name', 'Unknown').strip()
                size = section.get('virtual_size', 0)
                raw_size = section.get('raw_size', 0)
                entropy = section.get('entropy', 0)
                suspicious = section.get('suspicious', False)
                
                flag = "🚨" if suspicious else "  "
                
                # Format characteristics
                chars = section.get('characteristics', [])
                char_str = '/'.join(chars) if chars else '-'
                
                print(f"│  {flag} {name:10s} │ VSize: {size:8,} │ RSize: {raw_size:8,} │ Entropy: {entropy:.2f} │ {char_str}")
                
                if suspicious and section.get('suspicion_reason'):
                    print(f"│     ⚠️  {section.get('suspicion_reason')}")
            print(f"└─────────────────────────────────────────────────────────────\n")
        
        # Imports - DETAILED with Suspicious APIs
        imports = static.get('imports', [])
        if imports:
            suspicious_imports = [imp for imp in imports if imp.get('suspicious_count', 0) > 0]
            total_suspicious = sum(imp.get('suspicious_count', 0) for imp in imports)
            
            if suspicious_imports:
                print(f"┌─ SUSPICIOUS IMPORTS ({total_suspicious} suspicious APIs total)")
                for imp in suspicious_imports[:8]:
                    dll = imp.get('dll', 'Unknown')
                    sus_count = imp.get('suspicious_count', 0)
                    sus_apis = imp.get('suspicious_apis', [])
                    print(f"│  🚨 {dll}: {sus_count} suspicious APIs")
                    if sus_apis:
                        for api in sus_apis[:6]:
                            print(f"│       • {api}")
                print(f"└─────────────────────────────────────────────────────────────\n")
        
        # Anti-Analysis Techniques
        anti_analysis = static.get('anti_analysis', [])
        if anti_analysis:
            print(f"┌─ ANTI-ANALYSIS TECHNIQUES ({len(anti_analysis)} detected)")
            for technique in anti_analysis[:8]:
                print(f"│  🚨 {technique}")
            print(f"└─────────────────────────────────────────────────────────────\n")
        
        # Exports
        exports = static.get('exports', [])
        if exports:
            print(f"┌─ EXPORTS ({len(exports)} total)")
            for exp in exports[:10]:
                print(f"│    {exp}")
            if len(exports) > 10:
                print(f"│    ... and {len(exports) - 10} more")
            print(f"└─────────────────────────────────────────────────────────────\n")
        
        # Rich Header
        rich_header = static.get('rich_header', {})
        if rich_header.get('present'):
            print(f"┌─ RICH HEADER")
            print(f"│  Present: Yes")
            if rich_header.get('hash'):
                print(f"│  Hash: {rich_header.get('hash')}")
            print(f"└─────────────────────────────────────────────────────────────\n")
    
    # Sandbox Analysis - DETAILED (EACH SANDBOX SEPARATELY)
    sandbox_analysis = result.get('sandbox_analysis', {})
    if sandbox_analysis:
        summary = sandbox_analysis.get('summary', {})
        available_reports = summary.get('available_reports', 0)
        
        if available_reports > 0:
            print(f"╔══════════════════════════════════════════════════════════════╗")
            print(f"║  SANDBOX ANALYSIS - DETAILED (4 SANDBOXES)                   ")
            print(f"╚══════════════════════════════════════════════════════════════╝")
            print(f"Available Reports: {available_reports}/4\n")
            
            # Overall Verdict
            verdict = summary.get('verdict', 'UNKNOWN')
            if verdict != 'UNKNOWN':
                print(f"Overall Verdict: {verdict}\n")
            
            # ========== SANDBOX 1: Hybrid Analysis ==========
            hybrid = sandbox_analysis.get('hybrid_analysis', {})
            print(f"┌─ SANDBOX 1: Hybrid Analysis")
            if hybrid and not hybrid.get('error'):
                if hybrid.get('found'):
                    print(f"│  Status: ✅ REPORT FOUND")
                    print(f"│  Verdict: {hybrid.get('verdict', 'Unknown')}")
                    print(f"│  Threat Score: {hybrid.get('threat_score', 0)}/100")
                    
                    tags = hybrid.get('tags', [])
                    if tags:
                        print(f"│  Tags: {', '.join(tags[:5])}")
                    
                    if hybrid.get('report_url'):
                        print(f"│  🔗 {hybrid.get('report_url')}")
                else:
                    print(f"│  Status: ⚠️ NO REPORT FOUND")
            else:
                print(f"│  Status: ⚠️ {hybrid.get('error', 'Not checked')}")
            print(f"└─────────────────────────────────────────────────────────────\n")
            
            # ========== SANDBOX 2: VirusTotal Behavior ==========
            vt_behavior = sandbox_analysis.get('virustotal_behavior', {})
            print(f"┌─ SANDBOX 2: VirusTotal Behavior Analysis")
            if vt_behavior and not vt_behavior.get('error'):
                if vt_behavior.get('found'):
                    print(f"│  Status: ✅ REPORT FOUND")
                    
                    behaviors = vt_behavior.get('behaviors', [])
                    if behaviors:
                        print(f"│  Behaviors: {len(behaviors)} detected")
                        for b in behaviors[:3]:
                            print(f"│    • {b}")
                    
                    network = vt_behavior.get('network_activity', {})
                    if network.get('ips') or network.get('domains'):
                        print(f"│  Network Activity:")
                        if network.get('ips'):
                            print(f"│    IPs: {', '.join(network.get('ips', [])[:3])}")
                        if network.get('domains'):
                            print(f"│    Domains: {', '.join(network.get('domains', [])[:3])}")
                    
                    if vt_behavior.get('report_url'):
                        print(f"│  🔗 {vt_behavior.get('report_url')}")
                else:
                    print(f"│  Status: ⚠️ NO REPORT FOUND")
            else:
                print(f"│  Status: ⚠️ {vt_behavior.get('error', 'Not checked')}")
            print(f"└─────────────────────────────────────────────────────────────\n")
            
            # ========== SANDBOX 3: ANY.RUN ==========
            anyrun = sandbox_analysis.get('anyrun', {})
            print(f"┌─ SANDBOX 3: ANY.RUN (Public Submissions)")
            if anyrun and not anyrun.get('error'):
                if anyrun.get('found'):
                    print(f"│  Status: ✅ SUBMISSION FOUND")
                    print(f"│  Verdict: {anyrun.get('verdict', 'Unknown')}")
                    
                    if anyrun.get('malware_family'):
                        print(f"│  Malware Family: {anyrun.get('malware_family')}")
                    
                    if anyrun.get('report_url'):
                        print(f"│  🔗 {anyrun.get('report_url')}")
                else:
                    print(f"│  Status: ⚠️ NO SUBMISSION FOUND")
            else:
                print(f"│  Status: ⚠️ {anyrun.get('error', 'Not checked')}")
            print(f"└─────────────────────────────────────────────────────────────\n")
            
            # ========== SANDBOX 4: Joe Sandbox ==========
            joe = sandbox_analysis.get('joe_sandbox', {})
            print(f"┌─ SANDBOX 4: Joe Sandbox")
            if joe and not joe.get('error'):
                if joe.get('found'):
                    print(f"│  Status: ✅ REPORT FOUND")
                    print(f"│  Verdict: {joe.get('verdict', 'Unknown')}")
                    print(f"│  Threat Score: {joe.get('threat_score', 0)}/100")
                    
                    behaviors = joe.get('behaviors', [])
                    if behaviors:
                        print(f"│  Behaviors: {len(behaviors)} detected")
                        for b in behaviors[:3]:
                            print(f"│    • {b}")
                    
                    if joe.get('report_url'):
                        print(f"│  🔗 {joe.get('report_url')}")
                else:
                    print(f"│  Status: ⚠️ NO REPORT FOUND")
            else:
                print(f"│  Status: ⚠️ {joe.get('error', 'Not checked')}")
            print(f"└─────────────────────────────────────────────────────────────\n")
            
            # ========== AGGREGATE RESULTS ==========
            print(f"┌─ AGGREGATE ANALYSIS")
            
            # Behaviors
            behaviors = summary.get('behaviors', [])
            if behaviors:
                print(f"│  Total Behaviors: {len(behaviors)}")
                for behavior in behaviors[:5]:
                    print(f"│    • {behavior}")
            
            # Network Activity
            network = summary.get('network_activity', {})
            domains = network.get('domains', [])
            ips = network.get('ips', [])
            
            if domains or ips:
                print(f"│")
                print(f"│  Network Activity:")
                if ips:
                    print(f"│    IPs: {', '.join(ips[:5])}")
                if domains:
                    print(f"│    Domains: {', '.join(domains[:5])}")
            
            # MITRE ATT&CK
            mitre = summary.get('mitre_techniques', [])
            if mitre:
                print(f"│")
                print(f"│  MITRE ATT&CK Techniques: {len(mitre)}")
                for technique in mitre[:5]:
                    print(f"│    • {technique}")
            
            print(f"└─────────────────────────────────────────────────────────────\n")
    
    # String Analysis - DETAILED
    string_analysis = result.get('string_analysis', {})
    if string_analysis:
        total_strings = string_analysis.get('total_strings', 0)
        ascii_strings = string_analysis.get('ascii_strings', 0)
        unicode_strings = string_analysis.get('unicode_strings', 0)
        suspicious_cats = string_analysis.get('suspicious_categories', {})
        
        print(f"╔══════════════════════════════════════════════════════════════╗")
        print(f"║  STRING ANALYSIS - DETAILED                                   ")
        print(f"╚══════════════════════════════════════════════════════════════╝")
        print(f"Total Strings: {total_strings:,} (ASCII: {ascii_strings:,}, Unicode: {unicode_strings:,})\n")
        
        if suspicious_cats:
            print(f"┌─ SUSPICIOUS STRING CATEGORIES")
            for cat_name, strings in list(suspicious_cats.items())[:8]:
                print(f"│")
                print(f"│  {cat_name.upper()}: ({len(strings)} strings)")
                for string in strings[:5]:  # Show first 5
                    print(f"│    • {string[:80]}")
            print(f"└─────────────────────────────────────────────────────────────\n")
        
        # Interesting Strings (Top 20)
        interesting_strings = string_analysis.get('interesting_strings', [])
        if interesting_strings:
            print(f"┌─ TOP INTERESTING STRINGS ({len(interesting_strings)} found)")
            for string in interesting_strings[:15]:
                print(f"│    {string[:90]}")
            print(f"└─────────────────────────────────────────────────────────────\n")
        
        # Registry Keys
        reg_keys = string_analysis.get('registry_keys', [])
        if reg_keys:
            print(f"┌─ REGISTRY KEYS ({len(reg_keys)} found)")
            for key in reg_keys[:8]:
                print(f"│    • {key}")
            print(f"└─────────────────────────────────────────────────────────────\n")
        
        # Mutexes
        mutexes = string_analysis.get('mutexes', [])
        if mutexes:
            print(f"┌─ MUTEXES ({len(mutexes)} found)")
            for mutex in mutexes[:5]:
                print(f"│    • {mutex}")
            print(f"└─────────────────────────────────────────────────────────────\n")
        
        # User Agents
        user_agents = string_analysis.get('user_agents', [])
        if user_agents:
            print(f"┌─ USER AGENTS ({len(user_agents)} found)")
            for ua in user_agents[:3]:
                print(f"│    • {ua[:80]}")
            print(f"└─────────────────────────────────────────────────────────────\n")
    
    # YARA Analysis - DETAILED
    yara_analysis = result.get('yara_analysis', {})
    if yara_analysis and yara_analysis.get('matches'):
        matches = yara_analysis['matches']
        interpretation = yara_analysis.get('interpretation', {})
        
        print(f"╔══════════════════════════════════════════════════════════════╗")
        print(f"║  YARA ANALYSIS - {len(matches)} RULES MATCHED                        ")
        print(f"╚══════════════════════════════════════════════════════════════╝\n")
        
        for match in matches:
            rule_name = match.get('rule', 'Unknown')
            strings = match.get('strings', [])
            meta = match.get('meta', {})
            
            severity = meta.get('severity', 'UNKNOWN')
            severity_emoji = '🚨' if severity == 'CRITICAL' else '⚠️' if severity == 'MEDIUM' else 'ℹ️'
            
            print(f"┌─ {severity_emoji} RULE: {rule_name}")
            if meta:
                if meta.get('description'):
                    print(f"│  Description: {meta['description']}")
                if meta.get('severity'):
                    print(f"│  Severity: {meta['severity']}")
                if meta.get('author'):
                    print(f"│  Author: {meta['author']}")
                if meta.get('malware_family'):
                    print(f"│  Malware Family: {meta['malware_family']}")
            
            if strings:
                print(f"│")
                print(f"│  Matched Strings: ({len(strings)} matches)")
                for string_match in strings[:8]:
                    offset = string_match.get('offset', 0)
                    string_val = string_match.get('string', '')
                    identifier = string_match.get('identifier', '')
                    print(f"│    [{identifier}] @ 0x{offset:08x}: {string_val[:60]}")
            print(f"└─────────────────────────────────────────────────────────────\n")
        
        # Malware Families Summary
        malware_families = interpretation.get('malware_families', [])
        if malware_families:
            print(f"┌─ IDENTIFIED MALWARE FAMILIES")
            for family in malware_families:
                print(f"│  🦠 {family}")
            print(f"└─────────────────────────────────────────────────────────────\n")
        
        severity = interpretation.get('severity', 'NONE')
        if severity != 'NONE':
            severity_emoji = '🚨' if severity == 'CRITICAL' else '⚠️' if severity == 'MEDIUM' else 'ℹ️'
            print(f"Overall YARA Severity: {severity_emoji} {severity}\n")
    
    # Embedded IOCs - DETAILED
    ioc_analysis = result.get('ioc_analysis', {})
    if ioc_analysis.get('total_iocs', 0) > 0:
        print(f"Embedded IOC Analysis:")
        print(f"  Total IOCs: {ioc_analysis.get('total_iocs', 0)}")
        print(f"  Malicious: {ioc_analysis.get('malicious_iocs', 0)}")
        print(f"  Suspicious: {ioc_analysis.get('suspicious_iocs', 0)}")
        
        # Detailed IOC Results
        ioc_results = ioc_analysis.get('ioc_results', {})
        
        # IPs
        ips = ioc_results.get('ips', [])
        if ips:
            malicious_ips = [ip for ip in ips if ip.get('verdict') == 'MALICIOUS']
            if malicious_ips:
                print(f"\n  🚨 Malicious IPs: ({len(malicious_ips)} found)")
                for ip in malicious_ips[:5]:
                    ioc = ip.get('ioc', 'Unknown')
                    score = ip.get('threat_score', 0)
                    sources = ip.get('flagged_sources', [])
                    print(f"    • {ioc} (Score: {score}/100)")
                    if sources:
                        print(f"      Sources: {', '.join(sources[:3])}")
        
        # Domains
        domains = ioc_results.get('domains', [])
        if domains:
            malicious_domains = [d for d in domains if d.get('verdict') == 'MALICIOUS']
            if malicious_domains:
                print(f"\n  🚨 Malicious Domains: ({len(malicious_domains)} found)")
                for domain in malicious_domains[:5]:
                    ioc = domain.get('ioc', 'Unknown')
                    score = domain.get('threat_score', 0)
                    sources = domain.get('flagged_sources', [])
                    print(f"    • {ioc} (Score: {score}/100)")
                    if sources:
                        print(f"      Sources: {', '.join(sources[:3])}")
        
        # URLs
        urls = ioc_results.get('urls', [])
        if urls:
            malicious_urls = [u for u in urls if u.get('verdict') == 'MALICIOUS']
            if malicious_urls:
                print(f"\n  🚨 Malicious URLs: ({len(malicious_urls)} found)")
                for url in malicious_urls[:3]:
                    ioc = url.get('ioc', 'Unknown')
                    score = url.get('threat_score', 0)
                    print(f"    • {ioc[:80]} (Score: {score}/100)")
        
        print()
    
    # LLM Analysis (MAIN OUTPUT)
    llm_analysis = result.get('llm_analysis', {})
    if llm_analysis and llm_analysis.get('analysis'):
        provider = llm_analysis.get('provider', 'Unknown')
        
        print(f"[Analysis - {provider}]")
        print(f"{llm_analysis['analysis']}\n")
        
        # Recommendations from LLM
        recommendations = llm_analysis.get('recommendations', [])
        if recommendations:
            print("Recommendations:")
            for i, rec in enumerate(recommendations, 1):
                print(f"  {i}. {rec}")
            print()
async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Blue Team Assistant - SOC-Grade Threat Analysis Toolkit'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Analysis type')
    
    # IOC investigation
    ioc_parser = subparsers.add_parser('ioc', help='Investigate IOC')
    ioc_parser.add_argument('indicator', help='IP, domain, URL, or hash')
    ioc_parser.add_argument('--report', help='Generate HTML report')
    
    # Email analysis
    email_parser = subparsers.add_parser('email', help='Analyze email')
    email_parser.add_argument('path', help='Path to .eml file')
    email_parser.add_argument('--report', help='Generate HTML report')
    
    # File analysis
    file_parser = subparsers.add_parser('file', help='Analyze file')
    file_parser.add_argument('path', help='Path to file')
    file_parser.add_argument('--report', help='Generate HTML report')
    file_parser.add_argument('--pdf', help='Generate Executive PDF summary')
    file_parser.add_argument('--timeline', help='Generate Timeline HTML')
    file_parser.add_argument('--navigator', help='Generate MITRE Navigator JSON')
    file_parser.add_argument('--sandbox', action='store_true', help='Auto-submit to sandboxes')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Load config
    try:
        config = load_config()
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        print(f"\n❌ Error: Could not load config.yaml")
        print(f"   Make sure config.yaml exists and is properly formatted")
        return
    
    try:
        if args.command == 'ioc':
            investigator = IOCInvestigator(config)
            result = await investigator.investigate(args.indicator)
            
            if 'error' not in result:
                print_ioc_results(result, args.indicator)
            else:
                print(f"\n❌ Error: {result['error']}")
        
        elif args.command == 'email':
            if not Path(args.path).exists():
                print(f"\n❌ Error: File not found: {args.path}")
                return
            
            analyzer = EmailAnalyzer(config)
            file_analyzer = MalwareAnalyzer(config)
            ioc_investigator = IOCInvestigator(config)
            
            # Cross-tool integration
            analyzer.file_analyzer = file_analyzer
            analyzer.ioc_investigator = ioc_investigator
            
            result = await analyzer.analyze(args.path)
            
            if 'error' not in result:
                print_email_results(result, args.path)
            else:
                print(f"\n❌ Error: {result['error']}")
        
        elif args.command == 'file':
            if not Path(args.path).exists():
                print(f"\n❌ Error: File not found: {args.path}")
                return
            
            analyzer = MalwareAnalyzer(config)
            ioc_investigator = IOCInvestigator(config)
            
            # Cross-tool integration
            analyzer.ioc_investigator = ioc_investigator
            
            result = await analyzer.analyze(args.path)
            
            if 'error' not in result:
                print_file_results(result, args.path)
            else:
                print(f"\n❌ Error: {result['error']}")
        
        # HTML Report (if requested)
        if hasattr(args, 'report') and args.report:
            from .reporting.html_report_generator import HTMLReportGenerator
            
            # Use new comprehensive HTML report generator ()
            generator = HTMLReportGenerator()
            
            report_path = None
            if args.command == 'ioc':
                report_path = generator.generate_ioc_report(result, args.indicator, args.report)
            elif args.command == 'file':
                filename = Path(args.path).name if args.path else 'unknown'
                report_path = generator.generate_file_report(result, filename, args.report)
            elif args.command == 'email':
                report_path = generator.generate_email_report(result, args.path or 'email.eml', args.report)
            
            if report_path:
                print(f"\n📄 HTML report saved: {report_path}")
        
        # Executive PDF Report ()
        if hasattr(args, 'pdf') and args.pdf and args.command == 'file':
            try:
                from .reporting.executive_pdf import generate_executive_pdf
                pdf_path = generate_executive_pdf(result, args.pdf, 'file')
                if pdf_path:
                    print(f"\n📑 Executive PDF saved: {pdf_path}")
                else:
                    print("\n⚠️  PDF generation failed (install reportlab: pip install reportlab)")
            except ImportError:
                print("\n⚠️  PDF generation requires reportlab: pip install reportlab")
            except Exception as e:
                logger.error(f"PDF generation failed: {e}")
        
        # Timeline HTML Export ()
        if hasattr(args, 'timeline') and args.timeline and args.command == 'file':
            try:
                from .reporting.timeline_generator import export_timeline_html
                timeline_path = export_timeline_html(result, args.timeline)
                print(f"\n⏱️  Timeline HTML saved: {timeline_path}")
            except Exception as e:
                logger.error(f"Timeline generation failed: {e}")
                print(f"\n⚠️  Timeline generation failed: {e}")
        
        # MITRE Navigator JSON Export ()
        if hasattr(args, 'navigator') and args.navigator and args.command == 'file':
            try:
                from .reporting.mitre_navigator import generate_navigator_layer
                layer = generate_navigator_layer(result, args.navigator)
                print(f"\n🎯 MITRE Navigator JSON saved: {args.navigator}")
                print(f"   Import at: https://mitre-attack.github.io/attack-navigator/")
            except Exception as e:
                logger.error(f"Navigator export failed: {e}")
                print(f"\n⚠️  Navigator export failed: {e}")
        
        # Auto-Sandbox Submission ()
        if hasattr(args, 'sandbox') and args.sandbox and args.command == 'file':
            try:
                from .integrations.sandbox_submitter import auto_submit_suspicious
                score = result.get('composite_score', 0)
                
                print(f"\n🔬 Auto-submitting to sandboxes...")
                submit_result = await auto_submit_suspicious(args.path, score, config)
                
                if submit_result:
                    print(f"   Submitted to sandboxes:")
                    for provider, data in submit_result.get('results', {}).items():
                        status = "✅" if data.get('success') else "❌"
                        print(f"   {status} {provider}: {data.get('report_url', data.get('error', 'N/A'))}")
                else:
                    print(f"   ℹ️  Skipped (score {score} outside submission range)")
            except Exception as e:
                logger.error(f"Sandbox submission failed: {e}")
                print(f"\n⚠️  Sandbox submission failed: {e}")
    
    except KeyboardInterrupt:
        print("\n\n⚠️  Analysis interrupted by user")
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        print(f"\n❌ Analysis failed: {e}")
if __name__ == '__main__':
    asyncio.run(main())
