"""
Author: Ugur AtesYARA rule scanning for malware detection."""

import logging
from typing import Dict, List
from pathlib import Path

logger = logging.getLogger(__name__)

# Check if yara-python is available
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("[YARA] yara-python not installed. YARA scanning disabled.")
class YaraScanner:
    """
    YARA rule scanner for malware detection.
    
    Features:
    - Scan files against YARA rules
    - Built-in common malware signatures
    - Custom rule support
    """
    
    # Built-in YARA rules for common malware families
    BUILTIN_RULES = """
rule Emotet_Strings
{
    meta:
        description = "Detects Emotet malware strings"
        author = "SOC Team"
    strings:
        $s1 = "InternetOpenUrlW" wide ascii
        $s2 = "InternetReadFile" wide ascii
        $s3 = "cmd.exe /c" wide ascii
        $s4 = "WScript.Shell" wide ascii
    condition:
        3 of them
}

rule QakBot_Network
{
    meta:
        description = "Detects QakBot network indicators"
    strings:
        $n1 = "/%d/%s.png" wide ascii
        $n2 = "/%d/%d/" wide ascii
        $n3 = "Cookie:" wide ascii
    condition:
        2 of them
}

rule Cobalt_Strike
{
    meta:
        description = "Detects Cobalt Strike beacon"
    strings:
        $s1 = "%c%c%c%c%c%c%c%c%cMSSE-" ascii
        $s2 = "StartBrowser" ascii
        $s3 = "runasadmin" ascii
        $s4 = "postex" ascii
    condition:
        2 of them
}

rule Metasploit_Meterpreter
{
    meta:
        description = "Detects Meterpreter payload"
    strings:
        $s1 = "metsrv.dll" ascii
        $s2 = "METERPRETER_TRANSPORT" ascii
        $s3 = "ext_server" ascii
    condition:
        any of them
}

rule Generic_Ransomware
{
    meta:
        description = "Detects generic ransomware indicators"
    strings:
        $r1 = ".locked" ascii
        $r2 = ".encrypted" ascii
        $r3 = "bitcoin" nocase
        $r4 = "ransom" nocase
        $r5 = "decrypt" nocase
        $r6 = "HOW_TO_RESTORE" ascii
    condition:
        3 of them
}

rule Suspicious_PowerShell
{
    meta:
        description = "Detects suspicious PowerShell patterns"
    strings:
        $p1 = "-EncodedCommand" nocase
        $p2 = "IEX" nocase
        $p3 = "Invoke-Expression" nocase
        $p4 = "DownloadString" nocase
        $p5 = "FromBase64String" nocase
    condition:
        2 of them
}

rule Packer_UPX
{
    meta:
        description = "Detects UPX packer"
    strings:
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX!" ascii
    condition:
        any of them
}

rule Anti_Debug
{
    meta:
        description = "Detects anti-debug techniques"
    strings:
        $a1 = "IsDebuggerPresent" ascii
        $a2 = "CheckRemoteDebuggerPresent" ascii
        $a3 = "OutputDebugString" ascii
        $a4 = "NtQueryInformationProcess" ascii
    condition:
        2 of them
}

rule Code_Injection
{
    meta:
        description = "Detects code injection indicators"
    strings:
        $i1 = "CreateRemoteThread" ascii
        $i2 = "VirtualAllocEx" ascii
        $i3 = "WriteProcessMemory" ascii
        $i4 = "NtUnmapViewOfSection" ascii
    condition:
        2 of them
}
"""
    
    def __init__(self, rules_path: str = None):
        """
        Initialize YARA scanner.
        
        Args:
            rules_path: Path to custom YARA rules file
        """
        self.rules_path = rules_path
        self.rules = None
        
        if not YARA_AVAILABLE:
            logger.warning("[YARA] Scanner disabled - yara-python not installed")
            return
        
        try:
            if rules_path and Path(rules_path).exists():
                # Load custom rules
                self.rules = yara.compile(filepath=rules_path)
                logger.info(f"[YARA] Loaded custom rules from {rules_path}")
            else:
                # Load built-in rules
                self.rules = yara.compile(source=self.BUILTIN_RULES)
                logger.info("[YARA] Loaded built-in rules")
        except Exception as e:
            logger.error(f"[YARA] Failed to compile rules: {e}")
    
    def scan_file(self, file_path: str) -> List[Dict]:
        """
        Scan file with YARA rules.
        
        Args:
            file_path: Path to file to scan
        
        Returns:
            List of matched rules with metadata
        """
        if not YARA_AVAILABLE or not self.rules:
            return []
        
        matches = []
        
        try:
            yara_matches = self.rules.match(file_path)
            
            for match in yara_matches:
                match_info = {
                    'rule': match.rule,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': []
                }
                
                # Get matched strings (first 5)
                for string_match in match.strings[:5]:
                    match_info['strings'].append({
                        'offset': string_match[0],
                        'identifier': string_match[1],
                        'data': string_match[2].decode('utf-8', errors='ignore')[:100]
                    })
                
                matches.append(match_info)
            
            if matches:
                logger.info(f"[YARA] Found {len(matches)} matches in {Path(file_path).name}")
            
        except Exception as e:
            logger.error(f"[YARA] Scan failed: {e}")
        
        return matches
    
    @staticmethod
    def interpret_matches(matches: List[Dict]) -> Dict:
        """
        Interpret YARA matches and provide analysis.
        
        Args:
            matches: List of YARA matches
        
        Returns:
            Analysis dict with severity and recommendations
        """
        if not matches:
            return {
                'severity': 'NONE',
                'malware_families': [],
                'techniques': [],
                'recommendations': []
            }
        
        analysis = {
            'severity': 'LOW',
            'malware_families': [],
            'techniques': [],
            'recommendations': []
        }
        
        # Categorize matches
        malware_rules = ['Emotet', 'QakBot', 'Cobalt', 'Meterpreter', 'Ransomware']
        technique_rules = ['Anti_Debug', 'Code_Injection', 'PowerShell']
        packer_rules = ['Packer']
        
        for match in matches:
            rule_name = match['rule']
            
            # Check malware families
            for malware in malware_rules:
                if malware.lower() in rule_name.lower():
                    analysis['malware_families'].append(malware)
                    analysis['severity'] = 'CRITICAL'
            
            # Check techniques
            for technique in technique_rules:
                if technique.lower() in rule_name.lower():
                    analysis['techniques'].append(rule_name)
                    if analysis['severity'] == 'LOW':
                        analysis['severity'] = 'MEDIUM'
            
            # Check packers
            for packer in packer_rules:
                if packer.lower() in rule_name.lower():
                    analysis['techniques'].append('Packed executable')
        
        # Generate recommendations
        if analysis['malware_families']:
            analysis['recommendations'].append('⚠️ CRITICAL: Known malware family detected')
            analysis['recommendations'].append('🚨 Isolate system immediately')
            analysis['recommendations'].append('🔍 Perform full incident response')
        
        if 'Anti_Debug' in analysis['techniques']:
            analysis['recommendations'].append('⚙️ File uses anti-debugging techniques')
        
        if 'Code_Injection' in analysis['techniques']:
            analysis['recommendations'].append('💉 File may perform code injection')
        
        return analysis
