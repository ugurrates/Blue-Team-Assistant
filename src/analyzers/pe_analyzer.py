"""
PE Analyzer - Profesyonel Windows Executable Analizi.

Entegre Araçlar:
- pefile: PE header parsing
- capa: Capability detection (Mandiant)
- FLOSS: Obfuscated string extraction (Mandiant)
- DIE: Packer/compiler detection
- YARA: Malware family detection

v1.0.0 - Professional Analysis Suite
"""

import os
import math
import logging
from typing import Dict, List, Optional
from collections import Counter
from pathlib import Path

logger = logging.getLogger(__name__)

# pefile availability
PEFILE_AVAILABLE = False
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    logger.warning("[PE] pefile not available - install with: pip install pefile")


class PEAnalyzer:
    """
    Profesyonel PE file analizi with external tool integration.
    
    Features:
    - PE header parsing (pefile)
    - Capability detection (capa)
    - Obfuscated string extraction (FLOSS)
    - Packer/compiler detection (DIE)
    - Section entropy analysis
    - Import/Export analysis
    - Suspicious indicator detection
    """
    
    # Known packer sections
    PACKER_SECTIONS = {
        'UPX': ['UPX0', 'UPX1', 'UPX2', '.UPX'],
        'ASPack': ['.aspack', '.adata', '.ASPack'],
        'PECompact': ['PEC2', 'PECompact2', '.PEC'],
        'Themida': ['.themida', '.tmd', '.Themida'],
        'VMProtect': ['.vmp0', '.vmp1', '.vmp2', '.VMP'],
        'Enigma': ['.enigma1', '.enigma2'],
        'MPRESS': ['.MPRESS1', '.MPRESS2'],
        'Petite': ['.petite'],
    }
    
    # Suspicious imports by category
    SUSPICIOUS_IMPORTS = {
        'process_injection': [
            'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx',
            'CreateRemoteThread', 'CreateRemoteThreadEx', 'WriteProcessMemory',
            'ReadProcessMemory', 'NtCreateThreadEx', 'RtlCreateUserThread',
            'NtAllocateVirtualMemory', 'NtProtectVirtualMemory',
            'QueueUserAPC', 'NtQueueApcThread', 'SetThreadContext',
        ],
        'process_hollowing': [
            'NtUnmapViewOfSection', 'ZwUnmapViewOfSection',
            'NtResumeThread', 'ZwResumeThread',
        ],
        'code_loading': [
            'LoadLibrary', 'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryEx',
            'GetProcAddress', 'GetModuleHandle', 'LdrLoadDll',
        ],
        'process_creation': [
            'CreateProcess', 'CreateProcessA', 'CreateProcessW',
            'ShellExecute', 'ShellExecuteA', 'ShellExecuteW',
            'WinExec', 'system',
        ],
        'network': [
            'URLDownloadToFile', 'InternetOpen', 'InternetOpenUrl',
            'InternetReadFile', 'HttpSendRequest', 'HttpOpenRequest',
            'WSAStartup', 'socket', 'connect', 'send', 'recv',
        ],
        'registry': [
            'RegSetValue', 'RegSetValueEx', 'RegCreateKey', 'RegCreateKeyEx',
            'RegOpenKey', 'RegOpenKeyEx', 'RegDeleteKey',
        ],
        'crypto': [
            'CryptAcquireContext', 'CryptEncrypt', 'CryptDecrypt',
            'CryptGenKey', 'CryptDeriveKey', 'BCryptEncrypt',
        ],
        'keylogger': [
            'SetWindowsHookEx', 'GetAsyncKeyState', 'GetKeyState',
            'GetKeyboardState', 'RegisterHotKey',
        ],
        'anti_debug': [
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
            'NtQueryInformationProcess', 'OutputDebugString',
        ],
    }
    
    def __init__(self):
        """Initialize PE analyzer with tool integration."""
        self._init_tools()
    
    def _init_tools(self):
        """Initialize external tools."""
        try:
            from ..tools.external_tool_runner import get_tool_runner
            self.tool_runner = get_tool_runner()
        except:
            self.tool_runner = None
        
        try:
            from .capability_analyzer import CapabilityAnalyzer
            self.capa_analyzer = CapabilityAnalyzer()
        except:
            self.capa_analyzer = None
        
        try:
            from .obfuscated_string_analyzer import ObfuscatedStringAnalyzer
            self.floss_analyzer = ObfuscatedStringAnalyzer()
        except:
            self.floss_analyzer = None
    
    def analyze(self, file_path: str) -> Dict:
        """
        Kapsamlı PE analizi with all integrated tools.
        
        Pipeline:
        1. PE header analysis (pefile)
        2. Capability detection (capa)
        3. Obfuscated string extraction (FLOSS)
        4. Packer/compiler detection (DIE)
        5. Combined threat scoring
        """
        logger.info(f"[PE] Analyzing: {Path(file_path).name}")
        
        result = {
            'file_path': file_path,
            'file_type': 'PE',
            'analysis_tools': [],
            'is_pe': False,
            
            # PE analysis
            'pe_analysis': {
                'headers': {},
                'sections': [],
                'imports': [],
                'exports': [],
                'resources': [],
                'entropy': {},
                'packer_detected': None,
                'suspicious_imports': [],
                'anomalies': [],
                'threat_score': 0,
            },
            
            # External tools
            'capabilities': {},
            'strings': {},
            'packer_detection': {},
            'embedded_files': {},
            
            # Combined
            'threat_indicators': [],
            'threat_score': 0,
            'verdict': 'UNKNOWN',
            'raw_outputs': {},
        }
        
        # 1. PE Header Analysis (pefile)
        if PEFILE_AVAILABLE:
            pe_result = self._analyze_pe_headers(file_path)
            result['pe_analysis'] = pe_result
            result['is_pe'] = pe_result.get('is_pe', False)
            result['analysis_tools'].append('pefile')
            
            if pe_result.get('suspicious_imports'):
                for imp in pe_result['suspicious_imports'][:5]:
                    result['threat_indicators'].append(f"Suspicious import: {imp}")
        
        # 2. Capability Detection (capa)
        if self.capa_analyzer and self.tool_runner and self.tool_runner.is_available('capa'):
            capa_result = self.capa_analyzer.analyze(file_path)
            if capa_result.success:
                result['capabilities'] = {
                    'success': True,
                    'capabilities': [
                        {'name': c.name, 'namespace': c.namespace, 'attack_ids': c.attack_ids}
                        for c in capa_result.capabilities
                    ],
                    'attack_techniques': capa_result.attack_techniques,
                    'mbc_behaviors': capa_result.mbc_behaviors,
                    'threat_score': capa_result.threat_score,
                    'summary': capa_result.summary,
                }
                result['raw_outputs']['capa'] = capa_result.raw_output[:50000]
                result['analysis_tools'].append('capa')
                
                if capa_result.capabilities:
                    result['threat_indicators'].append(
                        f"capa: {len(capa_result.capabilities)} capabilities detected"
                    )
        
        # 3. Obfuscated String Extraction (FLOSS)
        if self.floss_analyzer and self.tool_runner and self.tool_runner.is_available('floss'):
            floss_result = self.floss_analyzer.analyze(file_path)
            if floss_result.success:
                result['strings'] = {
                    'success': True,
                    'static_count': len(floss_result.static_strings),
                    'decoded_count': len(floss_result.decoded_strings),
                    'stack_count': len(floss_result.stack_strings),
                    'tight_count': len(floss_result.tight_strings),
                    'urls': floss_result.urls[:30],
                    'ips': floss_result.ips[:30],
                    'domains': floss_result.domains[:30],
                    'registry_keys': floss_result.registry_keys[:30],
                    'suspicious_strings': floss_result.suspicious_strings[:50],
                    'threat_score': floss_result.threat_score,
                    'summary': floss_result.summary,
                }
                result['raw_outputs']['floss'] = floss_result.raw_output[:50000]
                result['analysis_tools'].append('floss')
                
                if floss_result.decoded_strings:
                    result['threat_indicators'].append(
                        f"FLOSS: {len(floss_result.decoded_strings)} decoded strings (obfuscation)"
                    )
        
        # 4. Packer/Compiler Detection (DIE)
        if self.tool_runner and self.tool_runner.is_available('diec'):
            die_result = self.tool_runner.run_diec(file_path)
            if die_result.success and die_result.parsed_output:
                result['packer_detection'] = self._parse_die_output(die_result.parsed_output)
                result['raw_outputs']['diec'] = die_result.stdout
                result['analysis_tools'].append('diec')
                
                if result['packer_detection'].get('packers'):
                    result['threat_indicators'].append(
                        f"DIE: Packed with {result['packer_detection']['packers'][0]}"
                    )
                if result['packer_detection'].get('protectors'):
                    result['threat_indicators'].append(
                        f"DIE: Protected with {result['packer_detection']['protectors'][0]}"
                    )
        
        # 5. Embedded Files (binwalk)
        if self.tool_runner and self.tool_runner.is_available('binwalk'):
            binwalk_result = self.tool_runner.run_binwalk_signature(file_path)
            if binwalk_result.success:
                result['embedded_files'] = self._parse_binwalk_output(binwalk_result.stdout)
                result['raw_outputs']['binwalk'] = binwalk_result.stdout
                result['analysis_tools'].append('binwalk')
        
        # 6. Calculate combined score
        result['threat_score'] = self._calculate_combined_score(result)
        result['verdict'] = self._determine_verdict(result['threat_score'])
        
        return result
    
    # Alias for compatibility
    def analyze_file(self, file_path: str) -> Dict:
        """Alias for analyze() for backward compatibility."""
        return self.analyze(file_path)
    
    def _analyze_pe_headers(self, file_path: str) -> Dict:
        """Analyze PE headers using pefile."""
        result = {
            'is_pe': False,
            'headers': {},
            'sections': [],
            'imports': [],
            'exports': [],
            'resources': [],
            'entropy': {},
            'packer_detected': None,
            'suspicious_imports': [],
            'anomalies': [],
            'threat_score': 0,
        }
        
        try:
            pe = pefile.PE(file_path)
            result['is_pe'] = True
            
            # Headers
            result['headers'] = {
                'machine': hex(pe.FILE_HEADER.Machine),
                'timestamp': pe.FILE_HEADER.TimeDateStamp,
                'characteristics': hex(pe.FILE_HEADER.Characteristics),
                'subsystem': pe.OPTIONAL_HEADER.Subsystem if hasattr(pe, 'OPTIONAL_HEADER') else None,
                'dll_characteristics': hex(pe.OPTIONAL_HEADER.DllCharacteristics) if hasattr(pe, 'OPTIONAL_HEADER') else None,
                'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint) if hasattr(pe, 'OPTIONAL_HEADER') else None,
            }
            
            # Security features
            if hasattr(pe, 'OPTIONAL_HEADER'):
                dll_char = pe.OPTIONAL_HEADER.DllCharacteristics
                result['headers']['aslr'] = bool(dll_char & 0x0040)
                result['headers']['dep'] = bool(dll_char & 0x0100)
                result['headers']['seh'] = not bool(dll_char & 0x0400)
                result['headers']['cfg'] = bool(dll_char & 0x4000)
            
            # Sections
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                entropy = section.get_entropy()
                
                section_info = {
                    'name': section_name,
                    'virtual_address': hex(section.VirtualAddress),
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'entropy': round(entropy, 2),
                    'characteristics': hex(section.Characteristics),
                    'is_executable': bool(section.Characteristics & 0x20000000),
                    'is_writable': bool(section.Characteristics & 0x80000000),
                }
                result['sections'].append(section_info)
                
                # High entropy detection
                if entropy > 7.0:
                    result['anomalies'].append(f"High entropy section: {section_name} ({entropy:.2f})")
                
                # Packer detection by section name
                for packer, signatures in self.PACKER_SECTIONS.items():
                    if section_name in signatures:
                        result['packer_detected'] = packer
                        result['anomalies'].append(f"Packer detected: {packer}")
            
            # Overall entropy
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                result['entropy']['overall'] = round(self._calculate_entropy(data), 2)
            except:
                pass
            
            # Imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            result['imports'].append({
                                'dll': dll_name,
                                'function': func_name,
                            })
                            
                            # Check for suspicious imports
                            for category, funcs in self.SUSPICIOUS_IMPORTS.items():
                                if func_name in funcs:
                                    result['suspicious_imports'].append(f"[{category}] {func_name}")
            
            # Exports
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        result['exports'].append(exp.name.decode('utf-8', errors='ignore'))
            
            # Calculate PE-specific threat score
            result['threat_score'] = self._calculate_pe_score(result)
            
            pe.close()
            
        except pefile.PEFormatError:
            result['anomalies'].append("Invalid PE format")
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"[PE] Analysis error: {e}")
        
        return result
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy."""
        if not data:
            return 0.0
        
        byte_counts = Counter(data)
        length = len(data)
        
        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _parse_die_output(self, data: Dict) -> Dict:
        """Parse DIE JSON output."""
        result = {
            'file_type': data.get('filetype', 'Unknown'),
            'packers': [],
            'protectors': [],
            'compilers': [],
            'linkers': [],
            'libraries': [],
        }
        
        for item in data.get('detects', []):
            item_type = item.get('type', '').lower()
            name = item.get('name', '')
            version = item.get('version', '')
            entry = f"{name} {version}".strip()
            
            if item_type == 'packer':
                result['packers'].append(entry)
            elif item_type == 'protector':
                result['protectors'].append(entry)
            elif item_type == 'compiler':
                result['compilers'].append(entry)
            elif item_type == 'linker':
                result['linkers'].append(entry)
            elif item_type == 'library':
                result['libraries'].append(entry)
        
        return result
    
    def _parse_binwalk_output(self, output: str) -> Dict:
        """Parse binwalk output."""
        result = {
            'embedded_files': [],
            'high_entropy_regions': [],
        }
        
        for line in output.split('\n'):
            if line.strip() and not line.startswith('DECIMAL'):
                parts = line.split(None, 2)
                if len(parts) >= 3:
                    try:
                        result['embedded_files'].append({
                            'offset': int(parts[0]),
                            'description': parts[2][:100]
                        })
                    except:
                        pass
        
        return result
    
    def _calculate_pe_score(self, pe_result: Dict) -> int:
        """Calculate PE-specific threat score."""
        score = 0
        
        # Suspicious imports
        score += min(len(pe_result.get('suspicious_imports', [])) * 3, 30)
        
        # Packer detection
        if pe_result.get('packer_detected'):
            score += 20
        
        # Anomalies
        score += len(pe_result.get('anomalies', [])) * 5
        
        # High overall entropy
        if pe_result.get('entropy', {}).get('overall', 0) > 7.0:
            score += 15
        
        # Missing security features
        headers = pe_result.get('headers', {})
        if not headers.get('aslr'):
            score += 5
        if not headers.get('dep'):
            score += 5
        
        return min(score, 100)
    
    def _calculate_combined_score(self, result: Dict) -> int:
        """Calculate combined threat score from all tools."""
        scores = {}
        
        # PE analysis score
        scores['pe'] = result.get('pe_analysis', {}).get('threat_score', 0)
        
        # capa score
        scores['capa'] = result.get('capabilities', {}).get('threat_score', 0)
        
        # FLOSS score
        scores['floss'] = result.get('strings', {}).get('threat_score', 0)
        
        # Packer detection bonus
        if result.get('packer_detection', {}).get('packers'):
            scores['packer'] = 30
        elif result.get('packer_detection', {}).get('protectors'):
            scores['packer'] = 50
        else:
            scores['packer'] = 0
        
        # Weighted average
        weights = {'pe': 0.25, 'capa': 0.35, 'floss': 0.20, 'packer': 0.20}
        
        total_weight = sum(weights.get(k, 0) for k in scores.keys())
        weighted_sum = sum(scores[k] * weights.get(k, 0.1) for k in scores.keys())
        
        if total_weight > 0:
            return min(int(weighted_sum / total_weight), 100)
        return 0
    
    def _determine_verdict(self, score: int) -> str:
        """Determine verdict from score."""
        if score >= 70:
            return 'MALICIOUS'
        elif score >= 40:
            return 'SUSPICIOUS'
        else:
            return 'CLEAN'
