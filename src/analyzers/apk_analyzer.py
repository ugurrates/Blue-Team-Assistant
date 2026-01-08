"""
Author: Ugur Ates
APK Analyzer - Android Package Analizi.

Entegre Araçlar:
- apktool: APK decompilation
- aapt: Manifest/resource extraction
- unzip: APK extraction
- strings: String extraction
"""

import logging
import re
import zipfile
import tempfile
import os
from typing import Dict, List
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)
@dataclass
class APKAnalysisResult:
    """APK analiz sonucu."""
    success: bool = False
    file_path: str = ""
    package_name: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: int = 0
    target_sdk: int = 0
    permissions: List[str] = field(default_factory=list)
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    native_libraries: List[str] = field(default_factory=list)
    certificate_info: Dict = field(default_factory=dict)
    suspicious_permissions: List[str] = field(default_factory=list)
    suspicious_strings: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    threat_indicators: List[str] = field(default_factory=list)
    threat_score: int = 0
    raw_outputs: Dict[str, str] = field(default_factory=dict)
class APKAnalyzer:
    """Android APK analizi."""
    
    DANGEROUS_PERMISSIONS = [
        'android.permission.READ_SMS',
        'android.permission.SEND_SMS',
        'android.permission.RECEIVE_SMS',
        'android.permission.READ_CONTACTS',
        'android.permission.READ_CALL_LOG',
        'android.permission.RECORD_AUDIO',
        'android.permission.CAMERA',
        'android.permission.READ_EXTERNAL_STORAGE',
        'android.permission.WRITE_EXTERNAL_STORAGE',
        'android.permission.ACCESS_FINE_LOCATION',
        'android.permission.READ_PHONE_STATE',
        'android.permission.CALL_PHONE',
        'android.permission.PROCESS_OUTGOING_CALLS',
        'android.permission.RECEIVE_BOOT_COMPLETED',
        'android.permission.SYSTEM_ALERT_WINDOW',
        'android.permission.BIND_ACCESSIBILITY_SERVICE',
        'android.permission.BIND_DEVICE_ADMIN',
        'android.permission.REQUEST_INSTALL_PACKAGES',
        'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE',
    ]
    
    SUSPICIOUS_STRINGS = [
        (r'su\s+\-c', 'Root command'),
        (r'/system/bin/su', 'Root binary'),
        (r'Superuser', 'Root check'),
        (r'busybox', 'Busybox'),
        (r'DexClassLoader', 'Dynamic DEX loading'),
        (r'dalvik\.system\.DexClassLoader', 'Dynamic code'),
        (r'Runtime\.getRuntime\(\)\.exec', 'Runtime exec'),
        (r'ProcessBuilder', 'Process execution'),
        (r'android\.app\.admin', 'Device admin'),
        (r'AccessibilityService', 'Accessibility abuse'),
        (r'getInstalledPackages', 'App enumeration'),
        (r'PackageManager', 'Package manipulation'),
    ]
    
    def __init__(self):
        from ..tools.external_tool_runner import get_tool_runner
        self.tool_runner = get_tool_runner()
    
    def analyze(self, file_path: str) -> APKAnalysisResult:
        """Kapsamlı APK analizi."""
        logger.info(f"[APK] Analyzing: {Path(file_path).name}")
        result = APKAnalysisResult(file_path=file_path)
        
        # 1. aapt ile manifest analizi
        if self.tool_runner.is_available('aapt'):
            aapt_out = self.tool_runner.run_aapt(file_path)
            if aapt_out.success:
                self._parse_aapt_output(aapt_out.stdout, result)
                result.raw_outputs['aapt'] = aapt_out.stdout
                result.success = True
        
        # 2. ZIP olarak aç ve analiz et
        try:
            self._analyze_apk_contents(file_path, result)
        except Exception as e:
            logger.warning(f"[APK] Content analysis failed: {e}")
        
        # 3. Suspicious permission detection
        self._detect_suspicious_permissions(result)
        
        # 4. Calculate score
        result.threat_score = self._calculate_score(result)
        
        return result
    
    def _parse_aapt_output(self, output: str, result: APKAnalysisResult):
        """aapt dump badging çıktısını parse et."""
        for line in output.split('\n'):
            if line.startswith('package:'):
                # package: name='com.example' versionCode='1' versionName='1.0'
                name_match = re.search(r"name='([^']+)'", line)
                if name_match:
                    result.package_name = name_match.group(1)
                
                version_code = re.search(r"versionCode='([^']+)'", line)
                if version_code:
                    result.version_code = version_code.group(1)
                
                version_name = re.search(r"versionName='([^']+)'", line)
                if version_name:
                    result.version_name = version_name.group(1)
            
            elif line.startswith('sdkVersion:'):
                sdk = re.search(r"'(\d+)'", line)
                if sdk:
                    result.min_sdk = int(sdk.group(1))
            
            elif line.startswith('targetSdkVersion:'):
                sdk = re.search(r"'(\d+)'", line)
                if sdk:
                    result.target_sdk = int(sdk.group(1))
            
            elif line.startswith('uses-permission:'):
                perm = re.search(r"name='([^']+)'", line)
                if perm:
                    result.permissions.append(perm.group(1))
            
            elif 'activity' in line.lower() and "name='" in line:
                name = re.search(r"name='([^']+)'", line)
                if name:
                    result.activities.append(name.group(1))
            
            elif 'service' in line.lower() and "name='" in line:
                name = re.search(r"name='([^']+)'", line)
                if name:
                    result.services.append(name.group(1))
            
            elif 'receiver' in line.lower() and "name='" in line:
                name = re.search(r"name='([^']+)'", line)
                if name:
                    result.receivers.append(name.group(1))
    
    def _analyze_apk_contents(self, file_path: str, result: APKAnalysisResult):
        """APK içeriğini analiz et."""
        with zipfile.ZipFile(file_path, 'r') as apk:
            # Native libraries
            for name in apk.namelist():
                if name.startswith('lib/') and name.endswith('.so'):
                    result.native_libraries.append(name)
            
            # DEX files - extract strings
            for name in apk.namelist():
                if name.endswith('.dex'):
                    try:
                        dex_content = apk.read(name)
                        self._analyze_dex_strings(dex_content, result)
                    except:
                        pass
    
    def _analyze_dex_strings(self, content: bytes, result: APKAnalysisResult):
        """DEX dosyasından string'leri analiz et."""
        try:
            text = content.decode('utf-8', errors='ignore')
        except:
            text = str(content)
        
        # URLs
        url_pattern = re.compile(r'https?://[^\s<>"\']+')
        for url in url_pattern.findall(text):
            if len(url) > 10 and url not in result.urls:
                result.urls.append(url[:200])
        
        # IPs
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        for ip in ip_pattern.findall(text):
            if ip not in result.ips and not ip.startswith('0.'):
                result.ips.append(ip)
        
        # Suspicious patterns
        for pattern, desc in self.SUSPICIOUS_STRINGS:
            if re.search(pattern, text, re.I):
                if desc not in result.suspicious_strings:
                    result.suspicious_strings.append(desc)
    
    def _detect_suspicious_permissions(self, result: APKAnalysisResult):
        """Tehlikeli permission'ları tespit et."""
        for perm in result.permissions:
            if perm in self.DANGEROUS_PERMISSIONS:
                result.suspicious_permissions.append(perm)
        
        # Specific dangerous combinations
        perm_set = set(result.permissions)
        
        if 'android.permission.SEND_SMS' in perm_set and 'android.permission.RECEIVE_SMS' in perm_set:
            result.threat_indicators.append("SMS interception capability")
        
        if 'android.permission.BIND_ACCESSIBILITY_SERVICE' in perm_set:
            result.threat_indicators.append("Accessibility service abuse risk")
        
        if 'android.permission.BIND_DEVICE_ADMIN' in perm_set:
            result.threat_indicators.append("Device admin capability")
        
        if 'android.permission.REQUEST_INSTALL_PACKAGES' in perm_set:
            result.threat_indicators.append("Can install other apps")
    
    def _calculate_score(self, result: APKAnalysisResult) -> int:
        """Threat score hesapla."""
        score = 0
        
        # Suspicious permissions
        score += min(len(result.suspicious_permissions) * 5, 40)
        
        # Suspicious strings
        score += min(len(result.suspicious_strings) * 5, 30)
        
        # Threat indicators
        score += len(result.threat_indicators) * 10
        
        # URLs/IPs
        score += min(len(result.urls) + len(result.ips), 10)
        
        # Low target SDK (old API = less security)
        if result.target_sdk > 0 and result.target_sdk < 26:
            score += 10
        
        return min(score, 100)
