"""
Author: Ugur Ates
Tool-Based Scoring - Harici araç çıktılarına dayalı skorlama.

Her araç kendi threat score'unu üretir:
- capa: Capability count * severity
- FLOSS: Obfuscated string count + IOC count
- DIE: Packer/protector detection
- olevba: Macro risk indicators
- pdfid: Suspicious keyword count
- binwalk: High entropy regions

Final score = weighted average of all tool scores
"""

import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)
@dataclass
class ToolScore:
    """Tek bir araçtan gelen skor."""
    tool_name: str
    score: int
    weight: float
    contributing_factors: List[str] = field(default_factory=list)
    raw_data: Optional[Dict] = None
@dataclass
class ScoringResult:
    """Combined scoring result."""
    combined_score: int
    verdict: str
    confidence: float
    tool_scores: Dict[str, ToolScore] = field(default_factory=dict)
    contributing_factors: List[str] = field(default_factory=list)
    breakdown: Dict[str, int] = field(default_factory=dict)
class ToolBasedScoring:
    """Araç çıktılarına dayalı akıllı skorlama."""
    
    # Araç ağırlıkları - file analysis için
    FILE_TOOL_WEIGHTS = {
        'capa': 0.25,           # Capability detection (en önemli)
        'floss': 0.15,          # Obfuscated strings
        'diec': 0.12,           # Packer detection
        'pe_analysis': 0.15,    # PE header analysis
        'static_analysis': 0.10, # Generic static analysis
        'binwalk': 0.08,        # Embedded files
        'yara': 0.15,           # YARA matches
        'threat_intel': 0.20,   # Hash reputation
        'strings': 0.10,        # String analysis
    }
    
    # Araç ağırlıkları - Office analysis için
    OFFICE_TOOL_WEIGHTS = {
        'olevba': 0.30,         # VBA macro analysis
        'mraptor': 0.25,        # Malicious macro detection
        'oleid': 0.10,          # OLE indicators
        'oleobj': 0.10,         # Embedded objects
        'yara': 0.10,           # YARA matches
        'threat_intel': 0.15,   # Hash reputation
    }
    
    # Araç ağırlıkları - PDF analysis için
    PDF_TOOL_WEIGHTS = {
        'pdfid': 0.35,          # PDF structure
        'pdf_parser': 0.25,     # Object analysis
        'yara': 0.15,           # YARA matches
        'threat_intel': 0.15,   # Hash reputation
        'strings': 0.10,        # String analysis
    }
    
    # Araç ağırlıkları - Email analysis için
    EMAIL_TOOL_WEIGHTS = {
        'forensics': 0.20,      # Email forensics
        'authentication': 0.15, # SPF/DKIM/DMARC
        'phishing': 0.25,       # Phishing detection
        'attachments': 0.25,    # Attachment analysis
        'ioc_analysis': 0.15,   # IOC reputation
    }
    
    # Verdict thresholds
    VERDICT_THRESHOLDS = {
        'MALICIOUS': 70,
        'SUSPICIOUS': 40,
        'CLEAN': 0
    }
    
    @staticmethod
    def calculate_combined_score(tool_scores: Dict[str, int], 
                                  weights: Dict[str, float] = None) -> int:
        """
        Tüm araç skorlarını birleştir.
        
        Args:
            tool_scores: {tool_name: score}
            weights: Custom weights (optional)
        
        Returns:
            Combined threat score (0-100)
        """
        if not tool_scores:
            return 0
        
        weights = weights or ToolBasedScoring.FILE_TOOL_WEIGHTS
        
        total_weight = 0
        weighted_sum = 0
        
        for tool, score in tool_scores.items():
            weight = weights.get(tool, 0.05)  # Default low weight for unknown tools
            weighted_sum += score * weight
            total_weight += weight
        
        if total_weight == 0:
            return 0
        
        # Normalize and cap at 100
        return min(int(weighted_sum / total_weight), 100)
    
    @staticmethod
    def determine_verdict(score: int) -> str:
        """Score'dan verdict belirle."""
        if score >= ToolBasedScoring.VERDICT_THRESHOLDS['MALICIOUS']:
            return 'MALICIOUS'
        elif score >= ToolBasedScoring.VERDICT_THRESHOLDS['SUSPICIOUS']:
            return 'SUSPICIOUS'
        else:
            return 'CLEAN'
    
    @staticmethod
    def calculate_confidence(tool_scores: Dict[str, int], weights: Dict[str, float]) -> float:
        """
        Analiz güvenilirliğini hesapla.
        
        Confidence factors:
        - Number of tools that provided scores
        - Coverage of high-weight tools
        - Consistency of scores
        """
        if not tool_scores:
            return 0.0
        
        total_possible_weight = sum(weights.values())
        covered_weight = sum(weights.get(tool, 0) for tool in tool_scores.keys())
        
        # Base confidence on tool coverage
        coverage_confidence = covered_weight / total_possible_weight if total_possible_weight > 0 else 0
        
        # Bonus for having multiple tools agree
        scores = list(tool_scores.values())
        if len(scores) >= 3:
            # Calculate score variance
            avg_score = sum(scores) / len(scores)
            variance = sum((s - avg_score) ** 2 for s in scores) / len(scores)
            
            # Lower variance = higher confidence (scores agree)
            consistency_factor = max(0, 1 - (variance / 2500))  # Normalized
        else:
            consistency_factor = 0.5
        
        # Combined confidence
        confidence = (coverage_confidence * 0.7 + consistency_factor * 0.3)
        
        return min(confidence, 1.0)
    
    @staticmethod
    def calculate_file_score(analysis_result: Dict) -> ScoringResult:
        """
        File analiz sonucundan combined score hesapla.
        
        Args:
            analysis_result: Full analysis result dictionary
            
        Returns:
            ScoringResult with combined score, verdict, and breakdown
        """
        tool_scores: Dict[str, ToolScore] = {}
        contributing_factors: List[str] = []
        
        # Extract capa score - only if capa actually ran
        if 'capabilities' in analysis_result:
            cap = analysis_result['capabilities']
            # Only include if capa actually ran (has success flag or capabilities)
            if cap.get('success') or cap.get('capabilities'):
                score = cap.get('threat_score', 0)
                factors = []
                
                if cap.get('capabilities'):
                    factors.append(f"{len(cap['capabilities'])} capabilities detected")
                if cap.get('attack_techniques'):
                    factors.append(f"{len(cap['attack_techniques'])} ATT&CK techniques")
                
                tool_scores['capa'] = ToolScore(
                    tool_name='capa',
                    score=score,
                    weight=ToolBasedScoring.FILE_TOOL_WEIGHTS['capa'],
                    contributing_factors=factors
                )
                
                if score > 50:
                    contributing_factors.append(f"capa: High capability score ({score})")
        
        # Extract FLOSS score - only if FLOSS found something
        if 'strings' in analysis_result:
            strings = analysis_result['strings']
            
            decoded = strings.get('decoded_count', strings.get('decoded_strings', 0))
            if isinstance(decoded, list):
                decoded = len(decoded)
            
            # Only include if FLOSS found decoded strings or has threat_score
            if decoded > 0 or strings.get('threat_score', 0) > 0:
                score = strings.get('threat_score', 0)
                factors = []
                
                if decoded > 0:
                    factors.append(f"{decoded} decoded/obfuscated strings")
                if strings.get('urls'):
                    factors.append(f"{len(strings['urls'])} URLs extracted")
                if strings.get('suspicious_strings'):
                    factors.append(f"{len(strings['suspicious_strings'])} suspicious patterns")
                
                tool_scores['floss'] = ToolScore(
                    tool_name='floss',
                    score=score,
                    weight=ToolBasedScoring.FILE_TOOL_WEIGHTS['floss'],
                    contributing_factors=factors
                )
                
                contributing_factors.append(f"FLOSS: {decoded} decoded strings (evasion)")
        
        # Extract DIE (packer detection) score - only if found packers/protectors
        if 'packer_detection' in analysis_result:
            packer = analysis_result['packer_detection']
            
            # Only include if DIE found something
            if packer.get('packers') or packer.get('protectors') or packer.get('compilers'):
                score = 0
                factors = []
                
                if packer.get('packers'):
                    score = 50
                    factors.append(f"Packed: {', '.join(packer['packers'][:3])}")
                    contributing_factors.append(f"DIE: Packed with {packer['packers'][0]}")
                
                if packer.get('protectors'):
                    score = 70
                    factors.append(f"Protected: {', '.join(packer['protectors'][:3])}")
                    contributing_factors.append(f"DIE: Protected with {packer['protectors'][0]}")
                
                if packer.get('compilers'):
                    factors.append(f"Compiler: {', '.join(packer['compilers'][:2])}")
                
                tool_scores['diec'] = ToolScore(
                    tool_name='diec',
                    score=score,
                    weight=ToolBasedScoring.FILE_TOOL_WEIGHTS['diec'],
                    contributing_factors=factors
                )
        
        # Extract PE analysis score
        if 'pe_analysis' in analysis_result:
            pe = analysis_result['pe_analysis']
            score = pe.get('threat_score', 0)
            factors = []
            
            if pe.get('suspicious_imports'):
                factors.append(f"{len(pe['suspicious_imports'])} suspicious imports")
            if pe.get('high_entropy_sections'):
                factors.append(f"High entropy sections detected")
            if pe.get('anomalies'):
                factors.append(f"{len(pe['anomalies'])} anomalies")
            
            tool_scores['pe_analysis'] = ToolScore(
                tool_name='pe_analysis',
                score=score,
                weight=ToolBasedScoring.FILE_TOOL_WEIGHTS['pe_analysis'],
                contributing_factors=factors
            )
        
        # Extract static analysis score
        if 'static_analysis' in analysis_result:
            static = analysis_result['static_analysis']
            score = static.get('threat_score', 0)
            factors = []
            
          
            # Script dosyalarının threat_score'u genellikle çok anlamlıdır
            is_script = static.get('file_type') == 'Script' or static.get('script_type')
            
            if is_script and score > 0:
                # Script için threat_score'u direkt büyük faktör olarak kullan
                tool_scores['script_analysis'] = ToolScore(
                    tool_name='script_analysis',
                    score=score,
                    weight=0.40,  # Yüksek ağırlık - script analysis güvenilir
                    contributing_factors=[f"Script threat score: {score}/100"]
                )
                contributing_factors.append(f"Script analysis: {score}/100 threat score")
            
            # Handle both suspicious_indicators and threat_indicators
            if static.get('suspicious_indicators'):
                factors.extend(static['suspicious_indicators'][:5])
            if static.get('threat_indicators'):
                factors.extend(static['threat_indicators'][:5])
                # Add to contributing factors if high score
                if score >= 40:
                    contributing_factors.append(f"Script analysis: {static['threat_indicators'][0]}")
            
            # Handle script-specific patterns
            if static.get('suspicious_patterns'):
                patterns = static['suspicious_patterns']
                if patterns.get('total_matches', 0) > 0:
                    score = max(score, min(patterns['total_matches'] * 5, 80))
                    high_risk_cats = ['execution', 'download', 'credential', 'evasion']
                    for cat, data in patterns.get('categories', {}).items():
                        if isinstance(data, dict) and data.get('count', 0) > 0:
                            factors.append(f"{cat}: {data['count']} patterns")
                            # Add high-risk categories to contributing factors
                            if cat in high_risk_cats and data.get('count', 0) > 0:
                                contributing_factors.append(f"Script {cat}: {data['count']} patterns")
            
            # Handle obfuscation
            if static.get('obfuscation', {}).get('likely_obfuscated'):
                obf = static['obfuscation']
                score = max(score, obf.get('confidence', 0))
                if obf.get('techniques'):
                    factors.append(f"Obfuscation: {', '.join(obf['techniques'][:3])}")
                    contributing_factors.append(f"Obfuscated script: {obf['techniques'][0]}")
            
            # Only add if we have score or factors
            if score > 0 or factors:
                tool_scores['static_analysis'] = ToolScore(
                    tool_name='static_analysis',
                    score=score,
                    weight=ToolBasedScoring.FILE_TOOL_WEIGHTS['static_analysis'],
                    contributing_factors=factors
                )
        
        # Extract binwalk score
        if 'embedded_files' in analysis_result:
            embedded = analysis_result['embedded_files']
            score = 0
            factors = []
            
            if embedded.get('embedded_files'):
                score = min(len(embedded['embedded_files']) * 5, 30)
                factors.append(f"{len(embedded['embedded_files'])} embedded items")
            
            if embedded.get('high_entropy_regions'):
                score += min(len(embedded['high_entropy_regions']) * 10, 30)
                factors.append(f"High entropy regions detected")
                contributing_factors.append("binwalk: High entropy (encrypted/packed)")
            
            tool_scores['binwalk'] = ToolScore(
                tool_name='binwalk',
                score=score,
                weight=ToolBasedScoring.FILE_TOOL_WEIGHTS['binwalk'],
                contributing_factors=factors
            )
        
        # Extract YARA score - only if there are matches
        if 'yara_analysis' in analysis_result:
            yara = analysis_result['yara_analysis']
            matches = yara.get('matches', [])
            
            # Only include if there are YARA matches
            if matches:
                score = min(len(matches) * 15, 80)
                factors = [f"{len(matches)} YARA matches"]
                contributing_factors.append(f"YARA: {len(matches)} rule matches")
                
                interpretation = yara.get('interpretation', {})
                if interpretation.get('malware_families'):
                    score = min(score + 20, 100)
                    factors.append(f"Families: {', '.join(interpretation['malware_families'][:3])}")
                
                tool_scores['yara'] = ToolScore(
                    tool_name='yara',
                    score=score,
                    weight=ToolBasedScoring.FILE_TOOL_WEIGHTS['yara'],
                    contributing_factors=factors
                )
        # Also handle direct yara_matches (from malware_analyzer)
        elif 'yara_matches' in analysis_result:
            matches = analysis_result['yara_matches']
            if isinstance(matches, list) and matches:  # Only if non-empty
                score = min(len(matches) * 15, 80)
                factors = [f"{len(matches)} YARA matches"]
                contributing_factors.append(f"YARA: {len(matches)} rule matches")
                
                tool_scores['yara'] = ToolScore(
                    tool_name='yara',
                    score=score,
                    weight=ToolBasedScoring.FILE_TOOL_WEIGHTS['yara'],
                    contributing_factors=factors
                )
        
        # Extract threat intel score - only if flagged
        if 'threat_intel' in analysis_result:
            ti = analysis_result['threat_intel']
            score = ti.get('score', ti.get('threat_score', 0))
            
            # Only include if there's a score or sources flagged
            if score > 0 or ti.get('sources_flagged', 0) > 0:
                factors = []
                if ti.get('sources_flagged', 0) > 0:
                    factors.append(f"{ti['sources_flagged']}/{ti.get('sources_checked', 0)} sources flagged")
                    contributing_factors.append(f"Threat Intel: {ti['sources_flagged']} sources flagged")
                
                tool_scores['threat_intel'] = ToolScore(
                    tool_name='threat_intel',
                    score=score,
                    weight=ToolBasedScoring.FILE_TOOL_WEIGHTS['threat_intel'],
                    contributing_factors=factors
                )
        # Also handle direct hash_score (from malware_analyzer)
        elif 'hash_score' in analysis_result:
            score = analysis_result['hash_score']
            if isinstance(score, (int, float)) and score > 0:
                factors = [f"Hash reputation score: {score}"]
                contributing_factors.append(f"Hash reputation: {score}/100")
                
                tool_scores['threat_intel'] = ToolScore(
                    tool_name='threat_intel',
                    score=int(score),
                    weight=ToolBasedScoring.FILE_TOOL_WEIGHTS['threat_intel'],
                    contributing_factors=factors
                )
        
        # Calculate combined score
        score_dict = {name: ts.score for name, ts in tool_scores.items()}
        combined = ToolBasedScoring.calculate_combined_score(
            score_dict, ToolBasedScoring.FILE_TOOL_WEIGHTS
        )
        
        # Determine verdict
        verdict = ToolBasedScoring.determine_verdict(combined)
        
        # Calculate confidence
        confidence = ToolBasedScoring.calculate_confidence(
            score_dict, ToolBasedScoring.FILE_TOOL_WEIGHTS
        )
        
        # Create breakdown
        breakdown = {name: ts.score for name, ts in tool_scores.items()}
        
        return ScoringResult(
            combined_score=combined,
            verdict=verdict,
            confidence=confidence,
            tool_scores=tool_scores,
            contributing_factors=contributing_factors,
            breakdown=breakdown
        )
    
    @staticmethod
    def calculate_office_score(analysis_result: Dict) -> ScoringResult:
        """Office document analiz sonucundan score hesapla."""
        tool_scores: Dict[str, ToolScore] = {}
        contributing_factors: List[str] = []
        
        # VBA analysis (olevba)
        if 'vba_analysis' in analysis_result:
            vba = analysis_result['vba_analysis']
            score = 0
            factors = []
            
            if vba.get('has_macros'):
                score = 20
                factors.append("Contains VBA macros")
            
            if vba.get('auto_execute'):
                score += 30
                factors.append(f"Auto-execute: {', '.join(vba['auto_execute'][:3])}")
                contributing_factors.append("Auto-execute macros detected")
            
            if vba.get('suspicious_keywords'):
                score += min(len(vba['suspicious_keywords']) * 5, 30)
                factors.append(f"{len(vba['suspicious_keywords'])} suspicious keywords")
            
            tool_scores['olevba'] = ToolScore(
                tool_name='olevba',
                score=min(score, 100),
                weight=ToolBasedScoring.OFFICE_TOOL_WEIGHTS['olevba'],
                contributing_factors=factors
            )
        
        # mraptor verdict
        if 'macro_verdict' in analysis_result:
            verdict = analysis_result['macro_verdict']
            score = 0
            factors = []
            
            if verdict.get('is_suspicious'):
                score = 70
                factors.append(f"Suspicious macro (flags: {verdict.get('flags', '')})")
                contributing_factors.append("mraptor: Suspicious macro behavior")
            
            if verdict.get('auto_exec') and verdict.get('execute'):
                score = 90
                factors.append("Auto-exec + Execute capabilities")
                contributing_factors.append("mraptor: AutoExec + Execute (high risk)")
            
            tool_scores['mraptor'] = ToolScore(
                tool_name='mraptor',
                score=score,
                weight=ToolBasedScoring.OFFICE_TOOL_WEIGHTS['mraptor'],
                contributing_factors=factors
            )
        
        # OLE indicators
        if 'ole_indicators' in analysis_result:
            ole = analysis_result['ole_indicators']
            score = 0
            factors = []
            
            if ole.get('has_vba'):
                score += 15
            if ole.get('has_xlm'):
                score += 25
                factors.append("XLM macros (Excel 4.0)")
            if ole.get('has_flash'):
                score += 30
                factors.append("Embedded Flash")
            if ole.get('has_external_links'):
                score += 20
                factors.append("External links")
            
            tool_scores['oleid'] = ToolScore(
                tool_name='oleid',
                score=min(score, 100),
                weight=ToolBasedScoring.OFFICE_TOOL_WEIGHTS['oleid'],
                contributing_factors=factors
            )
        
        # Calculate combined
        score_dict = {name: ts.score for name, ts in tool_scores.items()}
        combined = ToolBasedScoring.calculate_combined_score(
            score_dict, ToolBasedScoring.OFFICE_TOOL_WEIGHTS
        )
        
        verdict = ToolBasedScoring.determine_verdict(combined)
        confidence = ToolBasedScoring.calculate_confidence(
            score_dict, ToolBasedScoring.OFFICE_TOOL_WEIGHTS
        )
        
        return ScoringResult(
            combined_score=combined,
            verdict=verdict,
            confidence=confidence,
            tool_scores=tool_scores,
            contributing_factors=contributing_factors,
            breakdown={name: ts.score for name, ts in tool_scores.items()}
        )
    
    @staticmethod
    def calculate_pdf_score(analysis_result: Dict) -> ScoringResult:
        """PDF analiz sonucundan score hesapla."""
        tool_scores: Dict[str, ToolScore] = {}
        contributing_factors: List[str] = []
        
        # PDF structure (pdfid)
        if 'pdf_structure' in analysis_result:
            struct = analysis_result['pdf_structure']
            score = 0
            factors = []
            
            js_count = struct.get('javascript', 0) + struct.get('js', 0)
            if js_count > 0:
                score += 30
                factors.append(f"JavaScript: {js_count}")
                contributing_factors.append(f"PDF contains JavaScript ({js_count})")
            
            if struct.get('openaction', 0) > 0 or struct.get('aa', 0) > 0:
                score += 20
                factors.append("Auto-action present")
            
            if struct.get('launch', 0) > 0:
                score += 40
                factors.append("Launch action (code execution)")
                contributing_factors.append("PDF Launch action detected")
            
            if struct.get('embeddedfile', 0) > 0:
                score += 20
                factors.append(f"Embedded files: {struct['embeddedfile']}")
            
            if struct.get('obfuscated', 0) > 0:
                score += 25
                factors.append("Obfuscated content")
            
            tool_scores['pdfid'] = ToolScore(
                tool_name='pdfid',
                score=min(score, 100),
                weight=ToolBasedScoring.PDF_TOOL_WEIGHTS['pdfid'],
                contributing_factors=factors
            )
        
        # Calculate combined
        score_dict = {name: ts.score for name, ts in tool_scores.items()}
        combined = ToolBasedScoring.calculate_combined_score(
            score_dict, ToolBasedScoring.PDF_TOOL_WEIGHTS
        )
        
        verdict = ToolBasedScoring.determine_verdict(combined)
        confidence = ToolBasedScoring.calculate_confidence(
            score_dict, ToolBasedScoring.PDF_TOOL_WEIGHTS
        )
        
        return ScoringResult(
            combined_score=combined,
            verdict=verdict,
            confidence=confidence,
            tool_scores=tool_scores,
            contributing_factors=contributing_factors,
            breakdown={name: ts.score for name, ts in tool_scores.items()}
        )
    
    @staticmethod
    def calculate_email_score(analysis_result: Dict) -> ScoringResult:
        """Email analiz sonucundan combined score hesapla."""
        tool_scores: Dict[str, ToolScore] = {}
        contributing_factors: List[str] = []
        
        # Forensics score
        if 'forensics' in analysis_result:
            forensics = analysis_result['forensics']
            score = forensics.get('risk_score', forensics.get('forensics_score', 0))
            factors = []
            
            if forensics.get('risk_indicators'):
                factors.extend(forensics['risk_indicators'][:5])
            
            tool_scores['forensics'] = ToolScore(
                tool_name='forensics',
                score=score,
                weight=ToolBasedScoring.EMAIL_TOOL_WEIGHTS['forensics'],
                contributing_factors=factors
            )
            
            if score > 50:
                contributing_factors.append(f"Forensics score: {score}/100")
        
        # Authentication score
        auth = analysis_result.get('email_data', {})
        auth_score = 0
        auth_factors = []
        
        if str(auth.get('spf', '')).lower() != 'pass':
            auth_score += 25
            auth_factors.append("SPF failed")
        if str(auth.get('dkim', '')).lower() != 'pass':
            auth_score += 25
            auth_factors.append("DKIM failed")
        if str(auth.get('dmarc', '')).lower() != 'pass':
            auth_score += 25
            auth_factors.append("DMARC failed")
        
        if auth_score > 0:
            tool_scores['authentication'] = ToolScore(
                tool_name='authentication',
                score=auth_score,
                weight=ToolBasedScoring.EMAIL_TOOL_WEIGHTS['authentication'],
                contributing_factors=auth_factors
            )
            contributing_factors.append(f"Auth failures: {', '.join(auth_factors)}")
        
        # Phishing indicators
        if 'advanced_analysis' in analysis_result:
            adv = analysis_result['advanced_analysis']
            phish_score = 0
            phish_factors = []
            
            if adv.get('lookalike_domains'):
                phish_score += 40
                phish_factors.append(f"Lookalike domains: {len(adv['lookalike_domains'])}")
            if adv.get('link_mismatches'):
                phish_score += 30
                phish_factors.append(f"Link-text mismatches: {len(adv['link_mismatches'])}")
            if adv.get('header_analysis', {}).get('anomalies'):
                phish_score += 20
                phish_factors.append("Header anomalies")
            
            if phish_score > 0:
                tool_scores['phishing'] = ToolScore(
                    tool_name='phishing',
                    score=phish_score,
                    weight=ToolBasedScoring.EMAIL_TOOL_WEIGHTS['phishing'],
                    contributing_factors=phish_factors
                )
                contributing_factors.extend(phish_factors[:3])
        
        # Attachment analysis
        if 'attachment_analysis' in analysis_result:
            max_att_score = 0
            att_factors = []
            
            for att in analysis_result['attachment_analysis']:
                att_score = att.get('threat_score', 0)
                if att_score > max_att_score:
                    max_att_score = att_score
                    att_factors = [f"{att.get('filename', 'attachment')}: score {att_score}"]
            
            if max_att_score > 0:
                tool_scores['attachments'] = ToolScore(
                    tool_name='attachments',
                    score=max_att_score,
                    weight=ToolBasedScoring.EMAIL_TOOL_WEIGHTS['attachments'],
                    contributing_factors=att_factors
                )
                if max_att_score > 50:
                    contributing_factors.append(f"Malicious attachment detected")
        
        # Calculate combined
        score_dict = {name: ts.score for name, ts in tool_scores.items()}
        combined = ToolBasedScoring.calculate_combined_score(
            score_dict, ToolBasedScoring.EMAIL_TOOL_WEIGHTS
        )
        
        verdict = ToolBasedScoring.determine_verdict(combined)
        if combined >= 60:
            verdict = 'PHISHING'
        
        confidence = ToolBasedScoring.calculate_confidence(
            score_dict, ToolBasedScoring.EMAIL_TOOL_WEIGHTS
        )
        
        return ScoringResult(
            combined_score=combined,
            verdict=verdict,
            confidence=confidence,
            tool_scores=tool_scores,
            contributing_factors=contributing_factors,
            breakdown={name: ts.score for name, ts in tool_scores.items()}
        )
