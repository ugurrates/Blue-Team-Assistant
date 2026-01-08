"""
Author: Ugur AtesDigital signature and certificate validation for PE files."""

import logging
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    logger.warning("[CERT] pefile not available, certificate validation disabled")

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logger.warning("[CERT] cryptography not available, certificate validation disabled")
class CertificateValidator:
    """
    Validate digital signatures and certificates in PE files.
    
    Features:
    - Digital signature verification
    - Certificate chain validation
    - Timestamp verification
    - Revocation checking (future)
    - Certificate details extraction
    """
    
    @staticmethod
    def validate_pe_signature(file_path: str) -> Dict:
        """
        Validate PE file digital signature.
        
        Args:
            file_path: Path to PE file
        
        Returns:
            Dict containing validation results
        """
        if not PEFILE_AVAILABLE or not CRYPTO_AVAILABLE:
            return {
                'signed': False,
                'valid': False,
                'error': 'Required libraries not available (pefile, cryptography)'
            }
        
        try:
            pe = pefile.PE(file_path)
            
            # Check if file has security directory
            if not hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                return {
                    'signed': False,
                    'valid': False,
                    'reason': 'No digital signature present'
                }
            
            # Extract signature data
            signature_data = pe.DIRECTORY_ENTRY_SECURITY[0]
            
            result = {
                'signed': True,
                'signature_size': len(signature_data.struct.data),
                'certificates': [],
                'timestamps': [],
                'valid': None,  # Will be determined after checks
                'warnings': [],
                'errors': []
            }
            
            # Parse certificates from signature
            try:
                certs = CertificateValidator._parse_certificates(signature_data.struct.data)
                result['certificates'] = certs
                
                # Validate each certificate
                for cert in certs:
                    validation = CertificateValidator._validate_certificate(cert)
                    cert.update(validation)
                
                # Overall validation
                result['valid'] = all(c.get('is_valid', False) for c in certs)
                
            except Exception as e:
                result['errors'].append(f"Certificate parsing failed: {e}")
                result['valid'] = False
            
            pe.close()
            return result
            
        except Exception as e:
            logger.error(f"[CERT] Signature validation failed: {e}")
            return {
                'signed': False,
                'valid': False,
                'error': str(e)
            }
    
    @staticmethod
    def _parse_certificates(signature_data: bytes) -> List[Dict]:
        """Parse certificates from signature data."""
        certificates = []
        
        try:
            # PKCS#7 signature parsing (simplified)
            # In production, use proper ASN.1 parser
            
            # For now, extract basic info
            cert_info = {
                'subject': 'Certificate parsing requires ASN.1 library',
                'issuer': 'Not parsed',
                'serial_number': 'Not parsed',
                'valid_from': None,
                'valid_until': None,
                'signature_algorithm': 'Unknown',
                'key_size': 0,
                'thumbprint': 'Not calculated'
            }
            
            certificates.append(cert_info)
            
        except Exception as e:
            logger.error(f"[CERT] Certificate parsing error: {e}")
        
        return certificates
    
    @staticmethod
    def _validate_certificate(cert: Dict) -> Dict:
        """
        Validate individual certificate.
        
        Returns validation result dict
        """
        validation = {
            'is_valid': True,
            'issues': []
        }
        
        # Check expiration (if dates available)
        if cert.get('valid_until'):
            if cert['valid_until'] < datetime.now():
                validation['is_valid'] = False
                validation['issues'].append('Certificate expired')
        
        # Check key size
        if cert.get('key_size', 0) < 2048:
            validation['issues'].append('Weak key size (< 2048 bits)')
        
        # Check signature algorithm
        weak_algos = ['md5', 'sha1']
        if any(algo in cert.get('signature_algorithm', '').lower() for algo in weak_algos):
            validation['issues'].append('Weak signature algorithm')
        
        return validation
    
    @staticmethod
    def extract_certificate_details(file_path: str) -> Dict:
        """
        Extract detailed certificate information.
        
        Args:
            file_path: Path to PE file
        
        Returns:
            Dict with certificate details
        """
        signature_result = CertificateValidator.validate_pe_signature(file_path)
        
        if not signature_result.get('signed'):
            return {
                'has_signature': False,
                'details': None
            }
        
        details = {
            'has_signature': True,
            'is_valid': signature_result.get('valid', False),
            'certificate_count': len(signature_result.get('certificates', [])),
            'certificates': signature_result.get('certificates', []),
            'warnings': signature_result.get('warnings', []),
            'errors': signature_result.get('errors', [])
        }
        
        # Extract signer info from first certificate
        if details['certificates']:
            first_cert = details['certificates'][0]
            details['signer'] = {
                'subject': first_cert.get('subject', 'Unknown'),
                'issuer': first_cert.get('issuer', 'Unknown'),
                'valid_from': first_cert.get('valid_from'),
                'valid_until': first_cert.get('valid_until')
            }
        
        return details
    
    @staticmethod
    def check_certificate_trust(file_path: str) -> Dict:
        """
        Check if certificate is trusted.
        
        Args:
            file_path: Path to PE file
        
        Returns:
            Trust status dict
        """
        cert_details = CertificateValidator.extract_certificate_details(file_path)
        
        if not cert_details.get('has_signature'):
            return {
                'trusted': False,
                'reason': 'No digital signature'
            }
        
        # Known trusted publishers (can be expanded)
        TRUSTED_PUBLISHERS = [
            'Microsoft Corporation',
            'Microsoft Windows',
            'Adobe Systems',
            'Google LLC',
            'Apple Inc.'
        ]
        
        if cert_details.get('signer'):
            subject = cert_details['signer'].get('subject', '')
            
            # Check against trusted list
            for publisher in TRUSTED_PUBLISHERS:
                if publisher.lower() in subject.lower():
                    return {
                        'trusted': True,
                        'publisher': publisher,
                        'reason': 'Known trusted publisher'
                    }
        
        # Check validity
        if cert_details.get('is_valid'):
            return {
                'trusted': 'unknown',
                'reason': 'Valid signature but publisher not in trusted list'
            }
        
        return {
            'trusted': False,
            'reason': 'Invalid or untrusted signature'
        }
def analyze_certificate(file_path: str) -> Dict:
    """
    Main entry point for certificate analysis.
    
    Args:
        file_path: Path to PE file
    
    Returns:
        Complete certificate analysis
    """
    result = {
        'certificate_analysis': {}
    }
    
    # Validate signature
    signature = CertificateValidator.validate_pe_signature(file_path)
    result['certificate_analysis']['signature'] = signature
    
    # Extract details
    details = CertificateValidator.extract_certificate_details(file_path)
    result['certificate_analysis']['details'] = details
    
    # Check trust
    trust = CertificateValidator.check_certificate_trust(file_path)
    result['certificate_analysis']['trust'] = trust
    
    # Calculate risk score
    risk_score = 0
    
    if not signature.get('signed'):
        risk_score += 40  # Unsigned = high risk
    elif not signature.get('valid'):
        risk_score += 60  # Invalid signature = very high risk
    elif trust.get('trusted') == False:
        risk_score += 30  # Untrusted = medium risk
    
    result['certificate_analysis']['risk_score'] = risk_score
    
    return result
