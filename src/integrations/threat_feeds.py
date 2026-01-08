"""
Author: Ugur AtesFree threat feed integrations."""

import aiohttp
from typing import Dict, List
import logging

logger = logging.getLogger(__name__)
class ThreatFeeds:
    """
    Free threat feed aggregator.
    
    Sources:
    - USOM (Turkish national CERT)
    - SSL Blacklist
    - Public C2 trackers
    """
    
    def __init__(self, config: Dict):
        """Initialize threat feeds."""
        self.config = config
        self.timeout = aiohttp.ClientTimeout(total=30)
    
    async def check_usom(self, ioc: str) -> Dict:
        """
        Check IOC against USOM threat feed.
        
        Args:
            ioc: IOC to check
        
        Returns:
            USOM check result
        """
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                # USOM publishes various threat lists
                urls = [
                    'https://www.usom.gov.tr/url-list.txt',
                    'https://www.usom.gov.tr/ip-list.txt'
                ]
                
                for url in urls:
                    try:
                        async with session.get(url) as response:
                            if response.status == 200:
                                text = await response.text()
                                if ioc in text:
                                    return {
                                        'status': '✓',
                                        'source': 'USOM',
                                        'score': 85
                                    }
                    except:
                        continue
                
                return {'status': '✗', 'message': 'Not found'}
        
        except Exception as e:
            logger.error(f"[USOM] Error: {e}")
            return {'status': '⚠', 'error': str(e)}
    
    async def check_ssl_blacklist(self, hash_value: str) -> Dict:
        """
        Check SSL certificate hash against blacklist.
        
        Args:
            hash_value: SSL cert hash
        
        Returns:
            SSL blacklist result
        """
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get('https://sslbl.abuse.ch/blacklist/sslblacklist.csv') as response:
                    if response.status == 200:
                        text = await response.text()
                        if hash_value in text:
                            return {
                                'status': '✓',
                                'source': 'SSL Blacklist',
                                'score': 90
                            }
                        else:
                            return {'status': '✗', 'message': 'Not found'}
                    else:
                        return {'status': '⚠', 'error': f'HTTP {response.status}'}
        
        except Exception as e:
            logger.error(f"[SSLBlacklist] Error: {e}")
            return {'status': '⚠', 'error': str(e)}
