# bypass/waf_detector.py
"""
WAF detection from response headers.
"""

from enum import Enum
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)


class WAFType(Enum):
    UNKNOWN = "unknown"
    CLOUDFLARE = "cloudflare"
    SUCURI = "sucuri"
    STACKPATH = "stackpath"
    AWS_WAF = "aws_waf"
    AKAMAI = "akamai"
    FASTLY = "fastly"
    INCAPSULA = "incapsula"


class WAFDetector:
    """
    Detect WAF/CDN provider from HTTP response headers.
    """
    
    # Signature patterns for different WAFs
    SIGNATURES = {
        WAFType.CLOUDFLARE: {
            'headers': ['cf-ray', 'cf-cache-status', 'cf-request-id'],
            'server': ['cloudflare'],
        },
        WAFType.SUCURI: {
            'headers': ['x-sucuri-id', 'x-sucuri-cache'],
            'server': ['sucuri'],
        },
        WAFType.STACKPATH: {
            'headers': ['x-akamai-transformed', 'x-cdn'],
            'server': ['stackpath'],
        },
        WAFType.AWS_WAF: {
            'headers': ['x-amzn-requestid', 'x-amz-cf-id', 'x-amz-cf-pop'],
            'server': ['awselb'],
        },
        WAFType.AKAMAI: {
            'headers': ['x-akamai-transformed', 'x-akamai-request-id'],
            'server': ['akamai'],
        },
        WAFType.FASTLY: {
            'headers': ['x-served-by', 'x-cache', 'x-cache-hits'],
            'server': ['fastly'],
        },
        WAFType.INCAPSULA: {
            'headers': ['x-iinfo', 'x-cdn'],
            'server': ['incapsula'],
        },
    }
    
    @classmethod
    def detect(cls, headers: Dict[str, str]) -> WAFType:
        """
        Detect WAF type from response headers.
        
        Args:
            headers: HTTP response headers (case-insensitive)
            
        Returns:
            Detected WAFType
        """
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        for waf_type, sig in cls.SIGNATURES.items():
            # Check header signatures
            for sig_header in sig.get('headers', []):
                if sig_header in headers_lower:
                    logger.debug(f"Detected {waf_type.value} by header: {sig_header}")
                    return waf_type
            
            # Check server header
            server = headers_lower.get('server', '')
            for sig_server in sig.get('server', []):
                if sig_server in server:
                    logger.debug(f"Detected {waf_type.value} by server: {server}")
                    return waf_type
        
        return WAFType.UNKNOWN
    
    @classmethod
    def get_bypass_strategy(cls, waf_type: WAFType) -> Dict[str, Any]:
        """
        Get recommended bypass strategy for detected WAF.
        
        Args:
            waf_type: Detected WAF type
            
        Returns:
            Strategy configuration dict
        """
        strategies = {
            WAFType.CLOUDFLARE: {
                'requires_cf_clearance': True,
                'requires_ja3_spoof': True,
                'preferred_headers': ['cf-connecting-ip', 'cf-ray', 'x-forwarded-for'],
                'rate_limit_multiplier': 0.5,
            },
            WAFType.SUCURI: {
                'requires_cf_clearance': False,
                'requires_ja3_spoof': True,
                'preferred_headers': ['x-forwarded-for', 'x-real-ip'],
                'rate_limit_multiplier': 0.7,
            },
            WAFType.AWS_WAF: {
                'requires_cf_clearance': False,
                'requires_ja3_spoof': True,
                'preferred_headers': [],
                'rate_limit_multiplier': 0.8,
            },
            WAFType.AKAMAI: {
                'requires_cf_clearance': False,
                'requires_ja3_spoof': True,
                'preferred_headers': ['x-forwarded-for', 'x-akamai-request-id'],
                'rate_limit_multiplier': 0.6,
            },
            WAFType.UNKNOWN: {
                'requires_cf_clearance': False,
                'requires_ja3_spoof': False,
                'preferred_headers': [],
                'rate_limit_multiplier': 1.0,
            },
        }
        
        return strategies.get(waf_type, strategies[WAFType.UNKNOWN])