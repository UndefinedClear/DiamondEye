# bypass/__init__.py
from bypass.header_generator import HeaderGenerator, HeaderConfig
from bypass.waf_detector import WAFDetector, WAFType

__all__ = [
    'HeaderGenerator',
    'HeaderConfig',
    'WAFDetector',
    'WAFType',
]