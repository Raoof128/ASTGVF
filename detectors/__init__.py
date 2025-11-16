"""
Vulnerability detector modules
"""

from detectors.injection_detector import InjectionDetector
from detectors.authorization_detector import AuthorizationDetector
from detectors.authentication_detector import AuthenticationDetector

__all__ = [
    'InjectionDetector',
    'AuthorizationDetector',
    'AuthenticationDetector',
]
