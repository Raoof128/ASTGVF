"""
Core modules for API Security Framework
"""

from core.graphql_introspection import (
    GraphQLIntrospectionEngine,
    Vulnerability,
    VulnerabilitySeverity
)
from core.vulnerability_scanner import (
    BaseVulnerabilityDetector,
    VulnerabilityCategory,
    ScanStatus,
    ScanResult,
    PayloadDatabase,
    DetectionPatterns
)
from core.remediation_engine import (
    RemediationEngine,
    RemediationPlan,
    RemediationPriority,
    RemediationStep
)

__all__ = [
    # Introspection
    'GraphQLIntrospectionEngine',
    'Vulnerability',
    'VulnerabilitySeverity',
    # Scanner
    'BaseVulnerabilityDetector',
    'VulnerabilityCategory',
    'ScanStatus',
    'ScanResult',
    'PayloadDatabase',
    'DetectionPatterns',
    # Remediation
    'RemediationEngine',
    'RemediationPlan',
    'RemediationPriority',
    'RemediationStep',
]

__version__ = '1.0.0'
