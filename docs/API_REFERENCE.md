# API Reference

Complete reference documentation for the API Security Framework modules.

---

## Table of Contents

- [Core Modules](#core-modules)
  - [GraphQL Introspection Engine](#graphql-introspection-engine)
  - [Vulnerability Scanner Base](#vulnerability-scanner-base)
  - [Remediation Engine](#remediation-engine)
- [Detectors](#detectors)
  - [Injection Detector](#injection-detector)
  - [Authorization Detector](#authorization-detector)
  - [Authentication Detector](#authentication-detector)
- [Reporting](#reporting)
  - [Vulnerability Reporter](#vulnerability-reporter)
- [CLI](#cli)

---

## Core Modules

### GraphQL Introspection Engine

**Module:** `core.graphql_introspection`

#### GraphQLIntrospectionEngine

Discovers and analyzes GraphQL schemas for security misconfigurations.

**Constructor:**

```python
GraphQLIntrospectionEngine(
    graphql_endpoint: str,
    auth_headers: Optional[Dict[str, str]] = None,
    timeout: int = 30,
    verify_ssl: bool = True,
    max_retries: int = 3
)
```

**Parameters:**
- `graphql_endpoint` (str): Target GraphQL API URL
- `auth_headers` (dict, optional): Authentication headers
- `timeout` (int): Request timeout in seconds (default: 30)
- `verify_ssl` (bool): Verify SSL certificates (default: True)
- `max_retries` (int): Maximum retry attempts (default: 3)

**Methods:**

#### `fetch_schema(use_simple_query: bool = False) -> Dict`

Executes introspection query to retrieve full schema.

**Parameters:**
- `use_simple_query` (bool): Use simplified query (default: False)

**Returns:**
- `dict`: Schema data with types, queries, mutations, subscriptions

**Example:**
```python
from core.graphql_introspection import GraphQLIntrospectionEngine

engine = GraphQLIntrospectionEngine(
    graphql_endpoint="https://api.example.com/graphql",
    auth_headers={"Authorization": "Bearer token"}
)

schema = engine.fetch_schema()
print(f"Types: {len(schema['types'])}")
print(f"Queries: {len(schema['queries'])}")
```

#### `detect_information_disclosure() -> List[Vulnerability]`

Detects information disclosure vulnerabilities.

**Returns:**
- `list`: List of Vulnerability objects

**Detects:**
- Introspection enabled in production
- Verbose error messages
- Exposed field descriptions
- Unintended subscriptions

#### `analyze_field_accessibility() -> List[Vulnerability]`

Analyzes field accessibility for security issues.

**Returns:**
- `list`: List of Vulnerability objects

**Detects:**
- Fields without authentication
- Sensitive data in public queries
- Deeply nested queries (DoS risk)

#### `generate_attack_surface_map() -> Dict`

Generates comprehensive attack surface map.

**Returns:**
- `dict`: Attack surface data including risk scores

#### `run_full_analysis() -> Dict`

Executes complete introspection and vulnerability analysis.

**Returns:**
- `dict`: Complete analysis report

---

### Vulnerability Scanner Base

**Module:** `core.vulnerability_scanner`

#### BaseVulnerabilityDetector

Abstract base class for all vulnerability detectors.

**Constructor:**

```python
BaseVulnerabilityDetector(
    endpoint: str,
    auth_headers: Optional[Dict[str, str]] = None,
    timeout: int = 30,
    verify_ssl: bool = True,
    max_concurrent_requests: int = 5,
    rate_limit_delay: float = 0.1
)
```

**Abstract Methods:**

Must be implemented by subclasses:

```python
@abc.abstractmethod
def detect(self, **kwargs) -> List[Any]:
    """Execute vulnerability detection logic"""
    pass

@abc.abstractmethod
def get_detector_name(self) -> str:
    """Return detector name"""
    pass

@abc.abstractmethod
def get_vulnerability_category(self) -> VulnerabilityCategory:
    """Return OWASP category"""
    pass
```

**Concrete Methods:**

#### `execute_graphql_query(query: str, variables: Optional[Dict] = None) -> Dict`

Executes GraphQL query with error handling.

**Parameters:**
- `query` (str): GraphQL query string
- `variables` (dict, optional): Query variables

**Returns:**
- `dict`: Response with status_code, headers, body

#### `test_payloads(field_name: str, field_type: str, payloads: List[str], detection_patterns: List[str], query_template: str) -> List[PayloadResult]`

Tests multiple payloads against a field.

**Parameters:**
- `field_name` (str): GraphQL field name
- `field_type` (str): Field type
- `payloads` (list): Attack payloads
- `detection_patterns` (list): Detection regex patterns
- `query_template` (str): GraphQL query template

**Returns:**
- `list`: PayloadResult objects

#### `run_detection(**kwargs) -> ScanResult`

Executes detection with timing and error handling.

**Returns:**
- `ScanResult`: Scan execution results

#### PayloadDatabase

Static payload database class.

**Attributes:**
- `SQL_INJECTION`: List of SQL injection payloads
- `NOSQL_INJECTION`: List of NoSQL injection payloads
- `COMMAND_INJECTION`: List of command injection payloads
- `XSS`: List of XSS payloads
- `PATH_TRAVERSAL`: List of path traversal payloads

**Methods:**

```python
@classmethod
def get_payloads(cls, category: str) -> List[str]:
    """Get payloads for specific category"""
    return getattr(cls, category.upper(), [])
```

---

## Detectors

### Injection Detector

**Module:** `detectors.injection_detector`

#### InjectionDetector(BaseVulnerabilityDetector)

Detects SQL, NoSQL, Command, and LDAP injection vulnerabilities.

**Methods:**

#### `detect(schema: Optional[Dict] = None, test_fields: Optional[List[str]] = None, injection_types: Optional[List[str]] = None) -> List[Dict]`

Executes injection vulnerability detection.

**Parameters:**
- `schema` (dict, optional): GraphQL schema
- `test_fields` (list, optional): Specific fields to test
- `injection_types` (list, optional): Types to test ('sql', 'nosql', 'command', 'ldap')

**Returns:**
- `list`: Detected vulnerabilities

**Example:**
```python
from detectors.injection_detector import InjectionDetector

detector = InjectionDetector(
    endpoint="https://api.example.com/graphql",
    auth_headers={"Authorization": "Bearer token"}
)

# Run detection
result = detector.run_detection(
    injection_types=['sql', 'nosql']
)

print(f"Found {len(result.vulnerabilities)} vulnerabilities")
```

---

### Authorization Detector

**Module:** `detectors.authorization_detector`

#### AuthorizationDetector(BaseVulnerabilityDetector)

Detects IDOR, BOLA, BFLA, and privilege escalation vulnerabilities.

**Methods:**

#### `detect(schema: Optional[Dict] = None, current_user_id: Optional[str] = None, test_user_ids: Optional[List[str]] = None, test_fields: Optional[List[str]] = None) -> List[Dict]`

Executes authorization vulnerability detection.

**Parameters:**
- `schema` (dict, optional): GraphQL schema
- `current_user_id` (str, optional): Current user ID
- `test_user_ids` (list, optional): Other user IDs to test
- `test_fields` (list, optional): Specific fields to test

**Returns:**
- `list`: Detected vulnerabilities

**Example:**
```python
from detectors.authorization_detector import AuthorizationDetector

detector = AuthorizationDetector(
    endpoint="https://api.example.com/graphql"
)

result = detector.run_detection(
    current_user_id="123",
    test_user_ids=["1", "2", "456"]
)
```

---

### Authentication Detector

**Module:** `detectors.authentication_detector`

#### AuthenticationDetector(BaseVulnerabilityDetector)

Detects JWT vulnerabilities and authentication bypass issues.

**Methods:**

#### `detect(schema: Optional[Dict] = None, current_token: Optional[str] = None, test_mutations: bool = True) -> List[Dict]`

Executes authentication vulnerability detection.

**Parameters:**
- `schema` (dict, optional): GraphQL schema
- `current_token` (str, optional): Current JWT token
- `test_mutations` (bool): Test mutations for auth (default: True)

**Returns:**
- `list`: Detected vulnerabilities

**Detects:**
- JWT None Algorithm
- Weak JWT secrets
- Algorithm confusion
- Token tampering
- Authentication bypass

---

## Reporting

### Vulnerability Reporter

**Module:** `reporting.vulnerability_reporter`

#### VulnerabilityReporter

Generates professional security assessment reports.

**Methods:**

#### `generate_executive_summary(vulnerabilities: List[Dict], endpoint: str, risk_score: float) -> str`

Generates non-technical executive summary.

**Parameters:**
- `vulnerabilities` (list): List of vulnerabilities
- `endpoint` (str): API endpoint
- `risk_score` (float): Overall risk score (0-10)

**Returns:**
- `str`: Executive summary text

#### `generate_technical_report(scan_results: Dict, format: str = 'html') -> str`

Generates detailed technical report.

**Parameters:**
- `scan_results` (dict): Complete scan results
- `format` (str): Output format ('html', 'markdown', 'json', 'pdf')

**Returns:**
- `str`: Formatted report

**Example:**
```python
from reporting.vulnerability_reporter import VulnerabilityReporter

reporter = VulnerabilityReporter()

scan_results = {
    'endpoint': 'https://api.example.com/graphql',
    'vulnerabilities': vulnerabilities,
    'tests_executed': 100,
    'scan_duration': 45.3,
    'risk_score': 7.8
}

# Generate HTML report
html_report = reporter.generate_technical_report(scan_results, format='html')

# Export to file
reporter.export_to_file(scan_results, 'report.html')

# Export to PDF
reporter.export_to_pdf(scan_results, 'report.pdf')
```

#### `export_to_file(scan_results: Dict, filepath: str, format: Optional[str] = None) -> None`

Exports report to file.

**Parameters:**
- `scan_results` (dict): Scan results
- `filepath` (str): Output file path
- `format` (str, optional): Format (auto-detected from extension if None)

#### `export_to_pdf(scan_results: Dict, filepath: str) -> None`

Exports report to PDF (requires weasyprint).

---

## CLI

**Module:** `orchestration.cli`

### Commands

#### scan

Executes comprehensive API security scan.

**Usage:**
```bash
api-security scan --url URL [OPTIONS]
```

**Options:**
- `--url, -u` (required): Target API endpoint URL
- `--auth-token, -t`: Authentication token
- `--auth-header, -H`: Custom auth header (multiple allowed)
- `--output-file, -o`: Output report file (default: security_report.html)
- `--output-format, -f`: Report format (html|json|markdown|pdf)
- `--vulnerabilities, -v`: Vulnerability types to test
- `--confidence-threshold`: Detection confidence (0.0-1.0, default: 0.80)
- `--max-concurrent`: Maximum concurrent requests (default: 5)
- `--timeout`: Request timeout in seconds (default: 30)
- `--verify-ssl/--no-verify-ssl`: Verify SSL certificates (default: True)
- `--verbose, -V`: Verbose output

#### remediate

Generates remediation plans from scan results.

**Usage:**
```bash
api-security remediate --report-file FILE [OPTIONS]
```

**Options:**
- `--report-file, -r` (required): Scan report JSON file
- `--output-file, -o`: Output remediation plan file (default: remediation_plan.md)
- `--format, -f`: Output format (markdown|json)

#### introspect

Performs GraphQL introspection and saves schema.

**Usage:**
```bash
api-security introspect --url URL [OPTIONS]
```

**Options:**
- `--url, -u` (required): Target API endpoint
- `--auth-token, -t`: Authentication token
- `--output-file, -o`: Output schema file (default: schema.json)

#### config

Runs scan with configuration file.

**Usage:**
```bash
api-security config --config-file FILE
```

**Options:**
- `--config-file, -c` (required): Configuration file (YAML/JSON)

---

## Data Classes

### Vulnerability

```python
@dataclass
class Vulnerability:
    name: str
    severity: VulnerabilitySeverity
    cvss_score: float
    description: str
    evidence: Dict[str, Any]
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: Optional[str] = None
    affected_fields: List[str] = field(default_factory=list)
```

### ScanResult

```python
@dataclass
class ScanResult:
    detector_name: str
    status: ScanStatus
    vulnerabilities: List[Any] = field(default_factory=list)
    scan_duration: float = 0.0
    tests_executed: int = 0
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
```

### RemediationPlan

```python
@dataclass
class RemediationPlan:
    vulnerability_name: str
    cwe_id: str
    owasp_category: str
    cvss_score: float
    priority: RemediationPriority
    remediation_steps: List[RemediationStep]
    secure_code_examples: Dict[str, str]
    testing_recommendations: List[str]
    references: List[str]
    estimated_total_effort: str
```

---

## Enums

### VulnerabilitySeverity

```python
class VulnerabilitySeverity(Enum):
    CRITICAL = "CRITICAL"  # 9.0-10.0
    HIGH = "HIGH"          # 7.0-8.9
    MEDIUM = "MEDIUM"      # 4.0-6.9
    LOW = "LOW"            # 0.1-3.9
    INFO = "INFO"          # 0.0
```

### VulnerabilityCategory

```python
class VulnerabilityCategory(Enum):
    BROKEN_OBJECT_LEVEL_AUTH = "API1:2023 - Broken Object Level Authorization"
    BROKEN_AUTHENTICATION = "API2:2023 - Broken Authentication"
    BROKEN_OBJECT_PROPERTY_AUTH = "API3:2023 - Broken Object Property Level Authorization"
    UNRESTRICTED_RESOURCE_CONSUMPTION = "API4:2023 - Unrestricted Resource Consumption"
    # ... and more
```

---

## Examples

### Full Scan Example

```python
from core.graphql_introspection import GraphQLIntrospectionEngine
from detectors.injection_detector import InjectionDetector
from detectors.authorization_detector import AuthorizationDetector
from reporting.vulnerability_reporter import VulnerabilityReporter

# Setup
endpoint = "https://api.example.com/graphql"
auth = {"Authorization": "Bearer token"}

# Phase 1: Introspection
introspection = GraphQLIntrospectionEngine(endpoint, auth_headers=auth)
schema = introspection.fetch_schema()
introspection_vulns = introspection.run_full_analysis()['vulnerabilities']

# Phase 2: Injection Detection
injection_detector = InjectionDetector(endpoint, auth_headers=auth)
injection_result = injection_detector.run_detection(schema=schema)

# Phase 3: Authorization Detection
authz_detector = AuthorizationDetector(endpoint, auth_headers=auth)
authz_result = authz_detector.run_detection(schema=schema)

# Aggregate results
all_vulns = introspection_vulns + injection_result.vulnerabilities + authz_result.vulnerabilities

# Generate report
reporter = VulnerabilityReporter()
scan_results = {
    'endpoint': endpoint,
    'vulnerabilities': all_vulns,
    'tests_executed': injection_result.tests_executed + authz_result.tests_executed,
    'scan_duration': injection_result.scan_duration + authz_result.scan_duration,
    'risk_score': 0.0  # Calculate from vulnerabilities
}

reporter.export_to_file(scan_results, 'security_report.html')
```

---

## Error Handling

All methods may raise:

- `requests.exceptions.RequestException`: Network errors
- `ValueError`: Invalid input parameters
- `GraphQLError`: GraphQL-specific errors

Always wrap API calls in try-except blocks:

```python
try:
    result = detector.run_detection()
except Exception as e:
    logger.error(f"Detection failed: {e}")
```

---

## Performance Tuning

### Concurrent Requests

```python
detector = InjectionDetector(
    endpoint=url,
    max_concurrent_requests=10  # Increase for faster scans
)
```

### Rate Limiting

```python
detector = InjectionDetector(
    endpoint=url,
    rate_limit_delay=0.5  # Increase delay to avoid rate limiting
)
```

### Timeouts

```python
detector = InjectionDetector(
    endpoint=url,
    timeout=60  # Increase for slow APIs
)
```

---

## Type Hints

The framework uses Python type hints throughout:

```python
from typing import Dict, List, Optional, Any

def detect(
    self,
    schema: Optional[Dict[str, Any]] = None,
    test_fields: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    pass
```

---

## Further Reading

- [User Guide](README.md)
- [Setup Guide](SETUP.md)
- [Contributing Guide](../CONTRIBUTING.md)
- [Security Policy](../SECURITY.md)

---

**Last Updated:** 2025-01-XX
**Version:** 1.0.0
