"""
GraphQL Introspection Engine
Automated schema discovery, analysis, and security misconfiguration detection.

Author: Security Research Team
Version: 1.0.0
"""

import re
import json
import requests
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from loguru import logger
import time


class VulnerabilitySeverity(Enum):
    """CVSS-based vulnerability severity classification"""
    CRITICAL = "CRITICAL"  # 9.0-10.0
    HIGH = "HIGH"          # 7.0-8.9
    MEDIUM = "MEDIUM"      # 4.0-6.9
    LOW = "LOW"            # 0.1-3.9
    INFO = "INFO"          # 0.0


@dataclass
class Vulnerability:
    """Represents a detected security vulnerability"""
    name: str
    severity: VulnerabilitySeverity
    cvss_score: float
    description: str
    evidence: Dict[str, Any]
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: Optional[str] = None
    affected_fields: List[str] = field(default_factory=list)


@dataclass
class GraphQLField:
    """Represents a GraphQL field with security metadata"""
    name: str
    field_type: str
    description: Optional[str] = None
    args: List[Dict[str, str]] = field(default_factory=list)
    is_deprecated: bool = False
    deprecation_reason: Optional[str] = None
    is_sensitive: bool = False
    requires_auth: bool = False
    nesting_level: int = 0


@dataclass
class GraphQLType:
    """Represents a GraphQL type (Object, Interface, Union, etc.)"""
    name: str
    kind: str
    description: Optional[str] = None
    fields: List[GraphQLField] = field(default_factory=list)
    interfaces: List[str] = field(default_factory=list)
    possible_types: List[str] = field(default_factory=list)


class GraphQLIntrospectionEngine:
    """
    Discovers GraphQL schema, queries, mutations, and subscriptions.
    Analyzes for security misconfigurations and generates attack surface maps.
    """

    # Standard GraphQL introspection query
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }

    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }

    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
    }

    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
    """

    # Simplified introspection for detection bypass
    SIMPLE_INTROSPECTION_QUERY = """
    {
      __schema {
        types {
          name
          kind
        }
      }
    }
    """

    # Sensitive field patterns (PII, credentials, secrets)
    SENSITIVE_PATTERNS = [
        r'password', r'passwd', r'pwd', r'secret', r'token', r'api[_-]?key',
        r'access[_-]?key', r'private[_-]?key', r'credential', r'auth',
        r'ssn', r'social[_-]?security', r'credit[_-]?card', r'card[_-]?number',
        r'cvv', r'pin', r'salary', r'account[_-]?number', r'routing[_-]?number',
        r'email', r'phone', r'address', r'dob', r'birth[_-]?date'
    ]

    def __init__(
        self,
        graphql_endpoint: str,
        auth_headers: Optional[Dict[str, str]] = None,
        timeout: int = 30,
        verify_ssl: bool = True,
        max_retries: int = 3
    ):
        """
        Initialize GraphQL Introspection Engine

        Args:
            graphql_endpoint: Target GraphQL API URL
            auth_headers: Authentication headers (e.g., {'Authorization': 'Bearer token'})
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            max_retries: Maximum number of retry attempts
        """
        self.endpoint = graphql_endpoint
        self.auth_headers = auth_headers or {}
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.max_retries = max_retries

        self.schema: Optional[Dict[str, Any]] = None
        self.types: List[GraphQLType] = []
        self.queries: List[GraphQLField] = []
        self.mutations: List[GraphQLField] = []
        self.subscriptions: List[GraphQLField] = []
        self.vulnerabilities: List[Vulnerability] = []

        self.query_type_name: Optional[str] = None
        self.mutation_type_name: Optional[str] = None
        self.subscription_type_name: Optional[str] = None

        logger.info(f"Initialized GraphQL Introspection Engine for {graphql_endpoint}")

    def execute_query(
        self,
        query: str,
        variables: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute a GraphQL query with retry logic

        Args:
            query: GraphQL query string
            variables: Query variables

        Returns:
            Response data dictionary

        Raises:
            requests.exceptions.RequestException: On network errors
            ValueError: On invalid GraphQL responses
        """
        headers = {
            'Content-Type': 'application/json',
            **self.auth_headers
        }

        payload = {'query': query}
        if variables:
            payload['variables'] = variables

        for attempt in range(self.max_retries):
            try:
                logger.debug(f"Executing GraphQL query (attempt {attempt + 1}/{self.max_retries})")
                response = requests.post(
                    self.endpoint,
                    json=payload,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )

                response.raise_for_status()
                data = response.json()

                if 'errors' in data:
                    logger.warning(f"GraphQL errors: {data['errors']}")
                    # Some errors are informative for security testing
                    return data

                return data

            except requests.exceptions.Timeout:
                logger.warning(f"Request timeout (attempt {attempt + 1})")
                if attempt == self.max_retries - 1:
                    raise
                time.sleep(2 ** attempt)  # Exponential backoff

            except requests.exceptions.RequestException as e:
                logger.error(f"Request error: {e}")
                if attempt == self.max_retries - 1:
                    raise
                time.sleep(2 ** attempt)

        raise requests.exceptions.RequestException("Max retries exceeded")

    def fetch_schema(self, use_simple_query: bool = False) -> Dict[str, Any]:
        """
        Execute introspection query to retrieve full schema

        Args:
            use_simple_query: Use simplified query to bypass some protections

        Returns:
            Schema data dictionary with types, queries, mutations, subscriptions
        """
        logger.info("Fetching GraphQL schema via introspection...")

        query = self.SIMPLE_INTROSPECTION_QUERY if use_simple_query else self.INTROSPECTION_QUERY

        try:
            response = self.execute_query(query)

            if 'errors' in response:
                # Check if introspection is disabled
                error_messages = [err.get('message', '') for err in response['errors']]
                if any('introspection' in msg.lower() for msg in error_messages):
                    vuln = Vulnerability(
                        name="Introspection Disabled (Secure Configuration)",
                        severity=VulnerabilitySeverity.INFO,
                        cvss_score=0.0,
                        description="GraphQL introspection is properly disabled",
                        evidence={'errors': error_messages},
                        cwe_id="CWE-200",
                        remediation="This is a secure configuration. No action needed."
                    )
                    self.vulnerabilities.append(vuln)
                    logger.warning("Introspection is disabled - trying simplified query")

                    if not use_simple_query:
                        return self.fetch_schema(use_simple_query=True)

                raise ValueError(f"Schema introspection failed: {error_messages}")

            if 'data' not in response or '__schema' not in response['data']:
                raise ValueError("Invalid introspection response structure")

            self.schema = response['data']['__schema']
            self._parse_schema()

            logger.success(f"Successfully fetched schema: {len(self.types)} types, "
                          f"{len(self.queries)} queries, {len(self.mutations)} mutations")

            return {
                'types': [self._type_to_dict(t) for t in self.types],
                'queries': [self._field_to_dict(q) for q in self.queries],
                'mutations': [self._field_to_dict(m) for m in self.mutations],
                'subscriptions': [self._field_to_dict(s) for s in self.subscriptions]
            }

        except Exception as e:
            logger.error(f"Schema fetch failed: {e}")
            raise

    def _parse_schema(self) -> None:
        """Parse introspection response into structured types and operations"""
        if not self.schema:
            raise ValueError("Schema not fetched yet")

        # Extract type names
        self.query_type_name = self.schema.get('queryType', {}).get('name')
        self.mutation_type_name = self.schema.get('mutationType', {}).get('name')
        self.subscription_type_name = self.schema.get('subscriptionType', {}).get('name')

        # Parse all types
        for type_data in self.schema.get('types', []):
            # Skip internal GraphQL types
            if type_data['name'].startswith('__'):
                continue

            graphql_type = self._parse_type(type_data)
            self.types.append(graphql_type)

            # Categorize operations
            if type_data['name'] == self.query_type_name:
                self.queries = graphql_type.fields
            elif type_data['name'] == self.mutation_type_name:
                self.mutations = graphql_type.fields
            elif type_data['name'] == self.subscription_type_name:
                self.subscriptions = graphql_type.fields

    def _parse_type(self, type_data: Dict[str, Any]) -> GraphQLType:
        """Parse a single GraphQL type"""
        fields = []
        if type_data.get('fields'):
            for field_data in type_data['fields']:
                field = GraphQLField(
                    name=field_data['name'],
                    field_type=self._extract_type_name(field_data['type']),
                    description=field_data.get('description'),
                    args=[
                        {
                            'name': arg['name'],
                            'type': self._extract_type_name(arg['type']),
                            'default': arg.get('defaultValue')
                        }
                        for arg in field_data.get('args', [])
                    ],
                    is_deprecated=field_data.get('isDeprecated', False),
                    deprecation_reason=field_data.get('deprecationReason'),
                    is_sensitive=self._is_sensitive_field(field_data['name'])
                )
                fields.append(field)

        return GraphQLType(
            name=type_data['name'],
            kind=type_data['kind'],
            description=type_data.get('description'),
            fields=fields,
            interfaces=[self._extract_type_name(i) for i in type_data.get('interfaces', [])],
            possible_types=[self._extract_type_name(t) for t in type_data.get('possibleTypes', [])]
        )

    def _extract_type_name(self, type_ref: Dict[str, Any]) -> str:
        """Recursively extract type name from nested type reference"""
        if type_ref.get('name'):
            return type_ref['name']
        elif type_ref.get('ofType'):
            prefix = '[' if type_ref['kind'] == 'LIST' else ''
            suffix = ']' if type_ref['kind'] == 'LIST' else ''
            required = '!' if type_ref['kind'] == 'NON_NULL' else ''
            return f"{prefix}{self._extract_type_name(type_ref['ofType'])}{suffix}{required}"
        return "Unknown"

    def _is_sensitive_field(self, field_name: str) -> bool:
        """Check if field name matches sensitive data patterns"""
        field_lower = field_name.lower()
        return any(re.search(pattern, field_lower) for pattern in self.SENSITIVE_PATTERNS)

    def detect_information_disclosure(self) -> List[Vulnerability]:
        """
        Detect information disclosure vulnerabilities:
        - Introspection enabled in production
        - Overly verbose error messages
        - Exposed field descriptions revealing implementation details
        - Unintended subscriptions
        """
        vulns = []

        # 1. Introspection enabled (if we got here, it's enabled)
        if self.schema:
            vuln = Vulnerability(
                name="GraphQL Introspection Enabled",
                severity=VulnerabilitySeverity.MEDIUM,
                cvss_score=5.3,
                description="GraphQL introspection is enabled, allowing attackers to discover "
                           "the entire API schema including queries, mutations, and types.",
                evidence={
                    'types_count': len(self.types),
                    'queries_count': len(self.queries),
                    'mutations_count': len(self.mutations),
                    'subscriptions_count': len(self.subscriptions)
                },
                cwe_id="CWE-200",
                owasp_category="API1:2023 - Broken Object Level Authorization",
                remediation="Disable introspection in production environments. "
                           "Use schema stitching or federation for internal documentation only."
            )
            vulns.append(vuln)
            logger.warning(f"Detected: {vuln.name}")

        # 2. Verbose field descriptions
        verbose_fields = []
        for gql_type in self.types:
            for field in gql_type.fields:
                if field.description and len(field.description) > 200:
                    verbose_fields.append(f"{gql_type.name}.{field.name}")

        if verbose_fields:
            vuln = Vulnerability(
                name="Verbose Field Descriptions",
                severity=VulnerabilitySeverity.LOW,
                cvss_score=3.1,
                description=f"Found {len(verbose_fields)} fields with overly detailed descriptions "
                           "that may reveal implementation details.",
                evidence={'verbose_fields': verbose_fields[:10]},
                cwe_id="CWE-209",
                remediation="Limit field descriptions to functional documentation only. "
                           "Avoid exposing implementation details, database schemas, or internal logic."
            )
            vulns.append(vuln)

        # 3. Exposed subscriptions (can lead to DoS)
        if self.subscriptions:
            vuln = Vulnerability(
                name="GraphQL Subscriptions Exposed",
                severity=VulnerabilitySeverity.MEDIUM,
                cvss_score=4.3,
                description=f"Found {len(self.subscriptions)} subscription endpoints. "
                           "Improperly secured subscriptions can lead to resource exhaustion.",
                evidence={'subscriptions': [s.name for s in self.subscriptions]},
                cwe_id="CWE-400",
                owasp_category="API4:2023 - Unrestricted Resource Consumption",
                remediation="Implement rate limiting and authentication for all subscriptions. "
                           "Monitor WebSocket connection pools."
            )
            vulns.append(vuln)

        self.vulnerabilities.extend(vulns)
        return vulns

    def analyze_field_accessibility(self) -> List[Vulnerability]:
        """
        Identify:
        - Fields without authentication requirements
        - Sensitive data in public queries
        - Deeply nested queries (DoS risk)
        """
        vulns = []

        # 1. Sensitive fields in queries
        sensitive_fields = []
        for field in self.queries:
            if field.is_sensitive:
                sensitive_fields.append(field.name)

        if sensitive_fields:
            vuln = Vulnerability(
                name="Sensitive Data Exposure in Queries",
                severity=VulnerabilitySeverity.HIGH,
                cvss_score=7.5,
                description=f"Found {len(sensitive_fields)} query fields with sensitive data patterns. "
                           "These may expose PII, credentials, or secrets without proper authorization.",
                evidence={'sensitive_fields': sensitive_fields},
                affected_fields=sensitive_fields,
                cwe_id="CWE-359",
                owasp_category="API3:2023 - Broken Object Property Level Authorization",
                remediation="Implement field-level authorization. Use directives like @auth or "
                           "@requiresPermission. Redact sensitive fields from public schema."
            )
            vulns.append(vuln)
            logger.warning(f"Detected: {vuln.name} - {len(sensitive_fields)} fields")

        # 2. Deep nesting analysis (circular query DoS)
        max_depth = self._calculate_max_nesting_depth()
        if max_depth > 10:
            vuln = Vulnerability(
                name="Excessive Query Depth Allowed",
                severity=VulnerabilitySeverity.MEDIUM,
                cvss_score=5.3,
                description=f"Schema allows query nesting up to {max_depth} levels. "
                           "Attackers can craft deeply nested queries causing DoS.",
                evidence={'max_depth': max_depth},
                cwe_id="CWE-400",
                owasp_category="API4:2023 - Unrestricted Resource Consumption",
                remediation="Implement query depth limiting (max 5-7 levels). "
                           "Use libraries like graphql-depth-limit or apollo-server depth validation."
            )
            vulns.append(vuln)

        self.vulnerabilities.extend(vulns)
        return vulns

    def _calculate_max_nesting_depth(self) -> int:
        """Calculate maximum possible query nesting depth"""
        # Simplified: count types that reference themselves or other objects
        max_depth = 0
        for gql_type in self.types:
            if gql_type.kind == 'OBJECT':
                depth = self._calculate_type_depth(gql_type.name, set(), 0)
                max_depth = max(max_depth, depth)
        return max_depth

    def _calculate_type_depth(self, type_name: str, visited: set, current_depth: int) -> int:
        """Recursively calculate nesting depth for a type"""
        if current_depth > 20 or type_name in visited:  # Prevent infinite recursion
            return current_depth

        visited.add(type_name)
        gql_type = next((t for t in self.types if t.name == type_name), None)

        if not gql_type or gql_type.kind != 'OBJECT':
            return current_depth

        max_child_depth = current_depth
        for field in gql_type.fields:
            # Extract base type name (remove list/non-null markers)
            base_type = re.sub(r'[\[\]!]', '', field.field_type)
            child_depth = self._calculate_type_depth(base_type, visited.copy(), current_depth + 1)
            max_child_depth = max(max_child_depth, child_depth)

        return max_child_depth

    def generate_attack_surface_map(self) -> Dict[str, Any]:
        """
        Generate comprehensive attack surface map

        Returns:
            Dictionary with queryable fields, mutations, scalars, enums, and risk scores
        """
        logger.info("Generating attack surface map...")

        attack_surface = {
            'endpoint': self.endpoint,
            'timestamp': time.time(),
            'introspection_enabled': self.schema is not None,
            'authentication_detected': bool(self.auth_headers),
            'statistics': {
                'total_types': len(self.types),
                'total_queries': len(self.queries),
                'total_mutations': len(self.mutations),
                'total_subscriptions': len(self.subscriptions),
                'sensitive_fields': sum(1 for t in self.types for f in t.fields if f.is_sensitive),
                'deprecated_fields': sum(1 for t in self.types for f in t.fields if f.is_deprecated)
            },
            'queries': [
                {
                    'name': q.name,
                    'type': q.field_type,
                    'args': q.args,
                    'is_sensitive': q.is_sensitive,
                    'description': q.description
                }
                for q in self.queries
            ],
            'mutations': [
                {
                    'name': m.name,
                    'type': m.field_type,
                    'args': m.args,
                    'is_sensitive': m.is_sensitive,
                    'description': m.description
                }
                for m in self.mutations
            ],
            'subscriptions': [
                {
                    'name': s.name,
                    'type': s.field_type,
                    'description': s.description
                }
                for s in self.subscriptions
            ],
            'high_risk_fields': [
                f"{t.name}.{f.name}"
                for t in self.types
                for f in t.fields
                if f.is_sensitive
            ],
            'vulnerabilities_detected': len(self.vulnerabilities),
            'risk_score': self._calculate_risk_score()
        }

        return attack_surface

    def _calculate_risk_score(self) -> float:
        """
        Calculate overall API risk score (0-10)
        Based on: introspection enabled, sensitive fields, vulnerabilities, complexity
        """
        score = 0.0

        # Introspection enabled: +2
        if self.schema:
            score += 2.0

        # Sensitive fields: +0.1 per field (max +3)
        sensitive_count = sum(1 for t in self.types for f in t.fields if f.is_sensitive)
        score += min(sensitive_count * 0.1, 3.0)

        # Vulnerabilities: weighted by severity
        severity_weights = {
            VulnerabilitySeverity.CRITICAL: 2.0,
            VulnerabilitySeverity.HIGH: 1.5,
            VulnerabilitySeverity.MEDIUM: 0.8,
            VulnerabilitySeverity.LOW: 0.3,
            VulnerabilitySeverity.INFO: 0.0
        }
        for vuln in self.vulnerabilities:
            score += severity_weights.get(vuln.severity, 0.0)

        # Complexity (mutations): +0.05 per mutation (max +2)
        score += min(len(self.mutations) * 0.05, 2.0)

        return min(score, 10.0)  # Cap at 10.0

    def run_full_analysis(self) -> Dict[str, Any]:
        """
        Execute complete introspection and vulnerability analysis

        Returns:
            Comprehensive analysis report
        """
        logger.info("Starting full GraphQL security analysis...")

        # Fetch schema
        schema_data = self.fetch_schema()

        # Run vulnerability detections
        info_disclosure_vulns = self.detect_information_disclosure()
        field_access_vulns = self.analyze_field_accessibility()

        # Generate attack surface map
        attack_surface = self.generate_attack_surface_map()

        # Compile report
        report = {
            'endpoint': self.endpoint,
            'analysis_timestamp': time.time(),
            'schema': schema_data,
            'attack_surface': attack_surface,
            'vulnerabilities': [
                {
                    'name': v.name,
                    'severity': v.severity.value,
                    'cvss_score': v.cvss_score,
                    'description': v.description,
                    'evidence': v.evidence,
                    'cwe_id': v.cwe_id,
                    'owasp_category': v.owasp_category,
                    'remediation': v.remediation,
                    'affected_fields': v.affected_fields
                }
                for v in self.vulnerabilities
            ],
            'summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'critical_count': sum(1 for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.CRITICAL),
                'high_count': sum(1 for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.HIGH),
                'medium_count': sum(1 for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.MEDIUM),
                'low_count': sum(1 for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.LOW),
                'risk_score': attack_surface['risk_score']
            }
        }

        logger.success(f"Analysis complete: {len(self.vulnerabilities)} vulnerabilities detected, "
                      f"Risk Score: {attack_surface['risk_score']:.1f}/10.0")

        return report

    def _type_to_dict(self, gql_type: GraphQLType) -> Dict[str, Any]:
        """Convert GraphQLType to dictionary"""
        return {
            'name': gql_type.name,
            'kind': gql_type.kind,
            'description': gql_type.description,
            'fields': [self._field_to_dict(f) for f in gql_type.fields],
            'interfaces': gql_type.interfaces
        }

    def _field_to_dict(self, field: GraphQLField) -> Dict[str, Any]:
        """Convert GraphQLField to dictionary"""
        return {
            'name': field.name,
            'type': field.field_type,
            'description': field.description,
            'args': field.args,
            'is_deprecated': field.is_deprecated,
            'is_sensitive': field.is_sensitive
        }

    def export_report(self, filepath: str, format: str = 'json') -> None:
        """
        Export analysis report to file

        Args:
            filepath: Output file path
            format: Output format ('json', 'markdown', 'html')
        """
        report = self.run_full_analysis() if not self.vulnerabilities else {
            'vulnerabilities': [
                {
                    'name': v.name,
                    'severity': v.severity.value,
                    'cvss_score': v.cvss_score,
                    'description': v.description
                }
                for v in self.vulnerabilities
            ]
        }

        if format == 'json':
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
        elif format == 'markdown':
            # Basic markdown export
            with open(filepath, 'w') as f:
                f.write(f"# GraphQL Security Analysis Report\n\n")
                f.write(f"**Endpoint:** {self.endpoint}\n\n")
                f.write(f"## Vulnerabilities ({len(self.vulnerabilities)})\n\n")
                for v in self.vulnerabilities:
                    f.write(f"### {v.name}\n")
                    f.write(f"- **Severity:** {v.severity.value}\n")
                    f.write(f"- **CVSS:** {v.cvss_score}\n")
                    f.write(f"- **Description:** {v.description}\n\n")

        logger.info(f"Report exported to {filepath}")


if __name__ == "__main__":
    # Example usage
    engine = GraphQLIntrospectionEngine(
        graphql_endpoint="https://api.example.com/graphql",
        auth_headers={"Authorization": "Bearer YOUR_TOKEN_HERE"}
    )

    try:
        report = engine.run_full_analysis()
        engine.export_report("graphql_security_report.json")
        print(f"Found {len(engine.vulnerabilities)} vulnerabilities")
        print(f"Risk Score: {report['attack_surface']['risk_score']:.1f}/10.0")
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
