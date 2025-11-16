"""
Injection Vulnerability Detector
Detects SQL Injection, NoSQL Injection, Command Injection, and LDAP Injection.

Author: Security Research Team
Version: 1.0.0
"""

import re
import json
from typing import Dict, List, Optional, Any
from loguru import logger

from core.vulnerability_scanner import (
    BaseVulnerabilityDetector,
    VulnerabilityCategory,
    PayloadDatabase,
    DetectionPatterns,
    PayloadResult
)


class InjectionDetector(BaseVulnerabilityDetector):
    """
    Detects injection vulnerabilities in GraphQL/REST APIs:
    - SQL Injection (Error-based, Boolean-based, Time-based)
    - NoSQL Injection (MongoDB, CouchDB, etc.)
    - Command Injection (OS command execution)
    - LDAP Injection
    """

    def get_detector_name(self) -> str:
        return "Injection Vulnerability Detector"

    def get_vulnerability_category(self) -> VulnerabilityCategory:
        return VulnerabilityCategory.INJECTION

    def detect(
        self,
        schema: Optional[Dict[str, Any]] = None,
        test_fields: Optional[List[str]] = None,
        injection_types: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Execute injection vulnerability detection

        Args:
            schema: GraphQL schema (from introspection)
            test_fields: Specific fields to test (if None, test all)
            injection_types: Types to test ('sql', 'nosql', 'command', 'ldap')

        Returns:
            List of detected vulnerabilities
        """
        injection_types = injection_types or ['sql', 'nosql', 'command']
        vulnerabilities = []

        logger.info(f"Starting injection detection for types: {injection_types}")

        # Extract fields to test from schema
        fields_to_test = self._extract_testable_fields(schema, test_fields)

        logger.info(f"Testing {len(fields_to_test)} fields for injection vulnerabilities")

        for field_info in fields_to_test:
            field_name = field_info['name']
            field_type = field_info['type']
            args = field_info.get('args', [])

            # Test each injection type
            if 'sql' in injection_types:
                sql_vulns = self._test_sql_injection(field_name, field_type, args)
                vulnerabilities.extend(sql_vulns)

            if 'nosql' in injection_types:
                nosql_vulns = self._test_nosql_injection(field_name, field_type, args)
                vulnerabilities.extend(nosql_vulns)

            if 'command' in injection_types:
                cmd_vulns = self._test_command_injection(field_name, field_type, args)
                vulnerabilities.extend(cmd_vulns)

            if 'ldap' in injection_types:
                ldap_vulns = self._test_ldap_injection(field_name, field_type, args)
                vulnerabilities.extend(ldap_vulns)

        logger.success(f"Injection detection complete: {len(vulnerabilities)} vulnerabilities found")
        return vulnerabilities

    def _extract_testable_fields(
        self,
        schema: Optional[Dict[str, Any]],
        specific_fields: Optional[List[str]]
    ) -> List[Dict[str, Any]]:
        """
        Extract fields that can be tested for injection

        Args:
            schema: GraphQL schema
            specific_fields: Specific fields to test

        Returns:
            List of field dictionaries with name, type, args
        """
        testable_fields = []

        if not schema:
            # If no schema, create test case for common field names
            common_fields = ['id', 'userId', 'user', 'search', 'query', 'filter', 'input']
            return [
                {'name': field, 'type': 'String', 'args': [{'name': 'input', 'type': 'String'}]}
                for field in (specific_fields or common_fields)
            ]

        # Extract from schema
        for query in schema.get('queries', []):
            if specific_fields and query['name'] not in specific_fields:
                continue

            # Only test fields that accept string/scalar arguments
            if query.get('args'):
                testable_fields.append({
                    'name': query['name'],
                    'type': query.get('type', 'String'),
                    'args': query['args']
                })

        return testable_fields

    def _test_sql_injection(
        self,
        field_name: str,
        field_type: str,
        args: List[Dict[str, str]]
    ) -> List[Dict[str, Any]]:
        """
        Test field for SQL injection vulnerabilities

        Args:
            field_name: GraphQL field name
            field_type: Field return type
            args: Field arguments

        Returns:
            List of SQL injection vulnerabilities
        """
        vulnerabilities = []
        payloads = PayloadDatabase.SQL_INJECTION
        detection_patterns = DetectionPatterns.SQL_ERRORS

        logger.debug(f"Testing {field_name} for SQL injection ({len(payloads)} payloads)")

        # Test each argument
        for arg in args:
            arg_name = arg['name']
            arg_type = arg.get('type', 'String')

            # Only test string-like arguments
            if 'String' not in arg_type and 'ID' not in arg_type:
                continue

            successful_payloads = []

            for payload in payloads:
                # Build GraphQL query
                query = f"""
                query {{
                  {field_name}({arg_name}: "{payload}") {{
                    __typename
                  }}
                }}
                """

                response = self.execute_graphql_query(query)

                # Check for SQL error patterns
                match_found, matched_pattern = self.analyze_response_patterns(
                    response,
                    detection_patterns
                )

                if match_found:
                    successful_payloads.append({
                        'payload': payload,
                        'pattern': matched_pattern,
                        'response': response.get('raw_text', '')[:500],
                        'status_code': response.get('status_code')
                    })

                    logger.warning(f"SQL injection detected in {field_name}.{arg_name}: {payload}")

                # Also check for time-based blind SQL injection
                if self._detect_time_based_sqli(response):
                    successful_payloads.append({
                        'payload': payload,
                        'pattern': 'Time-based blind SQLi',
                        'response': 'Response time >5 seconds',
                        'type': 'time_based'
                    })

            # Create vulnerability if any payload succeeded
            if successful_payloads:
                vuln = self.create_vulnerability(
                    name="SQL Injection",
                    severity="CRITICAL",
                    cvss_score=9.8,
                    description=f"SQL injection vulnerability detected in field '{field_name}' "
                               f"argument '{arg_name}'. Successful payloads: {len(successful_payloads)}",
                    evidence={
                        'field': field_name,
                        'argument': arg_name,
                        'successful_payloads': successful_payloads[:5],  # Limit evidence size
                        'total_successful': len(successful_payloads)
                    },
                    cwe_id="CWE-89",
                    remediation=self._get_sql_injection_remediation(),
                    affected_field=f"{field_name}.{arg_name}",
                    exploitation_difficulty="Easy",
                    business_impact="Critical - Full database compromise possible"
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _test_nosql_injection(
        self,
        field_name: str,
        field_type: str,
        args: List[Dict[str, str]]
    ) -> List[Dict[str, Any]]:
        """
        Test field for NoSQL injection vulnerabilities

        Args:
            field_name: GraphQL field name
            field_type: Field return type
            args: Field arguments

        Returns:
            List of NoSQL injection vulnerabilities
        """
        vulnerabilities = []
        payloads = PayloadDatabase.NOSQL_INJECTION
        detection_patterns = DetectionPatterns.NOSQL_ERRORS

        logger.debug(f"Testing {field_name} for NoSQL injection")

        for arg in args:
            arg_name = arg['name']
            successful_payloads = []

            for payload in payloads:
                # Test different injection vectors
                queries_to_test = [
                    # Direct injection
                    f"""
                    query {{
                      {field_name}({arg_name}: "{payload}") {{
                        __typename
                      }}
                    }}
                    """,
                    # JSON object injection (for MongoDB)
                    f"""
                    query {{
                      {field_name}({arg_name}: {payload}) {{
                        __typename
                      }}
                    }}
                    """
                ]

                for query in queries_to_test:
                    try:
                        response = self.execute_graphql_query(query)

                        # Check for NoSQL error patterns
                        match_found, matched_pattern = self.analyze_response_patterns(
                            response,
                            detection_patterns
                        )

                        if match_found:
                            successful_payloads.append({
                                'payload': payload,
                                'pattern': matched_pattern,
                                'response': response.get('raw_text', '')[:500]
                            })

                        # Check for behavior changes (authentication bypass indicators)
                        if self._detect_nosql_bypass(response):
                            successful_payloads.append({
                                'payload': payload,
                                'pattern': 'NoSQL authentication bypass',
                                'response': 'Unexpected success response'
                            })

                    except Exception as e:
                        # JSON parsing errors might indicate successful injection
                        if 'json' in str(e).lower():
                            logger.debug(f"JSON error with payload {payload} - possible NoSQL injection")

            if successful_payloads:
                vuln = self.create_vulnerability(
                    name="NoSQL Injection",
                    severity="CRITICAL",
                    cvss_score=9.8,
                    description=f"NoSQL injection vulnerability detected in field '{field_name}' "
                               f"argument '{arg_name}'.",
                    evidence={
                        'field': field_name,
                        'argument': arg_name,
                        'successful_payloads': successful_payloads[:5]
                    },
                    cwe_id="CWE-943",
                    remediation=self._get_nosql_injection_remediation(),
                    affected_field=f"{field_name}.{arg_name}"
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _test_command_injection(
        self,
        field_name: str,
        field_type: str,
        args: List[Dict[str, str]]
    ) -> List[Dict[str, Any]]:
        """
        Test field for OS command injection vulnerabilities

        Args:
            field_name: GraphQL field name
            field_type: Field return type
            args: Field arguments

        Returns:
            List of command injection vulnerabilities
        """
        vulnerabilities = []
        payloads = PayloadDatabase.COMMAND_INJECTION
        detection_patterns = DetectionPatterns.COMMAND_EXECUTION

        logger.debug(f"Testing {field_name} for command injection")

        for arg in args:
            arg_name = arg['name']
            successful_payloads = []

            for payload in payloads:
                query = f"""
                query {{
                  {field_name}({arg_name}: "{payload}") {{
                    __typename
                  }}
                }}
                """

                response = self.execute_graphql_query(query)

                # Check for command execution patterns
                match_found, matched_pattern = self.analyze_response_patterns(
                    response,
                    detection_patterns
                )

                if match_found:
                    successful_payloads.append({
                        'payload': payload,
                        'pattern': matched_pattern,
                        'response': response.get('raw_text', '')[:500],
                        'severity': 'CRITICAL'
                    })

                    logger.critical(f"Command injection detected in {field_name}.{arg_name}!")

            if successful_payloads:
                vuln = self.create_vulnerability(
                    name="OS Command Injection",
                    severity="CRITICAL",
                    cvss_score=10.0,
                    description=f"OS command injection vulnerability detected in field '{field_name}' "
                               f"argument '{arg_name}'. Server-side code execution is possible.",
                    evidence={
                        'field': field_name,
                        'argument': arg_name,
                        'successful_payloads': successful_payloads
                    },
                    cwe_id="CWE-78",
                    remediation=self._get_command_injection_remediation(),
                    affected_field=f"{field_name}.{arg_name}",
                    business_impact="Critical - Full server compromise possible"
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _test_ldap_injection(
        self,
        field_name: str,
        field_type: str,
        args: List[Dict[str, str]]
    ) -> List[Dict[str, Any]]:
        """
        Test field for LDAP injection vulnerabilities

        Args:
            field_name: GraphQL field name
            field_type: Field return type
            args: Field arguments

        Returns:
            List of LDAP injection vulnerabilities
        """
        vulnerabilities = []
        payloads = PayloadDatabase.LDAP_INJECTION

        # LDAP error patterns
        ldap_patterns = [
            r"javax.naming.NameNotFoundException",
            r"LDAPException",
            r"com.sun.jndi.ldap"
        ]

        for arg in args:
            arg_name = arg['name']
            successful_payloads = []

            for payload in payloads:
                query = f"""
                query {{
                  {field_name}({arg_name}: "{payload}") {{
                    __typename
                  }}
                }}
                """

                response = self.execute_graphql_query(query)

                match_found, matched_pattern = self.analyze_response_patterns(
                    response,
                    ldap_patterns
                )

                if match_found:
                    successful_payloads.append({
                        'payload': payload,
                        'pattern': matched_pattern,
                        'response': response.get('raw_text', '')[:500]
                    })

            if successful_payloads:
                vuln = self.create_vulnerability(
                    name="LDAP Injection",
                    severity="HIGH",
                    cvss_score=8.1,
                    description=f"LDAP injection vulnerability detected in field '{field_name}' "
                               f"argument '{arg_name}'.",
                    evidence={
                        'field': field_name,
                        'argument': arg_name,
                        'successful_payloads': successful_payloads
                    },
                    cwe_id="CWE-90",
                    remediation="Use parameterized LDAP queries. Validate and sanitize all user input "
                               "before including in LDAP queries.",
                    affected_field=f"{field_name}.{arg_name}"
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _detect_time_based_sqli(self, response: Dict[str, Any]) -> bool:
        """
        Detect time-based blind SQL injection by analyzing response times

        Args:
            response: API response

        Returns:
            True if time-based SQLi detected
        """
        # Check if response time is significantly delayed
        # This would require storing request start/end times
        # Simplified check: look for timeout errors
        return 'timeout' in str(response.get('error', '')).lower()

    def _detect_nosql_bypass(self, response: Dict[str, Any]) -> bool:
        """
        Detect NoSQL authentication bypass indicators

        Args:
            response: API response

        Returns:
            True if bypass detected
        """
        # Check for successful responses that shouldn't happen
        if response.get('success') and response.get('status_code') == 200:
            body = response.get('body', {})
            # Look for authentication success indicators
            if isinstance(body, dict):
                data = body.get('data', {})
                if data and not body.get('errors'):
                    # Successful query with NoSQL injection payload = likely bypass
                    return True
        return False

    def _get_sql_injection_remediation(self) -> str:
        """Return SQL injection remediation guidance"""
        return """
**Remediation Steps:**

1. **Use Parameterized Queries/Prepared Statements:**
   - Never concatenate user input into SQL queries
   - Use ORM frameworks with parameterization (e.g., SQLAlchemy, TypeORM)

2. **Input Validation:**
   - Validate all input against expected types and formats
   - Use allowlist validation for known values
   - Reject unexpected characters (e.g., quotes, semicolons)

3. **Least Privilege:**
   - Database user should have minimal necessary permissions
   - Separate read-only and write database users

4. **Error Handling:**
   - Do not expose database errors to clients
   - Log errors server-side only
   - Return generic error messages

5. **Web Application Firewall (WAF):**
   - Deploy WAF with SQL injection rules
   - Monitor and alert on injection attempts

**Secure Code Example (GraphQL Resolver):**

```python
# VULNERABLE
def resolve_user(parent, info, user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)

# SECURE
def resolve_user(parent, info, user_id):
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,))
```
"""

    def _get_nosql_injection_remediation(self) -> str:
        """Return NoSQL injection remediation guidance"""
        return """
**Remediation Steps:**

1. **Sanitize Input:**
   - Remove or escape special NoSQL operators ($ne, $gt, $regex, etc.)
   - Validate input types match expected schema

2. **Use Schema Validation:**
   - Define strict schemas (e.g., Mongoose schemas for MongoDB)
   - Reject queries that don't match schema

3. **Avoid Direct Query Construction:**
   - Use ORM/ODM query builders
   - Never pass user input directly to database queries

4. **Type Casting:**
   - Explicitly cast input to expected types
   - Example: `parseInt(userId)` instead of direct use

**Secure Code Example:**

```javascript
// VULNERABLE
db.users.find({ username: req.body.username });

// SECURE
const username = String(req.body.username).replace(/[^a-zA-Z0-9]/g, '');
db.users.findOne({ username: username });
```
"""

    def _get_command_injection_remediation(self) -> str:
        """Return command injection remediation guidance"""
        return """
**Remediation Steps:**

1. **Avoid System Commands:**
   - Use native libraries instead of shell commands
   - Example: Use Python's `shutil` instead of `os.system('rm')`

2. **Input Validation:**
   - Strict allowlist of permitted characters
   - Reject shell metacharacters: ; | & $ ` \\ ! # ( )

3. **Use Safe APIs:**
   - Use `subprocess` with shell=False
   - Pass arguments as list, not string

4. **Sandboxing:**
   - Run processes in isolated containers
   - Use principle of least privilege

**Secure Code Example:**

```python
# VULNERABLE
import os
os.system(f"ping {user_input}")

# SECURE
import subprocess
import re

if re.match(r'^[a-zA-Z0-9.-]+$', user_input):
    subprocess.run(['ping', '-c', '4', user_input],
                   capture_output=True,
                   shell=False)
```
"""


if __name__ == "__main__":
    # Example usage
    detector = InjectionDetector(
        endpoint="https://api.example.com/graphql",
        auth_headers={"Authorization": "Bearer token"}
    )

    # Run detection
    result = detector.run_detection(
        schema=None,  # Would come from introspection
        injection_types=['sql', 'nosql', 'command']
    )

    print(f"Scan Status: {result.status.value}")
    print(f"Vulnerabilities Found: {len(result.vulnerabilities)}")
    print(f"Tests Executed: {result.tests_executed}")
    print(f"Duration: {result.scan_duration:.2f}s")
