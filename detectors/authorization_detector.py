"""
Authorization Vulnerability Detector
Detects IDOR, Broken Object Level Authorization, and Privilege Escalation.

Author: Security Research Team
Version: 1.0.0
"""

import re
import json
import random
from typing import Dict, List, Optional, Any, Tuple
from loguru import logger
from dataclasses import dataclass

from core.vulnerability_scanner import (
    BaseVulnerabilityDetector,
    VulnerabilityCategory
)


@dataclass
class IDORTestResult:
    """Result of IDOR enumeration test"""
    object_id: Any
    accessible: bool
    response_data: Dict[str, Any]
    fields_exposed: List[str]
    belongs_to_current_user: bool
    sensitivity_score: float


class AuthorizationDetector(BaseVulnerabilityDetector):
    """
    Detects authorization vulnerabilities:
    - IDOR (Insecure Direct Object References)
    - Broken Object Level Authorization (BOLA)
    - Broken Function Level Authorization (BFLA)
    - Privilege Escalation (Horizontal and Vertical)
    """

    def get_detector_name(self) -> str:
        return "Authorization Vulnerability Detector"

    def get_vulnerability_category(self) -> VulnerabilityCategory:
        return VulnerabilityCategory.BROKEN_OBJECT_LEVEL_AUTH

    def detect(
        self,
        schema: Optional[Dict[str, Any]] = None,
        current_user_id: Optional[str] = None,
        test_user_ids: Optional[List[str]] = None,
        test_fields: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Execute authorization vulnerability detection

        Args:
            schema: GraphQL schema from introspection
            current_user_id: Current authenticated user ID
            test_user_ids: List of other user IDs to test access
            test_fields: Specific fields to test

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []

        logger.info("Starting authorization vulnerability detection")

        # Extract testable fields
        fields_to_test = self._extract_object_access_fields(schema, test_fields)

        logger.info(f"Testing {len(fields_to_test)} fields for authorization issues")

        # Test IDOR vulnerabilities
        for field_info in fields_to_test:
            idor_vulns = self._test_idor(
                field_info,
                current_user_id,
                test_user_ids
            )
            vulnerabilities.extend(idor_vulns)

        # Test function-level authorization
        mutation_vulns = self._test_function_level_auth(schema)
        vulnerabilities.extend(mutation_vulns)

        # Test privilege escalation
        privesc_vulns = self._test_privilege_escalation(schema)
        vulnerabilities.extend(privesc_vulns)

        logger.success(f"Authorization detection complete: {len(vulnerabilities)} vulnerabilities found")
        return vulnerabilities

    def _extract_object_access_fields(
        self,
        schema: Optional[Dict[str, Any]],
        specific_fields: Optional[List[str]]
    ) -> List[Dict[str, Any]]:
        """
        Extract fields that access objects by ID (potential IDOR targets)

        Args:
            schema: GraphQL schema
            specific_fields: Specific fields to test

        Returns:
            List of field information dictionaries
        """
        object_fields = []

        if not schema:
            # Default common object access patterns
            common_patterns = [
                {'name': 'user', 'args': [{'name': 'id', 'type': 'ID'}]},
                {'name': 'post', 'args': [{'name': 'id', 'type': 'ID'}]},
                {'name': 'order', 'args': [{'name': 'id', 'type': 'ID'}]},
                {'name': 'profile', 'args': [{'name': 'userId', 'type': 'ID'}]},
                {'name': 'account', 'args': [{'name': 'accountId', 'type': 'ID'}]},
            ]
            return [f for f in common_patterns if not specific_fields or f['name'] in specific_fields]

        # Extract from schema
        for query in schema.get('queries', []):
            if specific_fields and query['name'] not in specific_fields:
                continue

            # Look for fields that take ID arguments
            id_args = [
                arg for arg in query.get('args', [])
                if 'ID' in arg.get('type', '') or 'id' in arg.get('name', '').lower()
            ]

            if id_args:
                object_fields.append({
                    'name': query['name'],
                    'type': query.get('type'),
                    'args': id_args,
                    'description': query.get('description', '')
                })

        return object_fields

    def _test_idor(
        self,
        field_info: Dict[str, Any],
        current_user_id: Optional[str],
        test_user_ids: Optional[List[str]]
    ) -> List[Dict[str, Any]]:
        """
        Test field for IDOR vulnerabilities

        Args:
            field_info: Field information (name, args, type)
            current_user_id: Current user's ID
            test_user_ids: Other user IDs to test

        Returns:
            List of IDOR vulnerabilities
        """
        vulnerabilities = []
        field_name = field_info['name']
        id_args = field_info.get('args', [])

        if not id_args:
            return vulnerabilities

        logger.debug(f"Testing {field_name} for IDOR vulnerabilities")

        # Get the ID argument name
        id_arg = id_args[0]
        id_arg_name = id_arg['name']

        # Generate test IDs if not provided
        if not test_user_ids:
            # Try sequential IDs
            test_user_ids = self._generate_test_ids(current_user_id)

        # Test access to other users' objects
        accessible_objects = []
        test_results = []

        for test_id in test_user_ids:
            result = self._test_object_access(
                field_name,
                id_arg_name,
                test_id,
                current_user_id
            )
            test_results.append(result)

            if result.accessible and not result.belongs_to_current_user:
                accessible_objects.append(result)
                logger.warning(
                    f"IDOR detected: Can access {field_name} with ID {test_id} "
                    f"(belongs to different user)"
                )

        # Calculate IDOR probability
        total_tests = len(test_results)
        successful_unauthorized = len(accessible_objects)

        if successful_unauthorized > 0:
            idor_probability = successful_unauthorized / total_tests if total_tests > 0 else 0

            # Calculate average sensitivity of exposed data
            avg_sensitivity = sum(r.sensitivity_score for r in accessible_objects) / len(accessible_objects)

            vuln = self.create_vulnerability(
                name="Insecure Direct Object Reference (IDOR)",
                severity=self._classify_idor_severity(successful_unauthorized, avg_sensitivity),
                cvss_score=self._calculate_idor_cvss(successful_unauthorized, avg_sensitivity),
                description=f"IDOR vulnerability detected in field '{field_name}'. "
                           f"Successfully accessed {successful_unauthorized} objects belonging to other users "
                           f"(tested {total_tests} IDs, {idor_probability*100:.1f}% success rate).",
                evidence={
                    'field': field_name,
                    'argument': id_arg_name,
                    'total_tests': total_tests,
                    'successful_unauthorized_access': successful_unauthorized,
                    'idor_probability': idor_probability,
                    'average_sensitivity': avg_sensitivity,
                    'sample_accessible_objects': [
                        {
                            'id': r.object_id,
                            'fields_exposed': r.fields_exposed,
                            'sensitivity': r.sensitivity_score
                        }
                        for r in accessible_objects[:5]  # First 5 examples
                    ]
                },
                cwe_id="CWE-639",
                remediation=self._get_idor_remediation(),
                affected_field=f"{field_name}.{id_arg_name}",
                business_impact=f"Users can access {successful_unauthorized}+ objects belonging to other users. "
                               f"Average data sensitivity: {avg_sensitivity:.1f}/10.0"
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _test_object_access(
        self,
        field_name: str,
        id_arg_name: str,
        object_id: Any,
        current_user_id: Optional[str]
    ) -> IDORTestResult:
        """
        Test access to a specific object ID

        Args:
            field_name: GraphQL field name
            id_arg_name: ID argument name
            object_id: Object ID to test
            current_user_id: Current user's ID

        Returns:
            IDORTestResult with access information
        """
        # Build GraphQL query to fetch object
        query = f"""
        query {{
          {field_name}({id_arg_name}: "{object_id}") {{
            __typename
            ... on Node {{
              id
            }}
          }}
        }}
        """

        # Try to get all fields (introspection of return type would be better)
        # For simplicity, use __typename and id
        response = self.execute_graphql_query(query)

        accessible = False
        fields_exposed = []
        belongs_to_current_user = False

        if response.get('success') and response.get('status_code') == 200:
            body = response.get('body', {})
            data = body.get('data', {})

            if data and data.get(field_name):
                accessible = True
                object_data = data[field_name]

                # Extract exposed fields
                if isinstance(object_data, dict):
                    fields_exposed = list(object_data.keys())

                    # Check ownership
                    owner_id = object_data.get('userId') or object_data.get('ownerId') or object_data.get('createdBy')
                    if owner_id and current_user_id:
                        belongs_to_current_user = (str(owner_id) == str(current_user_id))

        sensitivity_score = self._calculate_data_sensitivity(fields_exposed, response)

        return IDORTestResult(
            object_id=object_id,
            accessible=accessible,
            response_data=response,
            fields_exposed=fields_exposed,
            belongs_to_current_user=belongs_to_current_user,
            sensitivity_score=sensitivity_score
        )

    def _generate_test_ids(self, current_user_id: Optional[str], count: int = 20) -> List[str]:
        """
        Generate test IDs for IDOR enumeration

        Args:
            current_user_id: Current user ID (for pattern detection)
            count: Number of IDs to generate

        Returns:
            List of test IDs
        """
        test_ids = []

        # Try to detect ID pattern
        if current_user_id:
            # Numeric IDs
            if current_user_id.isdigit():
                user_num = int(current_user_id)
                # Test sequential IDs
                for i in range(max(1, user_num - 10), user_num + 10):
                    if i != user_num:
                        test_ids.append(str(i))

            # UUID-like IDs
            elif len(current_user_id) > 20 and '-' in current_user_id:
                # Generate random UUIDs
                import uuid
                test_ids = [str(uuid.uuid4()) for _ in range(count)]

            # Alphanumeric IDs
            else:
                # Try incrementing/decrementing
                test_ids = [
                    current_user_id[:-1] + chr((ord(current_user_id[-1]) + i) % 128)
                    for i in range(-5, 6) if i != 0
                ]
        else:
            # Default: sequential numeric IDs
            test_ids = [str(i) for i in range(1, count + 1)]

        return test_ids[:count]

    def _calculate_data_sensitivity(
        self,
        fields_exposed: List[str],
        response: Dict[str, Any]
    ) -> float:
        """
        Calculate sensitivity score for exposed data

        Args:
            fields_exposed: List of exposed field names
            response: Full API response

        Returns:
            Sensitivity score (0.0-10.0)
        """
        sensitivity = 0.0

        # Sensitive field patterns
        high_sensitivity_patterns = [
            r'password', r'secret', r'token', r'api[_-]?key',
            r'ssn', r'credit[_-]?card', r'cvv', r'account[_-]?number'
        ]

        medium_sensitivity_patterns = [
            r'email', r'phone', r'address', r'salary', r'dob',
            r'birth[_-]?date', r'medical', r'health'
        ]

        low_sensitivity_patterns = [
            r'name', r'age', r'gender', r'city', r'country'
        ]

        for field in fields_exposed:
            field_lower = field.lower()

            if any(re.search(p, field_lower) for p in high_sensitivity_patterns):
                sensitivity += 3.0
            elif any(re.search(p, field_lower) for p in medium_sensitivity_patterns):
                sensitivity += 1.5
            elif any(re.search(p, field_lower) for p in low_sensitivity_patterns):
                sensitivity += 0.5

        # Check response content for sensitive data patterns
        response_text = json.dumps(response).lower()
        if re.search(r'\b\d{3}-\d{2}-\d{4}\b', response_text):  # SSN
            sensitivity += 5.0
        if re.search(r'\b\d{16}\b', response_text):  # Credit card
            sensitivity += 5.0

        return min(sensitivity, 10.0)

    def _classify_idor_severity(
        self,
        successful_access_count: int,
        avg_sensitivity: float
    ) -> str:
        """Classify IDOR severity based on impact"""
        if avg_sensitivity >= 7.0 or successful_access_count > 10:
            return "CRITICAL"
        elif avg_sensitivity >= 4.0 or successful_access_count > 5:
            return "HIGH"
        elif avg_sensitivity >= 2.0:
            return "MEDIUM"
        else:
            return "LOW"

    def _calculate_idor_cvss(
        self,
        successful_access_count: int,
        avg_sensitivity: float
    ) -> float:
        """Calculate CVSS score for IDOR vulnerability"""
        base_score = 5.0

        # Increase based on sensitivity
        score = base_score + (avg_sensitivity * 0.3)

        # Increase based on ease of exploitation (more successful = easier)
        if successful_access_count > 10:
            score += 1.5
        elif successful_access_count > 5:
            score += 1.0

        return min(score, 10.0)

    def _test_function_level_auth(
        self,
        schema: Optional[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Test for broken function-level authorization (accessing admin mutations)

        Args:
            schema: GraphQL schema

        Returns:
            List of function-level auth vulnerabilities
        """
        vulnerabilities = []

        if not schema:
            return vulnerabilities

        # Look for admin/privileged mutations
        admin_patterns = [
            r'delete', r'remove', r'admin', r'ban', r'promote',
            r'elevate', r'grant', r'revoke', r'disable', r'enable'
        ]

        mutations = schema.get('mutations', [])
        potentially_privileged = []

        for mutation in mutations:
            mutation_name = mutation['name']
            if any(re.search(pattern, mutation_name, re.IGNORECASE) for pattern in admin_patterns):
                potentially_privileged.append(mutation)

        logger.info(f"Testing {len(potentially_privileged)} potentially privileged mutations")

        # Test each privileged mutation without admin credentials
        for mutation in potentially_privileged:
            mutation_name = mutation['name']
            args = mutation.get('args', [])

            # Build test mutation
            arg_values = []
            for arg in args[:3]:  # Test first 3 args
                arg_name = arg['name']
                arg_type = arg.get('type', 'String')

                # Generate test value based on type
                if 'ID' in arg_type or 'Int' in arg_type:
                    test_value = '1'
                elif 'Boolean' in arg_type:
                    test_value = 'true'
                else:
                    test_value = '"test"'

                arg_values.append(f'{arg_name}: {test_value}')

            mutation_query = f"""
            mutation {{
              {mutation_name}({', '.join(arg_values)}) {{
                __typename
              }}
            }}
            """

            response = self.execute_graphql_query(mutation_query)

            # Check if mutation succeeded without proper authorization
            if response.get('success') and response.get('status_code') == 200:
                body = response.get('body', {})
                if body.get('data') and not body.get('errors'):
                    logger.warning(f"Privileged mutation {mutation_name} accessible without admin auth")

                    vuln = self.create_vulnerability(
                        name="Broken Function Level Authorization",
                        severity="HIGH",
                        cvss_score=8.1,
                        description=f"Privileged mutation '{mutation_name}' is accessible without "
                                   f"proper authorization checks.",
                        evidence={
                            'mutation': mutation_name,
                            'args': args,
                            'response': body
                        },
                        cwe_id="CWE-284",
                        remediation=self._get_function_level_auth_remediation(),
                        affected_field=mutation_name
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _test_privilege_escalation(
        self,
        schema: Optional[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Test for privilege escalation vulnerabilities

        Args:
            schema: GraphQL schema

        Returns:
            List of privilege escalation vulnerabilities
        """
        vulnerabilities = []

        # Test role manipulation
        role_fields = ['role', 'isAdmin', 'permissions', 'privileges']

        mutations = schema.get('mutations', []) if schema else []

        for mutation in mutations:
            mutation_name = mutation['name']
            args = mutation.get('args', [])

            # Check if mutation has role-related arguments
            role_args = [
                arg for arg in args
                if any(role_field in arg.get('name', '').lower() for role_field in role_fields)
            ]

            if role_args:
                # Try to set admin role
                for role_arg in role_args:
                    arg_name = role_arg['name']

                    test_values = ['admin', 'administrator', 'root', 'superuser']

                    for test_value in test_values:
                        mutation_query = f"""
                        mutation {{
                          {mutation_name}({arg_name}: "{test_value}") {{
                            __typename
                          }}
                        }}
                        """

                        response = self.execute_graphql_query(mutation_query)

                        if response.get('success') and response.get('status_code') == 200:
                            body = response.get('body', {})
                            if body.get('data') and not body.get('errors'):
                                logger.critical(
                                    f"Privilege escalation possible via {mutation_name}.{arg_name}"
                                )

                                vuln = self.create_vulnerability(
                                    name="Privilege Escalation",
                                    severity="CRITICAL",
                                    cvss_score=9.1,
                                    description=f"Privilege escalation vulnerability: Regular users can "
                                               f"elevate privileges via '{mutation_name}' mutation.",
                                    evidence={
                                        'mutation': mutation_name,
                                        'argument': arg_name,
                                        'test_value': test_value,
                                        'response': body
                                    },
                                    cwe_id="CWE-269",
                                    remediation=self._get_privilege_escalation_remediation(),
                                    affected_field=f"{mutation_name}.{arg_name}",
                                    business_impact="Critical - Regular users can gain administrative access"
                                )
                                vulnerabilities.append(vuln)
                                break  # One vuln per mutation is enough

        return vulnerabilities

    def _get_idor_remediation(self) -> str:
        """Return IDOR remediation guidance"""
        return """
**Remediation Steps:**

1. **Implement Object Ownership Verification:**
   - Always verify that the requesting user owns/has access to the requested object
   - Check ownership before returning any data

2. **Use Indirect Object References:**
   - Instead of exposing database IDs, use random tokens or UUIDs
   - Map user sessions to allowed object IDs server-side

3. **Field-Level Authorization:**
   - Implement authorization checks at the resolver level
   - Use GraphQL directives like @auth or @requiresOwnership

4. **Audit Logging:**
   - Log all object access attempts
   - Monitor for unusual access patterns

**Secure Code Example:**

```python
# VULNERABLE
def resolve_user(parent, info, user_id):
    return db.query(User).filter(User.id == user_id).first()

# SECURE
def resolve_user(parent, info, user_id):
    current_user = info.context.user
    user = db.query(User).filter(User.id == user_id).first()

    # Verify authorization
    if user and user.id != current_user.id and not current_user.is_admin:
        raise AuthorizationError("Cannot access other user's data")

    return user
```
"""

    def _get_function_level_auth_remediation(self) -> str:
        """Return function-level auth remediation guidance"""
        return """
**Remediation Steps:**

1. **Implement Role-Based Access Control (RBAC):**
   - Define roles and permissions clearly
   - Check user roles before executing privileged operations

2. **Use Authorization Middleware:**
   - Apply authorization checks at the schema level
   - Use directives like @requiresRole("admin")

3. **Principle of Least Privilege:**
   - Grant minimum necessary permissions by default
   - Require explicit privilege grants for sensitive operations

4. **Testing:**
   - Test all mutations with different user roles
   - Ensure lower-privileged users cannot access admin functions

**Secure Code Example:**

```python
# GraphQL Schema with Authorization
type Mutation {
  deleteUser(id: ID!): User @requiresRole(role: "admin")
  banUser(userId: ID!): Boolean @requiresRole(role: "moderator")
}

# Resolver with authorization
def resolve_delete_user(parent, info, id):
    current_user = info.context.user

    if current_user.role != "admin":
        raise AuthorizationError("Admin role required")

    return db.delete_user(id)
```
"""

    def _get_privilege_escalation_remediation(self) -> str:
        """Return privilege escalation remediation guidance"""
        return """
**Remediation Steps:**

1. **Restrict Role Modification:**
   - Only allow administrators to modify user roles
   - Verify current user has sufficient privileges before role changes

2. **Server-Side Validation:**
   - Never trust client-provided role/permission values
   - Validate all role changes server-side

3. **Audit Trail:**
   - Log all role/permission changes
   - Alert on suspicious privilege modifications

4. **Separation of Duties:**
   - Require multiple approvals for privilege escalation
   - Implement time-limited elevated privileges

**Secure Code Example:**

```python
# VULNERABLE
def resolve_update_user(parent, info, user_id, role):
    user = db.get_user(user_id)
    user.role = role  # Anyone can set any role!
    return user

# SECURE
def resolve_update_user(parent, info, user_id, role):
    current_user = info.context.user

    # Only admins can change roles
    if current_user.role != "admin":
        raise AuthorizationError("Insufficient privileges")

    # Prevent self-demotion
    if user_id == current_user.id and role != "admin":
        raise ValueError("Cannot demote yourself")

    # Audit log
    audit_log.record(f"Admin {current_user.id} changed user {user_id} role to {role}")

    user = db.get_user(user_id)
    user.role = role
    return user
```
"""


if __name__ == "__main__":
    # Example usage
    detector = AuthorizationDetector(
        endpoint="https://api.example.com/graphql",
        auth_headers={"Authorization": "Bearer user_token"}
    )

    result = detector.run_detection(
        current_user_id="123",
        test_user_ids=["1", "2", "3", "456", "789"]
    )

    print(f"Scan Status: {result.status.value}")
    print(f"Vulnerabilities: {len(result.vulnerabilities)}")
