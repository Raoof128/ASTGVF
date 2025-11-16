"""
Authentication Vulnerability Detector
Detects JWT vulnerabilities, token issues, and authentication bypass.

Author: Security Research Team
Version: 1.0.0
"""

import re
import json
import base64
import jwt
from typing import Dict, List, Optional, Any
from loguru import logger
from datetime import datetime, timedelta

from core.vulnerability_scanner import (
    BaseVulnerabilityDetector,
    VulnerabilityCategory
)


class AuthenticationDetector(BaseVulnerabilityDetector):
    """
    Detects authentication vulnerabilities:
    - JWT algorithm confusion (None algorithm, RS256 to HS256)
    - Weak JWT secrets
    - JWT expiration issues
    - Token tampering
    - Authentication bypass
    - Missing authentication on sensitive endpoints
    """

    def get_detector_name(self) -> str:
        return "Authentication Vulnerability Detector"

    def get_vulnerability_category(self) -> VulnerabilityCategory:
        return VulnerabilityCategory.BROKEN_AUTHENTICATION

    def detect(
        self,
        schema: Optional[Dict[str, Any]] = None,
        current_token: Optional[str] = None,
        test_mutations: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Execute authentication vulnerability detection

        Args:
            schema: GraphQL schema
            current_token: Current JWT token (if available)
            test_mutations: Whether to test mutations for auth requirements

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []

        logger.info("Starting authentication vulnerability detection")

        # Test JWT vulnerabilities if token is provided
        if current_token and 'Bearer ' not in current_token:
            current_token = f"Bearer {current_token}"

        if current_token:
            jwt_token = current_token.replace('Bearer ', '').replace('bearer ', '')
            jwt_vulns = self._test_jwt_vulnerabilities(jwt_token)
            vulnerabilities.extend(jwt_vulns)

        # Test authentication bypass
        bypass_vulns = self._test_authentication_bypass(schema)
        vulnerabilities.extend(bypass_vulns)

        # Test missing authentication on mutations
        if test_mutations:
            unauth_vulns = self._test_unauthenticated_mutations(schema)
            vulnerabilities.extend(unauth_vulns)

        logger.success(f"Authentication detection complete: {len(vulnerabilities)} vulnerabilities found")
        return vulnerabilities

    def _test_jwt_vulnerabilities(self, token: str) -> List[Dict[str, Any]]:
        """
        Test JWT token for various vulnerabilities

        Args:
            token: JWT token string

        Returns:
            List of JWT vulnerabilities
        """
        vulnerabilities = []

        logger.debug("Analyzing JWT token for vulnerabilities")

        # Decode JWT header and payload (without verification)
        try:
            header = self._decode_jwt_part(token, part=0)
            payload = self._decode_jwt_part(token, part=1)

            logger.info(f"JWT Header: {header}")
            logger.info(f"JWT Algorithm: {header.get('alg')}")

            # Test 1: None algorithm attack
            none_alg_vuln = self._test_none_algorithm_attack(token, header, payload)
            if none_alg_vuln:
                vulnerabilities.append(none_alg_vuln)

            # Test 2: Algorithm confusion (RS256 to HS256)
            alg_confusion_vuln = self._test_algorithm_confusion(token, header, payload)
            if alg_confusion_vuln:
                vulnerabilities.append(alg_confusion_vuln)

            # Test 3: Weak secret brute force
            weak_secret_vuln = self._test_weak_jwt_secret(token)
            if weak_secret_vuln:
                vulnerabilities.append(weak_secret_vuln)

            # Test 4: Token expiration issues
            expiration_vuln = self._test_token_expiration(payload)
            if expiration_vuln:
                vulnerabilities.append(expiration_vuln)

            # Test 5: Sensitive data in JWT
            sensitive_data_vuln = self._test_sensitive_data_in_jwt(payload)
            if sensitive_data_vuln:
                vulnerabilities.append(sensitive_data_vuln)

            # Test 6: JWT signature verification bypass
            sig_bypass_vuln = self._test_signature_verification_bypass(token)
            if sig_bypass_vuln:
                vulnerabilities.append(sig_bypass_vuln)

        except Exception as e:
            logger.error(f"Error analyzing JWT: {e}")
            self.errors.append(f"JWT analysis error: {e}")

        return vulnerabilities

    def _decode_jwt_part(self, token: str, part: int) -> Dict[str, Any]:
        """
        Decode JWT header (part=0) or payload (part=1)

        Args:
            token: JWT token
            part: 0 for header, 1 for payload

        Returns:
            Decoded JWT part as dictionary
        """
        parts = token.split('.')
        if len(parts) < 2:
            raise ValueError("Invalid JWT format")

        # Add padding if needed
        encoded = parts[part]
        padding = 4 - len(encoded) % 4
        if padding != 4:
            encoded += '=' * padding

        decoded = base64.urlsafe_b64decode(encoded)
        return json.loads(decoded)

    def _test_none_algorithm_attack(
        self,
        token: str,
        header: Dict[str, Any],
        payload: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Test if API accepts JWT with 'none' algorithm

        Args:
            token: Original JWT token
            header: JWT header
            payload: JWT payload

        Returns:
            Vulnerability if detected, None otherwise
        """
        logger.debug("Testing 'none' algorithm attack")

        # Create JWT with 'none' algorithm
        none_header = {**header, 'alg': 'none'}

        # Encode header and payload
        encoded_header = base64.urlsafe_b64encode(
            json.dumps(none_header).encode()
        ).decode().rstrip('=')

        encoded_payload = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip('=')

        # Create unsigned token (no signature)
        none_token = f"{encoded_header}.{encoded_payload}."

        # Test if API accepts this token
        test_headers = {'Authorization': f'Bearer {none_token}'}
        original_headers = self.auth_headers
        self.auth_headers = test_headers

        # Try a simple query
        query = "{ __typename }"
        response = self.execute_graphql_query(query)

        self.auth_headers = original_headers  # Restore

        # Check if request succeeded
        if response.get('success') and response.get('status_code') == 200:
            logger.critical("API accepts JWT with 'none' algorithm - Critical vulnerability!")

            return self.create_vulnerability(
                name="JWT None Algorithm Accepted",
                severity="CRITICAL",
                cvss_score=9.8,
                description="API accepts JWT tokens with 'none' algorithm, allowing attackers to "
                           "forge unsigned tokens and bypass authentication completely.",
                evidence={
                    'original_algorithm': header.get('alg'),
                    'attack_token': none_token[:50] + '...',
                    'response_status': response.get('status_code'),
                    'authentication_bypassed': True
                },
                cwe_id="CWE-347",
                remediation=self._get_jwt_none_algorithm_remediation(),
                exploitation_difficulty="Easy",
                business_impact="Critical - Complete authentication bypass"
            )

        return None

    def _test_algorithm_confusion(
        self,
        token: str,
        header: Dict[str, Any],
        payload: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Test RS256 to HS256 algorithm confusion attack

        Args:
            token: Original JWT token
            header: JWT header
            payload: JWT payload

        Returns:
            Vulnerability if detected, None otherwise
        """
        if header.get('alg') != 'RS256':
            return None

        logger.debug("Testing RS256 to HS256 algorithm confusion")

        # Try to create HS256 token using common secrets
        common_secrets = ['secret', 'password', '123456', 'jwt_secret', 'key']

        for secret in common_secrets:
            try:
                confused_header = {**header, 'alg': 'HS256'}

                confused_token = jwt.encode(
                    payload,
                    secret,
                    algorithm='HS256',
                    headers=confused_header
                )

                # Test if API accepts this token
                test_headers = {'Authorization': f'Bearer {confused_token}'}
                original_headers = self.auth_headers
                self.auth_headers = test_headers

                query = "{ __typename }"
                response = self.execute_graphql_query(query)

                self.auth_headers = original_headers

                if response.get('success') and response.get('status_code') == 200:
                    logger.critical(
                        f"Algorithm confusion successful with secret: {secret}"
                    )

                    return self.create_vulnerability(
                        name="JWT Algorithm Confusion (RS256 to HS256)",
                        severity="CRITICAL",
                        cvss_score=9.1,
                        description="API vulnerable to RS256 to HS256 algorithm confusion attack. "
                                   f"Successfully forged token using secret: '{secret}'",
                        evidence={
                            'original_algorithm': 'RS256',
                            'confused_algorithm': 'HS256',
                            'secret_used': secret,
                            'attack_successful': True
                        },
                        cwe_id="CWE-347",
                        remediation=self._get_algorithm_confusion_remediation(),
                        business_impact="Critical - Authentication bypass via algorithm confusion"
                    )

            except Exception as e:
                logger.debug(f"Algorithm confusion test failed for secret '{secret}': {e}")

        return None

    def _test_weak_jwt_secret(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Test JWT for weak secrets using common wordlist

        Args:
            token: JWT token

        Returns:
            Vulnerability if weak secret detected
        """
        logger.debug("Testing for weak JWT secrets")

        # Common weak secrets
        weak_secrets = [
            'secret', 'password', '123456', 'qwerty', 'abc123',
            'letmein', 'monkey', 'password1', 'jwt', 'jwt_secret',
            'secret_key', 'my_secret', 'api_secret', 'token_secret'
        ]

        for secret in weak_secrets:
            try:
                # Try to verify with this secret
                decoded = jwt.decode(
                    token,
                    secret,
                    algorithms=['HS256', 'HS384', 'HS512'],
                    options={"verify_signature": True}
                )

                logger.critical(f"Weak JWT secret found: {secret}")

                return self.create_vulnerability(
                    name="Weak JWT Secret",
                    severity="CRITICAL",
                    cvss_score=9.1,
                    description=f"JWT is signed with weak/common secret: '{secret}'. "
                               "Attackers can forge arbitrary tokens.",
                    evidence={
                        'weak_secret': secret,
                        'decoded_payload': decoded,
                        'brute_force_difficulty': 'Trivial'
                    },
                    cwe_id="CWE-798",
                    remediation=self._get_weak_secret_remediation(),
                    business_impact="Critical - Attackers can forge authentication tokens"
                )

            except jwt.exceptions.InvalidSignatureError:
                continue
            except Exception as e:
                logger.debug(f"Secret test error for '{secret}': {e}")

        return None

    def _test_token_expiration(self, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Test JWT expiration configuration

        Args:
            payload: JWT payload

        Returns:
            Vulnerability if expiration issues detected
        """
        exp = payload.get('exp')
        iat = payload.get('iat')

        issues = []

        # Check if expiration is set
        if not exp:
            issues.append("No expiration time (exp) set - token never expires")

        # Check if issued-at is set
        if not iat:
            issues.append("No issued-at time (iat) set")

        # Check expiration duration
        if exp and iat:
            duration = exp - iat
            duration_days = duration / (60 * 60 * 24)

            if duration_days > 365:
                issues.append(f"Excessive expiration: {duration_days:.1f} days")
            elif duration_days > 90:
                issues.append(f"Long expiration: {duration_days:.1f} days (consider reducing)")

        if issues:
            severity = "HIGH" if "never expires" in str(issues) else "MEDIUM"
            cvss = 7.5 if severity == "HIGH" else 5.3

            return self.create_vulnerability(
                name="JWT Expiration Issues",
                severity=severity,
                cvss_score=cvss,
                description="JWT token has expiration configuration issues.",
                evidence={
                    'issues': issues,
                    'exp': exp,
                    'iat': iat,
                    'current_time': int(datetime.utcnow().timestamp())
                },
                cwe_id="CWE-613",
                remediation="""
Set appropriate JWT expiration:
- Access tokens: 15-60 minutes
- Refresh tokens: 7-30 days
- Always set 'exp' claim
- Implement token refresh mechanism
"""
            )

        return None

    def _test_sensitive_data_in_jwt(self, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check for sensitive data in JWT payload

        Args:
            payload: JWT payload

        Returns:
            Vulnerability if sensitive data detected
        """
        sensitive_keys = [
            'password', 'secret', 'api_key', 'private_key',
            'ssn', 'credit_card', 'cvv', 'account_number'
        ]

        found_sensitive = []

        for key, value in payload.items():
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                found_sensitive.append(key)

        if found_sensitive:
            return self.create_vulnerability(
                name="Sensitive Data in JWT",
                severity="MEDIUM",
                cvss_score=5.3,
                description=f"JWT contains sensitive data in claims: {', '.join(found_sensitive)}. "
                           "JWTs are only base64-encoded, not encrypted.",
                evidence={
                    'sensitive_claims': found_sensitive,
                    'payload_keys': list(payload.keys())
                },
                cwe_id="CWE-311",
                remediation="""
Remove sensitive data from JWT payload:
- Store sensitive data server-side only
- Reference data by ID in JWT
- Use encrypted JWT (JWE) if sensitive data is required
- Never store passwords, secrets, or PII in JWT
"""
            )

        return None

    def _test_signature_verification_bypass(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Test if API verifies JWT signature

        Args:
            token: Original JWT token

        Returns:
            Vulnerability if signature verification is bypassed
        """
        # Tamper with token payload
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None

            # Decode payload
            payload = self._decode_jwt_part(token, part=1)

            # Tamper: change user ID or role
            tampered_payload = {**payload}

            if 'userId' in tampered_payload:
                tampered_payload['userId'] = '999999'
            elif 'sub' in tampered_payload:
                tampered_payload['sub'] = '999999'

            if 'role' in tampered_payload:
                tampered_payload['role'] = 'admin'

            # Create tampered token with same signature (invalid)
            encoded_payload = base64.urlsafe_b64encode(
                json.dumps(tampered_payload).encode()
            ).decode().rstrip('=')

            tampered_token = f"{parts[0]}.{encoded_payload}.{parts[2]}"

            # Test if API accepts tampered token
            test_headers = {'Authorization': f'Bearer {tampered_token}'}
            original_headers = self.auth_headers
            self.auth_headers = test_headers

            query = "{ __typename }"
            response = self.execute_graphql_query(query)

            self.auth_headers = original_headers

            if response.get('success') and response.get('status_code') == 200:
                logger.critical("API does not verify JWT signature - tampered token accepted!")

                return self.create_vulnerability(
                    name="JWT Signature Verification Bypass",
                    severity="CRITICAL",
                    cvss_score=10.0,
                    description="API does not verify JWT signature. Tampered tokens are accepted.",
                    evidence={
                        'original_payload': payload,
                        'tampered_payload': tampered_payload,
                        'attack_successful': True
                    },
                    cwe_id="CWE-347",
                    remediation="""
**CRITICAL FIX REQUIRED:**

Always verify JWT signature:

```python
# VULNERABLE
payload = jwt.decode(token, options={"verify_signature": False})

# SECURE
payload = jwt.decode(token, secret_key, algorithms=["HS256"])
```

Enable signature verification in JWT library configuration.
"""
                )

        except Exception as e:
            logger.debug(f"Signature verification test error: {e}")

        return None

    def _test_authentication_bypass(
        self,
        schema: Optional[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Test for authentication bypass vulnerabilities

        Args:
            schema: GraphQL schema

        Returns:
            List of authentication bypass vulnerabilities
        """
        vulnerabilities = []

        # Test 1: Access without token
        original_headers = self.auth_headers
        self.auth_headers = {}  # No auth

        query = """
        {
          __schema {
            queryType {
              name
            }
          }
        }
        """

        response = self.execute_graphql_query(query)

        if response.get('success'):
            logger.warning("Introspection accessible without authentication")

            vulnerabilities.append(
                self.create_vulnerability(
                    name="Unauthenticated Introspection Access",
                    severity="MEDIUM",
                    cvss_score=5.3,
                    description="GraphQL introspection is accessible without authentication.",
                    evidence={'response': response},
                    cwe_id="CWE-306",
                    remediation="Require authentication for introspection queries."
                )
            )

        self.auth_headers = original_headers

        return vulnerabilities

    def _test_unauthenticated_mutations(
        self,
        schema: Optional[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Test if mutations are accessible without authentication

        Args:
            schema: GraphQL schema

        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []

        if not schema:
            return vulnerabilities

        mutations = schema.get('mutations', [])

        # Test each mutation without auth
        original_headers = self.auth_headers
        self.auth_headers = {}

        for mutation in mutations[:5]:  # Test first 5 mutations
            mutation_name = mutation['name']
            args = mutation.get('args', [])

            # Build test mutation
            arg_values = []
            for arg in args[:2]:
                arg_name = arg['name']
                arg_type = arg.get('type', 'String')

                if 'ID' in arg_type or 'Int' in arg_type:
                    test_value = '1'
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

            if response.get('success') and not response.get('body', {}).get('errors'):
                logger.warning(f"Mutation {mutation_name} accessible without authentication")

                vulnerabilities.append(
                    self.create_vulnerability(
                        name="Unauthenticated Mutation Access",
                        severity="HIGH",
                        cvss_score=7.5,
                        description=f"Mutation '{mutation_name}' is accessible without authentication.",
                        evidence={
                            'mutation': mutation_name,
                            'response': response
                        },
                        cwe_id="CWE-306",
                        remediation="Require authentication for all mutations. "
                                   "Use @auth directives or middleware.",
                        affected_field=mutation_name
                    )
                )

        self.auth_headers = original_headers

        return vulnerabilities

    def _get_jwt_none_algorithm_remediation(self) -> str:
        """Return JWT none algorithm remediation"""
        return """
**CRITICAL REMEDIATION REQUIRED:**

1. **Explicitly Reject 'none' Algorithm:**

```python
# Secure JWT configuration
jwt.decode(
    token,
    secret_key,
    algorithms=["HS256", "RS256"],  # Explicitly list allowed algorithms
    options={
        "verify_signature": True,
        "require": ["exp", "iat", "sub"]
    }
)
```

2. **Never Allow:**
- algorithms=["none"]
- Signature verification bypass
- Client-specified algorithms

3. **Implementation:**
- Use latest JWT library versions
- Set algorithm allowlist explicitly
- Validate algorithm in token header matches expected algorithm
"""

    def _get_algorithm_confusion_remediation(self) -> str:
        """Return algorithm confusion remediation"""
        return """
**Remediation for Algorithm Confusion:**

1. **Strict Algorithm Validation:**

```python
# VULNERABLE
jwt.decode(token, key, algorithms=["HS256", "RS256"])

# SECURE
expected_alg = "RS256"
header = jwt.get_unverified_header(token)

if header.get("alg") != expected_alg:
    raise ValueError(f"Invalid algorithm: {header.get('alg')}")

jwt.decode(token, key, algorithms=[expected_alg])
```

2. **Separate Keys:**
- Use different keys for HS256 and RS256
- Never use public key for HMAC verification
- Store algorithms with keys in configuration

3. **Key Type Verification:**
- Verify key type matches algorithm
- Use cryptographic library type checks
"""

    def _get_weak_secret_remediation(self) -> str:
        """Return weak secret remediation"""
        return """
**Remediation for Weak JWT Secrets:**

1. **Generate Strong Secrets:**
```python
import secrets

# Generate cryptographically secure secret (256 bits)
jwt_secret = secrets.token_urlsafe(32)
```

2. **Minimum Requirements:**
- Length: ≥32 characters (256 bits)
- Use cryptographically secure random generator
- Store in environment variables, not code
- Rotate regularly (every 90 days)

3. **Key Management:**
- Use secret management systems (HashiCorp Vault, AWS Secrets Manager)
- Never commit secrets to version control
- Use different secrets per environment
"""


if __name__ == "__main__":
    # Example usage
    detector = AuthenticationDetector(
        endpoint="https://api.example.com/graphql"
    )

    # Test with sample JWT
    sample_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

    result = detector.run_detection(current_token=sample_token)

    print(f"Authentication vulnerabilities: {len(result.vulnerabilities)}")
