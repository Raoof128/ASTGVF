"""
Remediation Engine
Maps vulnerabilities to CWE/OWASP standards and generates secure code fixes.

Author: Security Research Team
Version: 1.0.0
"""

import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
from loguru import logger


class RemediationPriority(Enum):
    """Remediation priority based on CVSS and business impact"""
    IMMEDIATE = "Immediate (0-24 hours)"
    URGENT = "Urgent (1-7 days)"
    HIGH = "High (1-2 weeks)"
    MEDIUM = "Medium (2-4 weeks)"
    LOW = "Low (1-3 months)"


@dataclass
class RemediationStep:
    """Individual remediation step"""
    step_number: int
    title: str
    description: str
    code_example: Optional[str] = None
    verification_method: Optional[str] = None
    estimated_effort: Optional[str] = None


@dataclass
class RemediationPlan:
    """Complete remediation plan for a vulnerability"""
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


class RemediationEngine:
    """
    Maps vulnerabilities to OWASP/CWE standards.
    Generates secure code fixes and hardening guides.
    """

    # Comprehensive CWE/OWASP/Remediation mappings
    REMEDIATION_DATABASE = {
        'SQL Injection': {
            'cwe': 'CWE-89',
            'owasp': 'A03:2021 – Injection',
            'owasp_api': 'API8:2023 - Security Misconfiguration',
            'cvss_base': 9.8,
            'priority_multiplier': 1.0,
            'remediation_steps': [
                RemediationStep(
                    step_number=1,
                    title="Implement Parameterized Queries",
                    description="Replace all string concatenation in SQL queries with parameterized queries or prepared statements.",
                    code_example="""
# VULNERABLE
query = f"SELECT * FROM users WHERE id = {user_id}"
result = db.execute(query)

# SECURE
query = "SELECT * FROM users WHERE id = ?"
result = db.execute(query, (user_id,))

# GraphQL Resolver (Secure)
def resolve_user(parent, info, user_id: int):
    # Use ORM with parameterization
    return User.query.filter_by(id=user_id).first()
""",
                    verification_method="Run SQL injection scanner against endpoint",
                    estimated_effort="2-4 hours per endpoint"
                ),
                RemediationStep(
                    step_number=2,
                    title="Input Validation and Sanitization",
                    description="Validate all user input against expected types, formats, and ranges.",
                    code_example="""
from typing import Union

def validate_user_id(user_id: Union[str, int]) -> int:
    try:
        uid = int(user_id)
        if uid < 1 or uid > 999999999:
            raise ValueError("Invalid user ID range")
        return uid
    except (ValueError, TypeError):
        raise ValueError("Invalid user ID format")

# In resolver
def resolve_user(parent, info, user_id):
    validated_id = validate_user_id(user_id)
    return User.query.get(validated_id)
""",
                    verification_method="Unit tests with malicious inputs",
                    estimated_effort="1-2 hours"
                ),
                RemediationStep(
                    step_number=3,
                    title="Apply Least Privilege to Database Users",
                    description="Database connections should use accounts with minimal necessary permissions.",
                    code_example="""
# Database user permissions (PostgreSQL)
-- Create read-only user for queries
CREATE USER app_reader WITH PASSWORD 'strong_password';
GRANT CONNECT ON DATABASE app_db TO app_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_reader;

-- Create limited write user for mutations
CREATE USER app_writer WITH PASSWORD 'strong_password';
GRANT INSERT, UPDATE ON specific_tables TO app_writer;

-- NEVER grant: DROP, DELETE, TRUNCATE unless absolutely necessary
""",
                    verification_method="Review database user permissions",
                    estimated_effort="1 hour"
                ),
                RemediationStep(
                    step_number=4,
                    title="Implement Error Handling",
                    description="Never expose database errors to clients. Log errors server-side only.",
                    code_example="""
import logging

def resolve_user(parent, info, user_id):
    try:
        validated_id = validate_user_id(user_id)
        return User.query.get(validated_id)
    except ValueError as e:
        # Return generic error to client
        raise GraphQLError("Invalid input")
    except Exception as e:
        # Log detailed error server-side
        logging.error(f"Database error: {e}", exc_info=True)
        # Return generic error to client
        raise GraphQLError("Internal server error")
""",
                    verification_method="Test error responses don't leak database info",
                    estimated_effort="2 hours"
                )
            ],
            'testing_recommendations': [
                "Run automated SQL injection scanner (SQLMap, ASTGVF)",
                "Perform manual testing with payloads: ' OR 1=1--, UNION SELECT, etc.",
                "Verify error messages don't reveal database structure",
                "Test with time-based blind SQL injection payloads",
                "Code review all database queries"
            ],
            'references': [
                "OWASP SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                "CWE-89: https://cwe.mitre.org/data/definitions/89.html",
                "OWASP Top 10 A03:2021: https://owasp.org/Top10/A03_2021-Injection/"
            ],
            'estimated_total_effort': "8-12 hours (varies by codebase size)"
        },

        'NoSQL Injection': {
            'cwe': 'CWE-943',
            'owasp': 'A03:2021 – Injection',
            'owasp_api': 'API8:2023 - Security Misconfiguration',
            'cvss_base': 9.8,
            'priority_multiplier': 1.0,
            'remediation_steps': [
                RemediationStep(
                    step_number=1,
                    title="Sanitize NoSQL Operators",
                    description="Remove or escape special NoSQL operators from user input.",
                    code_example="""
def sanitize_nosql_input(user_input):
    # Remove MongoDB operators
    dangerous_operators = ['$ne', '$gt', '$gte', '$lt', '$lte', '$regex', '$where', '$expr']

    if isinstance(user_input, dict):
        for key in list(user_input.keys()):
            if key.startswith('$'):
                del user_input[key]
        return user_input
    elif isinstance(user_input, str):
        # Escape special characters
        return user_input.replace('$', '\\$').replace('{', '\\{')
    return user_input

# In resolver
def resolve_user(parent, info, username):
    safe_username = sanitize_nosql_input(username)
    return User.find_one({'username': safe_username})
""",
                    verification_method="Test with NoSQL injection payloads",
                    estimated_effort="3-5 hours"
                ),
                RemediationStep(
                    step_number=2,
                    title="Use Schema Validation",
                    description="Define strict schemas and validate input types.",
                    code_example="""
# Mongoose schema with validation
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    match: /^[a-zA-Z0-9_]+$/,  // Only alphanumeric and underscore
    minlength: 3,
    maxlength: 30
  },
  email: {
    type: String,
    required: true,
    match: /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/
  }
});

// Reject documents that don't match schema
userSchema.set('strict', 'throw');
""",
                    verification_method="Attempt to insert invalid data",
                    estimated_effort="2-4 hours per model"
                )
            ],
            'testing_recommendations': [
                "Test with operator injection: {'$ne': null}, {'$gt': ''}",
                "Test with JavaScript injection in $where clauses",
                "Verify type validation rejects unexpected types",
                "Test authentication bypass with NoSQL operators"
            ],
            'references': [
                "OWASP NoSQL Injection: https://owasp.org/www-community/attacks/NoSQL_injection",
                "CWE-943: https://cwe.mitre.org/data/definitions/943.html"
            ],
            'estimated_total_effort': "6-10 hours"
        },

        'OS Command Injection': {
            'cwe': 'CWE-78',
            'owasp': 'A03:2021 – Injection',
            'cvss_base': 10.0,
            'priority_multiplier': 1.0,
            'remediation_steps': [
                RemediationStep(
                    step_number=1,
                    title="Replace System Commands with Native Libraries",
                    description="Use programming language native libraries instead of shell commands.",
                    code_example="""
# VULNERABLE
import os
os.system(f"ping {user_input}")

# SECURE
import subprocess
import re

def ping_host(hostname: str) -> dict:
    # Strict validation
    if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
        raise ValueError("Invalid hostname format")

    # Use subprocess with shell=False
    result = subprocess.run(
        ['ping', '-c', '4', hostname],
        capture_output=True,
        text=True,
        timeout=10,
        shell=False  # CRITICAL: Never use shell=True with user input
    )

    return {
        'success': result.returncode == 0,
        'output': result.stdout
    }
""",
                    verification_method="Attempt command injection with ; | & ` $",
                    estimated_effort="4-6 hours"
                ),
                RemediationStep(
                    step_number=2,
                    title="Input Allowlisting",
                    description="Only allow known-good characters. Reject shell metacharacters.",
                    code_example="""
import re

# Shell metacharacters to block
SHELL_METACHARACTERS = r'[;&|`$<>(){}\\[\\]!#\\n\\r]'

def validate_safe_input(user_input: str) -> str:
    if re.search(SHELL_METACHARACTERS, user_input):
        raise ValueError("Invalid characters detected")

    # Allowlist: only alphanumeric, dash, underscore, dot
    if not re.match(r'^[a-zA-Z0-9._-]+$', user_input):
        raise ValueError("Invalid format")

    return user_input
""",
                    verification_method="Test with all shell metacharacters",
                    estimated_effort="2 hours"
                )
            ],
            'testing_recommendations': [
                "Test with payloads: ; ls, | whoami, `cat /etc/passwd`, $(id)",
                "Verify subprocess calls use shell=False",
                "Test timeout functionality",
                "Code review all os.system(), os.popen(), subprocess calls"
            ],
            'references': [
                "OWASP Command Injection: https://owasp.org/www-community/attacks/Command_Injection",
                "CWE-78: https://cwe.mitre.org/data/definitions/78.html"
            ],
            'estimated_total_effort': "8-12 hours"
        },

        'Insecure Direct Object Reference (IDOR)': {
            'cwe': 'CWE-639',
            'owasp': 'A01:2021 – Broken Access Control',
            'owasp_api': 'API1:2023 - Broken Object Level Authorization',
            'cvss_base': 7.5,
            'priority_multiplier': 0.9,
            'remediation_steps': [
                RemediationStep(
                    step_number=1,
                    title="Implement Object Ownership Verification",
                    description="Always verify requesting user owns or has access to the object.",
                    code_example="""
def resolve_user_profile(parent, info, profile_id):
    current_user = info.context.user

    # Fetch requested profile
    profile = Profile.query.get(profile_id)

    if not profile:
        raise GraphQLError("Profile not found")

    # CRITICAL: Verify ownership or permission
    if profile.user_id != current_user.id and not current_user.is_admin:
        # Log unauthorized access attempt
        logger.warning(
            f"User {current_user.id} attempted to access profile {profile_id} "
            f"(owner: {profile.user_id})"
        )
        raise GraphQLError("Unauthorized")

    return profile
""",
                    verification_method="Test accessing other users' objects",
                    estimated_effort="3-5 hours per endpoint"
                ),
                RemediationStep(
                    step_number=2,
                    title="Use Indirect Object References",
                    description="Replace predictable IDs with random tokens or UUIDs.",
                    code_example="""
import uuid

class Profile(Base):
    id = Column(Integer, primary_key=True)  # Internal ID
    public_id = Column(String, unique=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey('users.id'))

# Expose public_id, not id
def resolve_profile(parent, info, public_id: str):
    profile = Profile.query.filter_by(public_id=public_id).first()

    if not profile:
        raise GraphQLError("Not found")

    current_user = info.context.user
    if profile.user_id != current_user.id:
        raise GraphQLError("Unauthorized")

    return profile
""",
                    verification_method="Verify sequential enumeration is impossible",
                    estimated_effort="6-8 hours (database migration required)"
                ),
                RemediationStep(
                    step_number=3,
                    title="Implement Field-Level Authorization",
                    description="Use GraphQL directives for declarative authorization.",
                    code_example="""
from functools import wraps

def requires_ownership(field_name='user_id'):
    def decorator(func):
        @wraps(func)
        def wrapper(parent, info, **kwargs):
            current_user = info.context.user

            # Execute original resolver
            obj = func(parent, info, **kwargs)

            # Check ownership
            if hasattr(obj, field_name):
                owner_id = getattr(obj, field_name)
                if owner_id != current_user.id:
                    raise GraphQLError("Unauthorized")

            return obj
        return wrapper
    return decorator

# Usage
@requires_ownership('user_id')
def resolve_profile(parent, info, profile_id):
    return Profile.query.get(profile_id)
""",
                    verification_method="Unit tests with different user contexts",
                    estimated_effort="4-6 hours"
                )
            ],
            'testing_recommendations': [
                "Test accessing objects with sequential IDs (1, 2, 3, ...)",
                "Test with different authenticated users",
                "Verify audit logs capture unauthorized attempts",
                "Test both horizontal (same role) and vertical (different role) access"
            ],
            'references': [
                "OWASP IDOR: https://owasp.org/www-community/attacks/Insecure_Direct_Object_References",
                "CWE-639: https://cwe.mitre.org/data/definitions/639.html",
                "OWASP API1:2023: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
            ],
            'estimated_total_effort': "15-20 hours (full codebase)"
        },

        'JWT None Algorithm Accepted': {
            'cwe': 'CWE-347',
            'owasp': 'A02:2021 – Cryptographic Failures',
            'owasp_api': 'API2:2023 - Broken Authentication',
            'cvss_base': 9.8,
            'priority_multiplier': 1.0,
            'remediation_steps': [
                RemediationStep(
                    step_number=1,
                    title="Explicitly Reject 'none' Algorithm",
                    description="Configure JWT library to reject 'none' algorithm.",
                    code_example="""
import jwt

# VULNERABLE
payload = jwt.decode(token, verify=False)

# VULNERABLE
payload = jwt.decode(token, secret, algorithms=["HS256", "none"])

# SECURE
ALLOWED_ALGORITHMS = ["HS256", "RS256"]  # Never include "none"

try:
    payload = jwt.decode(
        token,
        secret_key,
        algorithms=ALLOWED_ALGORITHMS,
        options={
            "verify_signature": True,
            "require": ["exp", "iat", "sub"]
        }
    )
except jwt.exceptions.InvalidAlgorithmError:
    raise AuthenticationError("Invalid token algorithm")
""",
                    verification_method="Attempt JWT with 'none' algorithm",
                    estimated_effort="1-2 hours"
                ),
                RemediationStep(
                    step_number=2,
                    title="Update JWT Library to Latest Version",
                    description="Ensure using latest JWT library with security patches.",
                    code_example="""
# requirements.txt
PyJWT>=2.8.0  # Latest version with security fixes

# Verify version
import jwt
print(f"PyJWT version: {jwt.__version__}")

# Should be 2.8.0 or higher
""",
                    verification_method="Check library version",
                    estimated_effort="30 minutes"
                )
            ],
            'testing_recommendations': [
                "Test with JWT using alg='none'",
                "Verify signature verification cannot be disabled",
                "Test algorithm confusion attacks"
            ],
            'references': [
                "JWT None Algorithm Vulnerability: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                "CWE-347: https://cwe.mitre.org/data/definitions/347.html"
            ],
            'estimated_total_effort': "2-3 hours"
        },

        'GraphQL Introspection Enabled': {
            'cwe': 'CWE-200',
            'owasp': 'A01:2021 – Broken Access Control',
            'owasp_api': 'API8:2023 - Security Misconfiguration',
            'cvss_base': 5.3,
            'priority_multiplier': 0.7,
            'remediation_steps': [
                RemediationStep(
                    step_number=1,
                    title="Disable Introspection in Production",
                    description="Disable GraphQL introspection for production environments.",
                    code_example="""
# Apollo Server (Node.js)
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',
  playground: process.env.NODE_ENV !== 'production'
});

# Graphene (Python)
from graphene import Schema

schema = Schema(
    query=Query,
    mutation=Mutation,
    auto_camelcase=False
)

# In your GraphQL view
def graphql_view(request):
    # Disable introspection in production
    if settings.ENVIRONMENT == 'production':
        introspection = False
    else:
        introspection = True

    return GraphQLView.as_view(
        schema=schema,
        graphiql=introspection
    )(request)
""",
                    verification_method="Attempt introspection query in production",
                    estimated_effort="1 hour"
                )
            ],
            'testing_recommendations': [
                "Query __schema in production",
                "Verify GraphiQL/Playground disabled in production"
            ],
            'references': [
                "GraphQL Security Best Practices: https://graphql.org/learn/best-practices/#security"
            ],
            'estimated_total_effort': "1-2 hours"
        }
    }

    def __init__(self):
        """Initialize Remediation Engine"""
        logger.info("Remediation Engine initialized")

    def generate_remediation_plan(
        self,
        vulnerability: Dict[str, Any]
    ) -> Optional[RemediationPlan]:
        """
        Generate comprehensive remediation plan for a vulnerability

        Args:
            vulnerability: Vulnerability dictionary from detector

        Returns:
            RemediationPlan object or None if no mapping exists
        """
        vuln_name = vulnerability.get('name', '')

        # Find matching remediation in database
        remediation_data = self.REMEDIATION_DATABASE.get(vuln_name)

        if not remediation_data:
            logger.warning(f"No remediation mapping for vulnerability: {vuln_name}")
            return None

        # Calculate priority
        cvss_score = vulnerability.get('cvss_score', remediation_data.get('cvss_base', 5.0))
        priority = self._calculate_priority(
            cvss_score,
            remediation_data.get('priority_multiplier', 0.8)
        )

        # Generate secure code examples
        secure_examples = self._extract_code_examples(remediation_data['remediation_steps'])

        plan = RemediationPlan(
            vulnerability_name=vuln_name,
            cwe_id=remediation_data['cwe'],
            owasp_category=remediation_data.get('owasp_api', remediation_data['owasp']),
            cvss_score=cvss_score,
            priority=priority,
            remediation_steps=remediation_data['remediation_steps'],
            secure_code_examples=secure_examples,
            testing_recommendations=remediation_data.get('testing_recommendations', []),
            references=remediation_data.get('references', []),
            estimated_total_effort=remediation_data.get('estimated_total_effort', 'Unknown')
        )

        return plan

    def _calculate_priority(
        self,
        cvss_score: float,
        multiplier: float
    ) -> RemediationPriority:
        """
        Calculate remediation priority based on CVSS score

        Args:
            cvss_score: CVSS 3.1 score
            multiplier: Priority multiplier (e.g., 1.0 for critical systems)

        Returns:
            RemediationPriority enum
        """
        adjusted_score = cvss_score * multiplier

        if adjusted_score >= 9.0:
            return RemediationPriority.IMMEDIATE
        elif adjusted_score >= 7.0:
            return RemediationPriority.URGENT
        elif adjusted_score >= 5.0:
            return RemediationPriority.HIGH
        elif adjusted_score >= 3.0:
            return RemediationPriority.MEDIUM
        else:
            return RemediationPriority.LOW

    def _extract_code_examples(
        self,
        remediation_steps: List[RemediationStep]
    ) -> Dict[str, str]:
        """
        Extract code examples from remediation steps

        Args:
            remediation_steps: List of remediation steps

        Returns:
            Dictionary mapping step titles to code examples
        """
        examples = {}

        for step in remediation_steps:
            if step.code_example:
                examples[step.title] = step.code_example.strip()

        return examples

    def export_remediation_plan(
        self,
        plan: RemediationPlan,
        format: str = 'markdown'
    ) -> str:
        """
        Export remediation plan in various formats

        Args:
            plan: RemediationPlan object
            format: Output format ('markdown', 'json', 'html')

        Returns:
            Formatted remediation plan string
        """
        if format == 'json':
            return json.dumps({
                'vulnerability': plan.vulnerability_name,
                'cwe': plan.cwe_id,
                'owasp': plan.owasp_category,
                'cvss_score': plan.cvss_score,
                'priority': plan.priority.value,
                'steps': [
                    {
                        'number': step.step_number,
                        'title': step.title,
                        'description': step.description,
                        'effort': step.estimated_effort
                    }
                    for step in plan.remediation_steps
                ],
                'total_effort': plan.estimated_total_effort
            }, indent=2)

        elif format == 'markdown':
            md = f"# Remediation Plan: {plan.vulnerability_name}\n\n"
            md += f"**CWE:** {plan.cwe_id}  \n"
            md += f"**OWASP:** {plan.owasp_category}  \n"
            md += f"**CVSS Score:** {plan.cvss_score}  \n"
            md += f"**Priority:** {plan.priority.value}  \n"
            md += f"**Estimated Total Effort:** {plan.estimated_total_effort}  \n\n"

            md += "## Remediation Steps\n\n"
            for step in plan.remediation_steps:
                md += f"### {step.step_number}. {step.title}\n\n"
                md += f"{step.description}\n\n"

                if step.code_example:
                    md += f"**Code Example:**\n\n```python\n{step.code_example}\n```\n\n"

                if step.verification_method:
                    md += f"**Verification:** {step.verification_method}  \n"

                if step.estimated_effort:
                    md += f"**Effort:** {step.estimated_effort}  \n"

                md += "\n"

            md += "## Testing Recommendations\n\n"
            for test in plan.testing_recommendations:
                md += f"- {test}\n"

            md += "\n## References\n\n"
            for ref in plan.references:
                md += f"- {ref}\n"

            return md

        else:
            raise ValueError(f"Unsupported format: {format}")


if __name__ == "__main__":
    # Example usage
    engine = RemediationEngine()

    # Sample vulnerability
    vuln = {
        'name': 'SQL Injection',
        'severity': 'CRITICAL',
        'cvss_score': 9.8
    }

    plan = engine.generate_remediation_plan(vuln)

    if plan:
        print(engine.export_remediation_plan(plan, format='markdown'))
