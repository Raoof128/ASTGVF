"""
CLI Interface for API Security Framework
Command-line orchestration for all scanning operations.

Author: Security Research Team
Version: 1.0.0
"""

import click
import json
import sys
from pathlib import Path
from typing import Optional, List
from loguru import logger

from core.graphql_introspection import GraphQLIntrospectionEngine
from detectors.injection_detector import InjectionDetector
from detectors.authorization_detector import AuthorizationDetector
from detectors.authentication_detector import AuthenticationDetector
from reporting.vulnerability_reporter import VulnerabilityReporter
from core.remediation_engine import RemediationEngine


# Configure logger
logger.remove()
logger.add(sys.stderr, level="INFO", format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>")


@click.group()
@click.version_option(version='1.0.0')
def cli():
    """
    🔒 API Security Testing & GraphQL Vulnerability Framework

    Comprehensive security scanner for GraphQL and REST APIs.
    """
    pass


@cli.command()
@click.option('--url', '-u', required=True, help='Target API endpoint URL')
@click.option('--auth-token', '-t', help='Authentication token (JWT, Bearer, etc.)')
@click.option('--auth-header', '-H', multiple=True, help='Custom auth header (format: "Key: Value")')
@click.option('--output-file', '-o', default='security_report.html', help='Output report file')
@click.option('--output-format', '-f', type=click.Choice(['html', 'json', 'markdown', 'pdf']), default='html', help='Report format')
@click.option('--vulnerabilities', '-v', help='Comma-separated list of vulnerability types to test (injection,idor,auth,all)')
@click.option('--confidence-threshold', type=float, default=0.80, help='Confidence threshold for detections (0.0-1.0)')
@click.option('--max-concurrent', type=int, default=5, help='Maximum concurrent requests')
@click.option('--timeout', type=int, default=30, help='Request timeout in seconds')
@click.option('--verify-ssl/--no-verify-ssl', default=True, help='Verify SSL certificates')
@click.option('--verbose', '-V', is_flag=True, help='Verbose output')
def scan(
    url: str,
    auth_token: Optional[str],
    auth_header: tuple,
    output_file: str,
    output_format: str,
    vulnerabilities: Optional[str],
    confidence_threshold: float,
    max_concurrent: int,
    timeout: int,
    verify_ssl: bool,
    verbose: bool
):
    """
    Execute comprehensive API security scan

    Example:
        api-security scan --url https://api.example.com/graphql \\
                          --auth-token "Bearer xyz" \\
                          --output-file report.html
    """
    if verbose:
        logger.remove()
        logger.add(sys.stderr, level="DEBUG")

    logger.info(f"Starting API security scan: {url}")

    # Parse auth headers
    auth_headers = {}
    if auth_token:
        if not auth_token.startswith('Bearer '):
            auth_token = f'Bearer {auth_token}'
        auth_headers['Authorization'] = auth_token

    for header in auth_header:
        if ': ' in header:
            key, value = header.split(': ', 1)
            auth_headers[key] = value

    # Determine vulnerability types to test
    vuln_types = []
    if vulnerabilities:
        if vulnerabilities.lower() == 'all':
            vuln_types = ['introspection', 'injection', 'authorization', 'authentication']
        else:
            vuln_types = [v.strip() for v in vulnerabilities.split(',')]
    else:
        vuln_types = ['introspection', 'injection', 'authorization', 'authentication']

    all_vulnerabilities = []
    total_tests = 0
    scan_duration = 0

    # Phase 1: GraphQL Introspection
    if 'introspection' in vuln_types or 'all' in vuln_types:
        try:
            logger.info("Phase 1: GraphQL Introspection Analysis")
            introspection_engine = GraphQLIntrospectionEngine(
                graphql_endpoint=url,
                auth_headers=auth_headers,
                timeout=timeout,
                verify_ssl=verify_ssl
            )

            introspection_report = introspection_engine.run_full_analysis()
            all_vulnerabilities.extend(introspection_report.get('vulnerabilities', []))
            schema = introspection_report.get('schema')

            logger.success(f"Introspection complete: {len(introspection_report.get('vulnerabilities', []))} issues found")

        except Exception as e:
            logger.error(f"Introspection failed: {e}")
            schema = None
    else:
        schema = None

    # Phase 2: Injection Detection
    if 'injection' in vuln_types or 'all' in vuln_types:
        try:
            logger.info("Phase 2: Injection Vulnerability Detection")
            injection_detector = InjectionDetector(
                endpoint=url,
                auth_headers=auth_headers,
                timeout=timeout,
                verify_ssl=verify_ssl,
                max_concurrent_requests=max_concurrent
            )

            injection_result = injection_detector.run_detection(
                schema=schema,
                injection_types=['sql', 'nosql', 'command']
            )

            all_vulnerabilities.extend(injection_result.vulnerabilities)
            total_tests += injection_result.tests_executed
            scan_duration += injection_result.scan_duration

            logger.success(f"Injection detection complete: {len(injection_result.vulnerabilities)} vulnerabilities")

        except Exception as e:
            logger.error(f"Injection detection failed: {e}")

    # Phase 3: Authorization Detection
    if 'authorization' in vuln_types or 'idor' in vuln_types or 'all' in vuln_types:
        try:
            logger.info("Phase 3: Authorization Vulnerability Detection")
            auth_detector = AuthorizationDetector(
                endpoint=url,
                auth_headers=auth_headers,
                timeout=timeout,
                verify_ssl=verify_ssl,
                max_concurrent_requests=max_concurrent
            )

            auth_result = auth_detector.run_detection(schema=schema)
            all_vulnerabilities.extend(auth_result.vulnerabilities)
            total_tests += auth_result.tests_executed
            scan_duration += auth_result.scan_duration

            logger.success(f"Authorization detection complete: {len(auth_result.vulnerabilities)} vulnerabilities")

        except Exception as e:
            logger.error(f"Authorization detection failed: {e}")

    # Phase 4: Authentication Detection
    if 'authentication' in vuln_types or 'auth' in vuln_types or 'all' in vuln_types:
        try:
            logger.info("Phase 4: Authentication Vulnerability Detection")
            authn_detector = AuthenticationDetector(
                endpoint=url,
                auth_headers=auth_headers,
                timeout=timeout,
                verify_ssl=verify_ssl
            )

            authn_result = authn_detector.run_detection(
                schema=schema,
                current_token=auth_token
            )

            all_vulnerabilities.extend(authn_result.vulnerabilities)
            total_tests += authn_result.tests_executed
            scan_duration += authn_result.scan_duration

            logger.success(f"Authentication detection complete: {len(authn_result.vulnerabilities)} vulnerabilities")

        except Exception as e:
            logger.error(f"Authentication detection failed: {e}")

    # Calculate risk score
    risk_score = calculate_risk_score(all_vulnerabilities)

    # Compile final results
    scan_results = {
        'endpoint': url,
        'timestamp': __import__('time').time(),
        'vulnerabilities': all_vulnerabilities,
        'tests_executed': total_tests,
        'scan_duration': scan_duration,
        'risk_score': risk_score,
        'summary': {
            'total_vulnerabilities': len(all_vulnerabilities),
            'critical_count': sum(1 for v in all_vulnerabilities if v.get('severity') == 'CRITICAL'),
            'high_count': sum(1 for v in all_vulnerabilities if v.get('severity') == 'HIGH'),
            'medium_count': sum(1 for v in all_vulnerabilities if v.get('severity') == 'MEDIUM'),
            'low_count': sum(1 for v in all_vulnerabilities if v.get('severity') == 'LOW'),
        }
    }

    # Generate report
    logger.info(f"Generating {output_format.upper()} report...")
    reporter = VulnerabilityReporter()

    try:
        if output_format == 'pdf':
            reporter.export_to_pdf(scan_results, output_file)
        else:
            reporter.export_to_file(scan_results, output_file, format=output_format)

        logger.success(f"Report saved to: {output_file}")

    except Exception as e:
        logger.error(f"Report generation failed: {e}")

    # Print summary
    print_scan_summary(scan_results)

    # Exit code based on findings
    if scan_results['summary']['critical_count'] > 0:
        sys.exit(1)  # Critical vulnerabilities found
    elif scan_results['summary']['high_count'] > 0:
        sys.exit(2)  # High vulnerabilities found
    else:
        sys.exit(0)  # Success


@cli.command()
@click.option('--report-file', '-r', required=True, help='Scan report JSON file')
@click.option('--output-file', '-o', default='remediation_plan.md', help='Output remediation plan file')
@click.option('--format', '-f', type=click.Choice(['markdown', 'json']), default='markdown', help='Output format')
def remediate(report_file: str, output_file: str, format: str):
    """
    Generate remediation plans from scan results

    Example:
        api-security remediate --report-file scan.json --output-file plan.md
    """
    logger.info(f"Generating remediation plans from: {report_file}")

    # Load scan results
    try:
        with open(report_file, 'r') as f:
            scan_results = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load report: {e}")
        sys.exit(1)

    vulnerabilities = scan_results.get('vulnerabilities', [])

    if not vulnerabilities:
        logger.warning("No vulnerabilities found in report")
        return

    # Generate remediation plans
    engine = RemediationEngine()
    remediation_plans = []

    for vuln in vulnerabilities:
        plan = engine.generate_remediation_plan(vuln)
        if plan:
            remediation_plans.append(plan)

    logger.info(f"Generated {len(remediation_plans)} remediation plans")

    # Export plans
    output = ""
    if format == 'markdown':
        for plan in remediation_plans:
            output += engine.export_remediation_plan(plan, format='markdown')
            output += "\n\n---\n\n"
    elif format == 'json':
        output = json.dumps([
            json.loads(engine.export_remediation_plan(plan, format='json'))
            for plan in remediation_plans
        ], indent=2)

    Path(output_file).write_text(output, encoding='utf-8')
    logger.success(f"Remediation plan saved to: {output_file}")


@cli.command()
@click.option('--url', '-u', required=True, help='Target API endpoint')
@click.option('--auth-token', '-t', help='Authentication token')
@click.option('--output-file', '-o', default='schema.json', help='Output schema file')
def introspect(url: str, auth_token: Optional[str], output_file: str):
    """
    Perform GraphQL introspection and save schema

    Example:
        api-security introspect --url https://api.example.com/graphql -o schema.json
    """
    logger.info(f"Introspecting GraphQL schema: {url}")

    auth_headers = {}
    if auth_token:
        if not auth_token.startswith('Bearer '):
            auth_token = f'Bearer {auth_token}'
        auth_headers['Authorization'] = auth_token

    try:
        engine = GraphQLIntrospectionEngine(
            graphql_endpoint=url,
            auth_headers=auth_headers
        )

        schema = engine.fetch_schema()

        # Save schema
        with open(output_file, 'w') as f:
            json.dump(schema, f, indent=2)

        logger.success(f"Schema saved to: {output_file}")

        # Print summary
        print(f"\n📊 Schema Summary:")
        print(f"  Types: {len(schema.get('types', []))}")
        print(f"  Queries: {len(schema.get('queries', []))}")
        print(f"  Mutations: {len(schema.get('mutations', []))}")
        print(f"  Subscriptions: {len(schema.get('subscriptions', []))}")

    except Exception as e:
        logger.error(f"Introspection failed: {e}")
        sys.exit(1)


@cli.command()
@click.option('--config-file', '-c', required=True, help='Configuration file (YAML/JSON)')
def config(config_file: str):
    """
    Run scan with configuration file

    Example config.yaml:
        endpoint: https://api.example.com/graphql
        auth_token: Bearer xyz
        output_file: report.html
        vulnerabilities: [injection, idor, auth]
    """
    logger.info(f"Loading configuration from: {config_file}")

    try:
        import yaml

        with open(config_file, 'r') as f:
            if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                config = yaml.safe_load(f)
            else:
                config = json.load(f)

        # Extract options
        ctx = click.Context(scan)
        ctx.invoke(
            scan,
            url=config.get('endpoint'),
            auth_token=config.get('auth_token'),
            auth_header=config.get('auth_headers', []),
            output_file=config.get('output_file', 'report.html'),
            output_format=config.get('output_format', 'html'),
            vulnerabilities=','.join(config.get('vulnerabilities', [])) if isinstance(config.get('vulnerabilities'), list) else config.get('vulnerabilities'),
            confidence_threshold=config.get('confidence_threshold', 0.80),
            max_concurrent=config.get('max_concurrent', 5),
            timeout=config.get('timeout', 30),
            verify_ssl=config.get('verify_ssl', True),
            verbose=config.get('verbose', False)
        )

    except Exception as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)


def calculate_risk_score(vulnerabilities: List[dict]) -> float:
    """
    Calculate overall risk score (0-10) based on vulnerabilities

    Args:
        vulnerabilities: List of vulnerability dictionaries

    Returns:
        Risk score (0-10)
    """
    if not vulnerabilities:
        return 0.0

    # Weight vulnerabilities by severity
    severity_weights = {
        'CRITICAL': 2.0,
        'HIGH': 1.5,
        'MEDIUM': 0.8,
        'LOW': 0.3,
        'INFO': 0.0
    }

    score = 0.0
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'INFO')
        score += severity_weights.get(severity, 0.0)

    # Normalize to 0-10 scale
    # Assume 5+ critical/high vulns = 10.0
    normalized_score = min(score / 5.0 * 10.0, 10.0)

    return round(normalized_score, 1)


def print_scan_summary(scan_results: dict):
    """Print formatted scan summary to console"""
    print("\n" + "="*60)
    print("🔒 API SECURITY SCAN SUMMARY")
    print("="*60)

    summary = scan_results['summary']
    risk_score = scan_results['risk_score']

    print(f"\n📊 Results:")
    print(f"  Total Vulnerabilities: {summary['total_vulnerabilities']}")
    print(f"  Critical: {summary['critical_count']}")
    print(f"  High: {summary['high_count']}")
    print(f"  Medium: {summary['medium_count']}")
    print(f"  Low: {summary['low_count']}")

    print(f"\n⚠️  Risk Score: {risk_score}/10.0")

    if risk_score >= 8.0:
        risk_level = "CRITICAL"
        color = "red"
    elif risk_score >= 6.0:
        risk_level = "HIGH"
        color = "orange"
    elif risk_score >= 4.0:
        risk_level = "MEDIUM"
        color = "yellow"
    else:
        risk_level = "LOW"
        color = "green"

    print(f"  Risk Level: {risk_level}")

    print(f"\n🔍 Scan Statistics:")
    print(f"  Tests Executed: {scan_results.get('tests_executed', 0)}")
    print(f"  Duration: {scan_results.get('scan_duration', 0):.2f}s")

    print("\n" + "="*60 + "\n")


def main():
    """Main entry point"""
    try:
        cli()
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
