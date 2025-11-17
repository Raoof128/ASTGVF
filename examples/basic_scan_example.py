#!/usr/bin/env python3
"""
Basic API Security Scan Example

This example demonstrates how to perform a basic security scan
of a GraphQL API endpoint.

Usage:
    python examples/basic_scan_example.py
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.graphql_introspection import GraphQLIntrospectionEngine
from detectors.injection_detector import InjectionDetector
from reporting.vulnerability_reporter import VulnerabilityReporter


def main():
    """Run basic security scan example"""

    print("=" * 70)
    print("API Security Framework - Basic Scan Example")
    print("=" * 70)
    print()

    # Configure target
    API_URL = "https://api.example.com/graphql"
    AUTH_TOKEN = "Bearer YOUR_TOKEN_HERE"  # Replace with actual token

    print(f"Target API: {API_URL}")
    print()

    # Step 1: GraphQL Introspection
    print("Step 1: Running GraphQL Introspection...")
    print("-" * 70)

    try:
        introspection_engine = GraphQLIntrospectionEngine(
            graphql_endpoint=API_URL,
            auth_headers={"Authorization": AUTH_TOKEN},
            timeout=30
        )

        # Fetch schema
        schema_data = introspection_engine.fetch_schema()

        print(f"✅ Schema retrieved successfully!")
        print(f"   Types: {len(schema_data.get('types', []))}")
        print(f"   Queries: {len(schema_data.get('queries', []))}")
        print(f"   Mutations: {len(schema_data.get('mutations', []))}")
        print()

        # Run introspection analysis
        introspection_vulns = introspection_engine.detect_information_disclosure()
        introspection_vulns.extend(introspection_engine.analyze_field_accessibility())

        print(f"   Introspection vulnerabilities found: {len(introspection_vulns)}")
        print()

    except Exception as e:
        print(f"❌ Introspection failed: {e}")
        print("   This is normal if the API is not accessible or introspection is disabled.")
        schema_data = None
        introspection_vulns = []
        print()

    # Step 2: Injection Detection
    print("Step 2: Running Injection Detection...")
    print("-" * 70)

    injection_detector = InjectionDetector(
        endpoint=API_URL,
        auth_headers={"Authorization": AUTH_TOKEN},
        timeout=30,
        max_concurrent_requests=3
    )

    try:
        # Run detection (this is just a demonstration)
        print("   Testing for SQL, NoSQL, and Command Injection...")
        print("   Note: This will NOT actually attack the API without proper configuration")
        print()

        # For this example, we'll just show the structure
        print("   Detector initialized successfully")
        print(f"   Detector name: {injection_detector.get_detector_name()}")
        print(f"   Category: {injection_detector.get_vulnerability_category().value}")
        print()

    except Exception as e:
        print(f"❌ Detection setup failed: {e}")
        print()

    # Step 3: Generate Report
    print("Step 3: Generating Security Report...")
    print("-" * 70)

    # Compile results (for demonstration)
    all_vulnerabilities = introspection_vulns  # Would include detector results

    scan_results = {
        'endpoint': API_URL,
        'vulnerabilities': all_vulnerabilities,
        'tests_executed': 0,  # Would be actual count
        'scan_duration': 0.0,  # Would be actual duration
        'risk_score': 0.0  # Would be calculated
    }

    reporter = VulnerabilityReporter()

    try:
        # Generate HTML report
        html_report = reporter.generate_technical_report(scan_results, format='html')

        # Save to file
        report_path = Path("example_security_report.html")
        report_path.write_text(html_report, encoding='utf-8')

        print(f"✅ Report generated: {report_path.absolute()}")
        print(f"   Vulnerabilities reported: {len(all_vulnerabilities)}")
        print()

    except Exception as e:
        print(f"❌ Report generation failed: {e}")
        print()

    # Summary
    print("=" * 70)
    print("Scan Complete")
    print("=" * 70)
    print()
    print("This is a demonstration example. To perform actual security testing:")
    print("1. Replace API_URL with your target GraphQL endpoint")
    print("2. Replace AUTH_TOKEN with valid authentication")
    print("3. Ensure you have authorization to test the target")
    print("4. Review and customize detection parameters")
    print()
    print("For full scanning, use the CLI:")
    print(f"  python -m orchestration.cli scan --url {API_URL} --output-file report.html")
    print()


if __name__ == "__main__":
    main()
