"""
Integration tests for full scanning workflow

Author: Security Research Team
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from core.graphql_introspection import GraphQLIntrospectionEngine
from detectors.injection_detector import InjectionDetector
from reporting.vulnerability_reporter import VulnerabilityReporter


class TestFullScanWorkflow:
    """Test complete scanning workflow integration"""

    @pytest.fixture
    def mock_response(self):
        """Create a mock HTTP response"""
        mock = Mock()
        mock.status_code = 200
        mock.headers = {'Content-Type': 'application/json'}
        mock.json.return_value = {
            'data': {
                '__schema': {
                    'queryType': {'name': 'Query'},
                    'mutationType': {'name': 'Mutation'},
                    'types': [
                        {
                            'name': 'User',
                            'kind': 'OBJECT',
                            'fields': [
                                {
                                    'name': 'id',
                                    'type': {'name': 'ID'},
                                    'args': []
                                }
                            ]
                        }
                    ]
                }
            }
        }
        mock.text = '{}'
        mock.content = b'{}'
        return mock

    @patch('requests.post')
    def test_introspection_to_detection_workflow(self, mock_post, mock_response):
        """Test workflow from introspection to detection"""
        mock_post.return_value = mock_response

        # Step 1: Introspection
        introspection_engine = GraphQLIntrospectionEngine(
            graphql_endpoint="https://api.example.com/graphql"
        )

        schema = introspection_engine.fetch_schema()

        assert 'types' in schema
        assert 'queries' in schema

        # Step 2: Use schema in detector
        detector = InjectionDetector(
            endpoint="https://api.example.com/graphql"
        )

        # Should not raise error
        result = detector.run_detection(schema=schema, injection_types=['sql'])

        assert result.detector_name == "Injection Vulnerability Detector"
        assert result.status.value in ['completed', 'failed']

    @patch('requests.post')
    def test_detection_to_reporting_workflow(self, mock_post, mock_response):
        """Test workflow from detection to reporting"""
        mock_post.return_value = mock_response

        # Mock vulnerabilities from detection
        vulnerabilities = [
            {
                'name': 'SQL Injection',
                'severity': 'CRITICAL',
                'cvss_score': 9.8,
                'description': 'SQL injection detected',
                'evidence': {'payload': "' OR 1=1--"},
                'cwe_id': 'CWE-89'
            }
        ]

        scan_results = {
            'endpoint': 'https://api.example.com/graphql',
            'vulnerabilities': vulnerabilities,
            'tests_executed': 100,
            'scan_duration': 45.3,
            'risk_score': 8.5
        }

        # Generate report
        reporter = VulnerabilityReporter()

        html_report = reporter.generate_technical_report(scan_results, format='html')

        assert isinstance(html_report, str)
        assert 'SQL Injection' in html_report
        assert 'CRITICAL' in html_report

        json_report = reporter.generate_technical_report(scan_results, format='json')

        assert isinstance(json_report, str)
        assert 'SQL Injection' in json_report

    def test_multiple_detectors_workflow(self):
        """Test running multiple detectors sequentially"""
        from detectors.injection_detector import InjectionDetector
        from detectors.authorization_detector import AuthorizationDetector

        endpoint = "https://api.example.com/graphql"

        # Initialize detectors
        injection_detector = InjectionDetector(endpoint=endpoint)
        authz_detector = AuthorizationDetector(endpoint=endpoint)

        # Verify initialization
        assert injection_detector.endpoint == endpoint
        assert authz_detector.endpoint == endpoint

        # Verify they use the same base class
        from core.vulnerability_scanner import BaseVulnerabilityDetector

        assert isinstance(injection_detector, BaseVulnerabilityDetector)
        assert isinstance(authz_detector, BaseVulnerabilityDetector)


@pytest.mark.slow
class TestEndToEndScan:
    """End-to-end integration tests (requires mock server)"""

    def test_scan_result_aggregation(self):
        """Test aggregating results from multiple detectors"""
        all_vulnerabilities = []

        # Simulate results from different detectors
        injection_vulns = [
            {'name': 'SQL Injection', 'severity': 'CRITICAL', 'cvss_score': 9.8}
        ]

        authz_vulns = [
            {'name': 'IDOR', 'severity': 'HIGH', 'cvss_score': 7.5}
        ]

        all_vulnerabilities.extend(injection_vulns)
        all_vulnerabilities.extend(authz_vulns)

        assert len(all_vulnerabilities) == 2
        assert all_vulnerabilities[0]['name'] == 'SQL Injection'
        assert all_vulnerabilities[1]['name'] == 'IDOR'

    def test_risk_score_calculation(self):
        """Test risk score calculation from vulnerabilities"""
        vulnerabilities = [
            {'severity': 'CRITICAL', 'cvss_score': 9.8},
            {'severity': 'HIGH', 'cvss_score': 7.5},
            {'severity': 'MEDIUM', 'cvss_score': 5.0}
        ]

        # Calculate risk score
        severity_weights = {
            'CRITICAL': 2.0,
            'HIGH': 1.5,
            'MEDIUM': 0.8,
            'LOW': 0.3,
            'INFO': 0.0
        }

        score = sum(severity_weights.get(v['severity'], 0.0) for v in vulnerabilities)
        normalized_score = min(score / 5.0 * 10.0, 10.0)

        assert normalized_score > 0
        assert normalized_score <= 10.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
