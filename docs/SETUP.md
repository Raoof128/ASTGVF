# Setup Guide

Complete installation and configuration guide for the API Security Framework.

---

## System Requirements

### Minimum Requirements
- **OS:** Linux, macOS, or Windows (WSL2)
- **Python:** 3.9 or higher
- **RAM:** 2GB minimum, 4GB recommended
- **Disk:** 500MB for installation + space for reports

### Recommended Requirements
- **OS:** Ubuntu 20.04+ or macOS 12+
- **Python:** 3.11
- **RAM:** 8GB
- **CPU:** 4+ cores for concurrent scanning
- **Disk:** 2GB

---

## Installation Methods

### Method 1: Direct Installation (Recommended for Development)

```bash
# 1. Clone repository
git clone https://github.com/yourusername/api-security-framework.git
cd api-security-framework

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\\Scripts\\activate

# 3. Upgrade pip
pip install --upgrade pip

# 4. Install dependencies
pip install -r requirements.txt

# 5. Install package in editable mode
pip install -e .

# 6. Verify installation
api-security --version
```

### Method 2: Docker (Recommended for Production)

```bash
# 1. Clone repository
git clone https://github.com/yourusername/api-security-framework.git
cd api-security-framework

# 2. Build Docker image
docker build -t api-security-framework -f docker/Dockerfile .

# 3. Run scan
docker run --rm \\
  -v $(pwd)/reports:/app/reports \\
  api-security-framework scan \\
  --url https://api.example.com/graphql \\
  --output-file /app/reports/report.html
```

### Method 3: Docker Compose (Easiest for Quick Start)

```bash
# 1. Set environment variables
export TARGET_API_URL=https://api.example.com/graphql
export AUTH_TOKEN=your_token_here

# 2. Run scan
docker-compose up api-scanner

# 3. View reports
docker-compose up report-viewer
# Open http://localhost:8080
```

---

## Configuration

### Environment Variables

Create `.env` file in project root:

```bash
# Target API Configuration
TARGET_API_URL=https://api.example.com/graphql
AUTH_TOKEN=Bearer your_jwt_token_here

# Scan Configuration
OUTPUT_FORMAT=html
VERIFY_SSL=true
MAX_CONCURRENT=5
TIMEOUT=30

# Report Viewer
REPORT_PORT=8080

# Continuous Monitoring
SCAN_INTERVAL=3600  # Seconds between scans
```

### Configuration File (YAML)

Create `config.yaml`:

```yaml
# API Configuration
endpoint: https://api.example.com/graphql
auth_token: Bearer xyz123

# Scan Settings
output_file: security_report.html
output_format: html
vulnerabilities:
  - injection
  - idor
  - auth
  - introspection

# Performance Tuning
confidence_threshold: 0.85
max_concurrent: 10
timeout: 60
verify_ssl: true
verbose: false

# Rate Limiting
rate_limit_delay: 0.1  # Seconds between requests
max_retries: 3
```

Run with config:

```bash
api-security config --config-file config.yaml
```

---

## Usage Examples

### 1. Basic Scan

```bash
api-security scan \\
  --url https://api.example.com/graphql \\
  --output-file report.html
```

### 2. Authenticated Scan

```bash
# JWT Bearer token
api-security scan \\
  --url https://api.example.com/graphql \\
  --auth-token "Bearer eyJhbGciOiJIUzI1NiIs..." \\
  --output-file report.html

# Custom headers
api-security scan \\
  --url https://api.example.com/graphql \\
  -H "Authorization: Bearer token" \\
  -H "X-API-Key: abc123" \\
  --output-file report.html
```

### 3. Targeted Vulnerability Testing

```bash
# Test only injection vulnerabilities
api-security scan \\
  --url https://api.example.com/graphql \\
  --vulnerabilities injection \\
  --output-format json

# Test multiple specific types
api-security scan \\
  --url https://api.example.com/graphql \\
  --vulnerabilities injection,idor,auth
```

### 4. High-Performance Scanning

```bash
api-security scan \\
  --url https://api.example.com/graphql \\
  --max-concurrent 20 \\
  --timeout 10 \\
  --confidence-threshold 0.90
```

### 5. CI/CD Integration

```bash
# Generate JSON report for automation
api-security scan \\
  --url $API_URL \\
  --auth-token "$API_TOKEN" \\
  --output-file scan.json \\
  --output-format json

# Check exit code
if [ $? -eq 1 ]; then
  echo "Critical vulnerabilities found!"
  exit 1
fi
```

---

## Troubleshooting

### Issue: SSL Certificate Verification Fails

```bash
# Disable SSL verification (NOT recommended for production)
api-security scan --url https://api.example.com/graphql --no-verify-ssl
```

### Issue: Rate Limiting / 429 Errors

```bash
# Reduce concurrent requests and add delay
api-security scan \\
  --url https://api.example.com/graphql \\
  --max-concurrent 2 \\
  --timeout 60
```

Edit `core/vulnerability_scanner.py`:
```python
rate_limit_delay=1.0  # Increase from 0.1 to 1.0 seconds
```

### Issue: Out of Memory

```bash
# Reduce concurrent requests
api-security scan --url https://api.example.com/graphql --max-concurrent 2

# Or use Docker with memory limit
docker run --rm -m 2g api-security-framework scan --url https://api.example.com/graphql
```

### Issue: GraphQL Introspection Disabled

```bash
# Introspection might be disabled (secure configuration)
# Framework will still test other vulnerabilities

# To skip introspection phase:
api-security scan \\
  --url https://api.example.com/graphql \\
  --vulnerabilities injection,idor,auth  # Exclude 'introspection'
```

### Issue: PDF Generation Fails

```bash
# Install system dependencies for WeasyPrint
# Ubuntu/Debian:
sudo apt-get install libcairo2-dev libpango1.0-dev libgdk-pixbuf2.0-dev

# macOS:
brew install cairo pango gdk-pixbuf

# Then reinstall weasyprint:
pip install --upgrade weasyprint
```

---

## Performance Tuning

### Optimize for Speed

```yaml
# config.yaml
max_concurrent: 20        # Increase parallelism
timeout: 10               # Reduce timeout
confidence_threshold: 0.9  # Reduce false positives
rate_limit_delay: 0.05     # Faster requests (check API limits!)
```

### Optimize for Accuracy

```yaml
max_concurrent: 3
timeout: 60
confidence_threshold: 0.75  # More sensitive detection
rate_limit_delay: 0.5        # More thorough testing
```

### Large API Optimization

For APIs with 100+ endpoints:

```bash
# Test in phases
api-security scan --url $URL --vulnerabilities injection -o injection.json
api-security scan --url $URL --vulnerabilities idor -o idor.json
api-security scan --url $URL --vulnerabilities auth -o auth.json

# Merge reports
jq -s '.[0] + .[1] + .[2]' injection.json idor.json auth.json > combined.json
```

---

## Integration Examples

### GitHub Actions

`.github/workflows/api-security.yml`:

```yaml
name: API Security Scan

on:
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight
  workflow_dispatch:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install -e .

      - name: Run security scan
        run: |
          api-security scan \\
            --url ${{ secrets.API_URL }} \\
            --auth-token "${{ secrets.API_TOKEN }}" \\
            --output-file report.json \\
            --output-format json

      - name: Upload report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: report.json

      - name: Check for critical vulnerabilities
        run: |
          CRITICAL_COUNT=$(jq '.summary.critical_count' report.json)
          if [ "$CRITICAL_COUNT" -gt 0 ]; then
            echo "::error::Found $CRITICAL_COUNT critical vulnerabilities"
            exit 1
          fi
```

### GitLab CI

`.gitlab-ci.yml`:

```yaml
api-security-scan:
  image: python:3.11
  script:
    - pip install -r requirements.txt
    - pip install -e .
    - >
      api-security scan
      --url $API_URL
      --auth-token "$API_TOKEN"
      --output-file report.json
      --output-format json
  artifacts:
    reports:
      junit: report.json
    paths:
      - report.json
    expire_in: 30 days
  only:
    - schedules
    - main
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('API Security Scan') {
            steps {
                script {
                    docker.image('python:3.11').inside {
                        sh '''
                            pip install -r requirements.txt
                            pip install -e .
                            api-security scan \\
                                --url ${API_URL} \\
                                --auth-token "${API_TOKEN}" \\
                                --output-file report.html
                        '''
                    }
                }
            }
        }
        stage('Publish Report') {
            steps {
                publishHTML([
                    reportDir: '.',
                    reportFiles: 'report.html',
                    reportName: 'API Security Report'
                ])
            }
        }
    }
}
```

---

## Updating

```bash
# Pull latest changes
git pull origin main

# Update dependencies
pip install --upgrade -r requirements.txt

# Reinstall package
pip install -e .

# Verify version
api-security --version
```

---

## Uninstallation

```bash
# Remove package
pip uninstall api-security-framework

# Remove virtual environment
deactivate
rm -rf venv/

# Remove Docker images
docker rmi api-security-framework
docker-compose down -v
```

---

## Next Steps

1. Read [API Reference](API_REFERENCE.md) for detailed module documentation
2. Review [Case Studies](CASE_STUDIES.md) for real-world examples
3. Join our community: [GitHub Discussions](https://github.com/yourusername/api-security-framework/discussions)

---

## Support

- **Issues:** https://github.com/yourusername/api-security-framework/issues
- **Discussions:** https://github.com/yourusername/api-security-framework/discussions
- **Email:** security@example.com
