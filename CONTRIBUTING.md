# Contributing to API Security Framework

Thank you for your interest in contributing! This document provides guidelines for contributing to the API Security Framework.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Process](#development-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Feature Requests](#feature-requests)

---

## Code of Conduct

This project adheres to a Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to [security@example.com](mailto:security@example.com).

---

## Getting Started

### Prerequisites

- Python 3.9 or higher
- Git
- Virtual environment (recommended)

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/yourusername/api-security-framework.git
cd api-security-framework

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install package in editable mode
pip install -e .

# Install development dependencies
pip install pytest pytest-cov black flake8 mypy

# Run tests to verify setup
pytest tests/
```

---

## Development Process

### Branching Strategy

- `main` - Stable production code
- `develop` - Integration branch for features
- `feature/*` - New features
- `bugfix/*` - Bug fixes
- `docs/*` - Documentation updates

### Workflow

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/new-detector`
3. **Make your changes**
4. **Write tests** for new functionality
5. **Run tests**: `pytest tests/`
6. **Format code**: `black .`
7. **Lint code**: `flake8 .`
8. **Commit changes**: `git commit -m "feat: add new detector"`
9. **Push to your fork**: `git push origin feature/new-detector`
10. **Create Pull Request**

---

## Coding Standards

### Python Style Guide

- Follow [PEP 8](https://pep8.org/)
- Use type hints for function signatures
- Maximum line length: 120 characters
- Use docstrings for all public functions/classes

### Code Formatting

```bash
# Format code with black
black .

# Check formatting
black --check .

# Lint with flake8
flake8 . --max-line-length=120 --exclude=venv,__pycache__
```

### Naming Conventions

- **Classes**: `PascalCase` (e.g., `InjectionDetector`)
- **Functions**: `snake_case` (e.g., `detect_sql_injection`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `MAX_RETRIES`)
- **Private methods**: `_leading_underscore` (e.g., `_parse_response`)

### Docstring Format

```python
def detect_vulnerability(endpoint: str, payload: str) -> bool:
    """
    Detect vulnerability using specified payload

    Args:
        endpoint: Target API endpoint URL
        payload: Attack payload to test

    Returns:
        True if vulnerability detected, False otherwise

    Raises:
        ValueError: If endpoint URL is invalid
    """
    pass
```

---

## Testing

### Writing Tests

- Place unit tests in `tests/unit_tests/`
- Place integration tests in `tests/integration_tests/`
- Test file naming: `test_<module_name>.py`
- Test function naming: `test_<functionality>()`

### Running Tests

```bash
# Run all tests
pytest tests/

# Run specific test file
pytest tests/unit_tests/test_injection_detector.py

# Run with coverage
pytest --cov=. --cov-report=html

# Run only unit tests
pytest tests/unit_tests/ -v

# Run tests in parallel
pytest -n auto
```

### Test Coverage Requirements

- Minimum coverage: 80%
- Critical modules (detectors): 90%
- New code: 85%

---

## Pull Request Process

### Before Submitting

1. **Update documentation** if you changed APIs
2. **Add tests** for new functionality
3. **Ensure tests pass**: `pytest tests/`
4. **Update CHANGELOG.md** with your changes
5. **Verify code quality**: `black .` and `flake8 .`

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature causing existing functionality to break)
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] All tests pass locally

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review performed
- [ ] Comments added for complex code
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Tests added with coverage > 80%
```

### Review Process

1. Maintainer reviews code
2. CI/CD checks must pass
3. At least one approval required
4. Maintainer merges PR

---

## Reporting Bugs

### Before Reporting

1. **Check existing issues** to avoid duplicates
2. **Try latest version** of the framework
3. **Gather information**: logs, error messages, steps to reproduce

### Bug Report Template

```markdown
**Describe the Bug**
Clear description of the bug

**To Reproduce**
Steps to reproduce:
1. Run command '...'
2. With configuration '...'
3. See error

**Expected Behavior**
What you expected to happen

**Actual Behavior**
What actually happened

**Environment**
- OS: [e.g., Ubuntu 22.04]
- Python Version: [e.g., 3.11]
- Framework Version: [e.g., 1.0.0]

**Additional Context**
Logs, screenshots, etc.
```

---

## Feature Requests

### Proposing New Features

1. **Open an issue** with label `enhancement`
2. **Describe the feature** and use case
3. **Explain benefits** to the project
4. **Suggest implementation** if possible

### Feature Request Template

```markdown
**Feature Description**
Clear description of the proposed feature

**Use Case**
Why this feature is needed

**Proposed Solution**
How you envision the feature working

**Alternatives Considered**
Other approaches you've considered

**Additional Context**
Any other relevant information
```

---

## Adding New Detectors

### Detector Development Guide

1. **Create detector file**: `detectors/your_detector.py`
2. **Inherit base class**: `BaseVulnerabilityDetector`
3. **Implement required methods**:
   - `get_detector_name()`
   - `get_vulnerability_category()`
   - `detect(**kwargs)`

4. **Add tests**: `tests/unit_tests/test_your_detector.py`
5. **Update documentation**: Add to `docs/README.md`

### Example Detector Structure

```python
from core.vulnerability_scanner import BaseVulnerabilityDetector, VulnerabilityCategory

class YourDetector(BaseVulnerabilityDetector):
    def get_detector_name(self) -> str:
        return "Your Detector Name"

    def get_vulnerability_category(self) -> VulnerabilityCategory:
        return VulnerabilityCategory.INJECTION

    def detect(self, **kwargs):
        vulnerabilities = []
        # Your detection logic here
        return vulnerabilities
```

---

## Documentation

### Documentation Updates

- Update `docs/README.md` for feature changes
- Update `docs/SETUP.md` for installation changes
- Add examples to `examples/` directory
- Update inline code comments

### Building Documentation

```bash
# Generate API documentation (future)
# python -m pydoc-markdown

# Validate markdown
# markdownlint docs/
```

---

## Security

### Reporting Security Vulnerabilities

**DO NOT** open a public issue for security vulnerabilities.

Instead, email [security@example.com](mailto:security@example.com) with:
- Description of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will respond within 48 hours.

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

## Questions?

- Open an issue for questions
- Email: [contributors@example.com](mailto:contributors@example.com)
- Discussions: [GitHub Discussions](https://github.com/yourusername/api-security-framework/discussions)

---

**Thank you for contributing to API Security Framework!** 🙏
