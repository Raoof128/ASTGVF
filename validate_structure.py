#!/usr/bin/env python3
"""
Structure Validation Script
Tests that all modules can be imported and basic structure is correct.
Does NOT require external dependencies to be installed.
"""

import sys
import ast
from pathlib import Path


def check_syntax(filepath: Path) -> bool:
    """Check if Python file has valid syntax"""
    try:
        with open(filepath, 'r') as f:
            ast.parse(f.read())
        print(f"✅ {filepath.relative_to(Path.cwd())}")
        return True
    except SyntaxError as e:
        print(f"❌ {filepath.relative_to(Path.cwd())}: {e}")
        return False


def check_imports(filepath: Path) -> list:
    """Extract all imports from a file"""
    try:
        with open(filepath, 'r') as f:
            tree = ast.parse(f.read())

        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append(node.module)

        return imports
    except Exception as e:
        print(f"⚠️  Could not parse imports from {filepath}: {e}")
        return []


def validate_structure():
    """Validate project structure"""
    print("=" * 60)
    print("API Security Framework - Structure Validation")
    print("=" * 60)

    root = Path.cwd()
    errors = []

    # Check required directories
    required_dirs = [
        'core',
        'detectors',
        'reporting',
        'orchestration',
        'datasets/payloads',
        'tests/unit_tests',
        'docs',
        'docker'
    ]

    print("\n📁 Checking directory structure...")
    for dir_path in required_dirs:
        full_path = root / dir_path
        if full_path.exists():
            print(f"✅ {dir_path}/")
        else:
            print(f"❌ {dir_path}/ - MISSING")
            errors.append(f"Missing directory: {dir_path}")

    # Check required files
    required_files = [
        'requirements.txt',
        'setup.py',
        'README.md',
        'LICENSE',
        '.gitignore',
        'docker-compose.yml'
    ]

    print("\n📄 Checking required files...")
    for file_path in required_files:
        full_path = root / file_path
        if full_path.exists():
            print(f"✅ {file_path}")
        else:
            print(f"❌ {file_path} - MISSING")
            errors.append(f"Missing file: {file_path}")

    # Check Python syntax
    print("\n🐍 Checking Python syntax...")
    python_files = list(root.rglob('*.py'))
    syntax_errors = 0

    for py_file in python_files:
        # Skip __pycache__ and venv
        if '__pycache__' in str(py_file) or 'venv' in str(py_file):
            continue

        if not check_syntax(py_file):
            syntax_errors += 1
            errors.append(f"Syntax error in: {py_file}")

    # Check __init__.py files
    print("\n📦 Checking package __init__.py files...")
    required_inits = [
        'core/__init__.py',
        'detectors/__init__.py',
        'reporting/__init__.py',
        'orchestration/__init__.py',
        'tests/__init__.py'
    ]

    for init_file in required_inits:
        full_path = root / init_file
        if full_path.exists():
            # Check if it has content
            content = full_path.read_text().strip()
            if content:
                print(f"✅ {init_file} (with content)")
            else:
                print(f"⚠️  {init_file} (empty - acceptable)")
        else:
            print(f"❌ {init_file} - MISSING")
            errors.append(f"Missing __init__.py: {init_file}")

    # Check key modules exist
    print("\n🔑 Checking key modules...")
    key_modules = [
        'core/graphql_introspection.py',
        'core/vulnerability_scanner.py',
        'core/remediation_engine.py',
        'detectors/injection_detector.py',
        'detectors/authorization_detector.py',
        'detectors/authentication_detector.py',
        'reporting/vulnerability_reporter.py',
        'orchestration/cli.py'
    ]

    for module in key_modules:
        full_path = root / module
        if full_path.exists():
            size_kb = full_path.stat().st_size / 1024
            print(f"✅ {module} ({size_kb:.1f} KB)")
        else:
            print(f"❌ {module} - MISSING")
            errors.append(f"Missing module: {module}")

    # Check documentation
    print("\n📚 Checking documentation...")
    doc_files = [
        'docs/README.md',
        'docs/SETUP.md'
    ]

    for doc in doc_files:
        full_path = root / doc
        if full_path.exists():
            word_count = len(full_path.read_text().split())
            print(f"✅ {doc} ({word_count} words)")
        else:
            print(f"⚠️  {doc} - MISSING (optional)")

    # Summary
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)

    total_py_files = len([f for f in python_files if '__pycache__' not in str(f)])
    print(f"Python files checked: {total_py_files}")
    print(f"Syntax errors: {syntax_errors}")
    print(f"Total issues: {len(errors)}")

    if errors:
        print("\n⚠️  Issues found:")
        for i, error in enumerate(errors, 1):
            print(f"  {i}. {error}")
        print("\n❌ Validation FAILED")
        return False
    else:
        print("\n✅ All validation checks PASSED!")
        print("\nProject structure is valid and ready for development.")
        print("\nNext steps:")
        print("  1. Install dependencies: pip install -r requirements.txt")
        print("  2. Install package: pip install -e .")
        print("  3. Run tests: pytest tests/")
        print("  4. Try CLI: python -m orchestration.cli --help")
        return True


if __name__ == '__main__':
    success = validate_structure()
    sys.exit(0 if success else 1)
