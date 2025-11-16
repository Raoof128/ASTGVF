#!/usr/bin/env python3
"""
Code Quality Check Script
Performs static analysis without requiring dependencies to be installed.
"""

import ast
import re
from pathlib import Path
from collections import defaultdict


def analyze_file(filepath: Path) -> dict:
    """Analyze a Python file for quality metrics"""
    with open(filepath, 'r') as f:
        content = f.read()
        lines = content.split('\n')

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return {'error': 'Syntax error'}

    metrics = {
        'lines': len(lines),
        'code_lines': len([l for l in lines if l.strip() and not l.strip().startswith('#')]),
        'comment_lines': len([l for l in lines if l.strip().startswith('#')]),
        'blank_lines': len([l for l in lines if not l.strip()]),
        'functions': 0,
        'classes': 0,
        'imports': 0,
        'docstrings': 0,
        'long_functions': [],
        'complex_functions': [],
        'missing_docstrings': []
    }

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            metrics['functions'] += 1

            # Check docstring
            if ast.get_docstring(node):
                metrics['docstrings'] += 1
            else:
                metrics['missing_docstrings'].append(node.name)

            # Check function length
            func_lines = node.end_lineno - node.lineno if hasattr(node, 'end_lineno') else 0
            if func_lines > 100:
                metrics['long_functions'].append((node.name, func_lines))

            # Check complexity (count if/for/while statements)
            complexity = sum(1 for n in ast.walk(node) if isinstance(n, (ast.If, ast.For, ast.While, ast.Try)))
            if complexity > 10:
                metrics['complex_functions'].append((node.name, complexity))

        elif isinstance(node, ast.ClassDef):
            metrics['classes'] += 1
            if not ast.get_docstring(node):
                metrics['missing_docstrings'].append(node.name)

        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            metrics['imports'] += 1

    return metrics


def check_common_issues(filepath: Path) -> list:
    """Check for common code issues"""
    issues = []
    content = filepath.read_text()

    # Check for print statements (should use logger)
    print_matches = re.findall(r'^\s*print\(', content, re.MULTILINE)
    if print_matches and 'cli.py' not in str(filepath) and 'test' not in str(filepath):
        issues.append(f"Found {len(print_matches)} print statements (use logger instead)")

    # Check for bare except
    if re.search(r'except\s*:', content):
        issues.append("Found bare 'except:' clause (specify exception type)")

    # Check for TODO/FIXME
    todos = re.findall(r'#\s*(TODO|FIXME|XXX|HACK):', content, re.IGNORECASE)
    if todos:
        issues.append(f"Found {len(todos)} TODO/FIXME comments")

    # Check for long lines (>120 chars)
    long_lines = [i+1 for i, line in enumerate(content.split('\n')) if len(line) > 120]
    if long_lines:
        issues.append(f"{len(long_lines)} lines exceed 120 characters")

    # Check for proper docstrings
    if '"""' not in content[:500] and "'''" not in content[:500]:
        if filepath.name != '__init__.py':
            issues.append("Missing module docstring")

    return issues


def main():
    print("=" * 70)
    print("API Security Framework - Code Quality Check")
    print("=" * 70)

    root = Path.cwd()
    python_files = [
        f for f in root.rglob('*.py')
        if '__pycache__' not in str(f) and 'venv' not in str(f)
    ]

    total_metrics = defaultdict(int)
    all_issues = []

    print(f"\n📊 Analyzing {len(python_files)} Python files...\n")

    for py_file in sorted(python_files):
        rel_path = py_file.relative_to(root)

        # Analyze metrics
        metrics = analyze_file(py_file)

        if 'error' in metrics:
            print(f"❌ {rel_path}: {metrics['error']}")
            continue

        # Accumulate total metrics
        for key, value in metrics.items():
            if isinstance(value, (int, float)):
                total_metrics[key] += value

        # Check for issues
        issues = check_common_issues(py_file)

        if metrics['long_functions']:
            for func, lines in metrics['long_functions']:
                issues.append(f"Long function '{func}' ({lines} lines)")

        if metrics['complex_functions']:
            for func, complexity in metrics['complex_functions']:
                issues.append(f"Complex function '{func}' (complexity={complexity})")

        # Print file summary
        doc_ratio = (metrics['docstrings'] / metrics['functions'] * 100) if metrics['functions'] > 0 else 100
        status = "✅" if not issues else "⚠️ "

        print(f"{status} {rel_path}")
        print(f"   Lines: {metrics['code_lines']:4d} code, {metrics['comment_lines']:3d} comments, {metrics['blank_lines']:3d} blank")
        print(f"   Functions: {metrics['functions']:2d} ({doc_ratio:.0f}% documented)")

        if metrics['classes'] > 0:
            print(f"   Classes: {metrics['classes']}")

        if issues:
            all_issues.append((rel_path, issues))
            for issue in issues:
                print(f"      ⚠️  {issue}")

        print()

    # Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)

    print(f"\n📈 Overall Metrics:")
    print(f"   Total lines of code: {total_metrics['code_lines']:,}")
    print(f"   Total comment lines: {total_metrics['comment_lines']:,}")
    print(f"   Code/Comment ratio: {total_metrics['code_lines']/total_metrics['comment_lines']:.1f}:1" if total_metrics['comment_lines'] > 0 else "No comments")
    print(f"   Total functions: {total_metrics['functions']}")
    print(f"   Total classes: {total_metrics['classes']}")
    print(f"   Documentation rate: {(total_metrics['docstrings']/total_metrics['functions']*100):.1f}%" if total_metrics['functions'] > 0 else "N/A")

    print(f"\n📋 Quality Assessment:")
    if all_issues:
        print(f"   Files with issues: {len(all_issues)}/{len(python_files)}")
        print(f"   Total issues: {sum(len(issues) for _, issues in all_issues)}")

        print(f"\n   Issue Breakdown:")
        issue_types = defaultdict(int)
        for _, issues in all_issues:
            for issue in issues:
                # Categorize issue
                if 'print statement' in issue:
                    issue_types['print() usage'] += 1
                elif 'long line' in issue or 'exceed' in issue:
                    issue_types['long lines'] += 1
                elif 'TODO' in issue or 'FIXME' in issue:
                    issue_types['TODO comments'] += 1
                elif 'Long function' in issue:
                    issue_types['long functions'] += 1
                elif 'Complex function' in issue:
                    issue_types['complex functions'] += 1
                elif 'docstring' in issue:
                    issue_types['missing docstrings'] += 1
                else:
                    issue_types['other'] += 1

        for issue_type, count in sorted(issue_types.items(), key=lambda x: x[1], reverse=True):
            print(f"      - {issue_type}: {count}")

    else:
        print("   ✅ No issues found!")

    print(f"\n💯 Code Quality Score: {calculate_score(total_metrics, all_issues):.1f}/100")

    print("\n" + "=" * 70)


def calculate_score(metrics, issues):
    """Calculate overall code quality score"""
    score = 100

    # Deduct for missing docstrings
    if metrics['functions'] > 0:
        doc_rate = metrics['docstrings'] / metrics['functions']
        if doc_rate < 0.8:
            score -= (0.8 - doc_rate) * 30

    # Deduct for issues
    issue_count = sum(len(iss) for _, iss in issues)
    score -= min(issue_count * 2, 40)

    return max(score, 0)


if __name__ == '__main__':
    main()
