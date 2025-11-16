"""
API Security Testing & GraphQL Vulnerability Framework
Setup configuration
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "docs" / "README.md"
long_description = ""
if readme_file.exists():
    long_description = readme_file.read_text(encoding="utf-8")

setup(
    name="api-security-framework",
    version="1.0.0",
    author="Security Research Team",
    author_email="security@example.com",
    description="Comprehensive API Security Testing & GraphQL Vulnerability Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/api-security-framework",
    packages=find_packages(exclude=["tests*", "docs*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.9",
    install_requires=[
        line.strip()
        for line in Path("requirements.txt").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ],
    entry_points={
        "console_scripts": [
            "api-security=orchestration.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "datasets": ["payloads/*", "vulnerable_apis/*"],
        "reporting": ["templates/*"],
    },
)
