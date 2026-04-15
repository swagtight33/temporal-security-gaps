"""
Setup configuration for temporal-security-gaps package.
Derivatives #62-#71: Closing architectural gaps in cached executable
persistence across security policy transitions.

Patent Application: SLL-2025-001
Inventor: Stanley Lee Linton / STAAML Corp
"""
from setuptools import setup, find_packages

setup(
    name="temporal-security-gaps",
    version="1.0.0",
    author="Stanley Lee Linton",
    author_email="Stanleylinton@Staamlcorp.com",
    description=(
        "Production implementations for 10 architectural gaps in "
        "cached executable persistence across security policy transitions"
    ),
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/swagtight33/temporal-security-gaps",
    packages=find_packages(),
    python_requires=">=3.9",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: Other/Proprietary License",
        "Operating System :: OS Independent",
    ],
    keywords="security temporal-binding cache-validation policy-transitions",
)
