from setuptools import setup, find_packages
import os

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith('#')]

setup(
    name="byma-tools",
    version="1.0.0",
    author="BYMA SECURITY",
    description="Multi-Purpose Cybersecurity Toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/byma-tools/byma-tools",
    packages=[".", "core", "config", "tools",
              "tools.recon", "tools.scanner", "tools.network",
              "tools.password", "tools.web", "tools.exploit",
              "tools.forensics", "tools.utils"],
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={},
)
