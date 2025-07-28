# =============================================================================
# LLM Security Testing Framework - Comprehensive AI Security Assessment
# =============================================================================
#
# Author: Keith Pachulski
# Company: Red Cell Security, LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2025 Keith Pachulski. All rights reserved.
#
# License: This software is licensed under the MIT License.
#          You are free to use, modify, and distribute this software
#          in accordance with the terms of the license.
#
# Purpose: This module is part of the LLM Security Testing Framework, designed to
#          provide comprehensive security assessment capabilities for Large Language
#          Models and AI systems. It includes automated vulnerability detection,
#          prompt injection testing, business logic bypass detection, data extraction
#          analysis, and professional security reporting for authorized penetration
#          testing and security research.
#
# SECURITY NOTICE: This framework is intended for authorized security testing only.
#                  Users must obtain explicit permission before testing any LLM system.
#                  This tool is designed for defensive security purposes and should
#                  only be used in accordance with applicable laws and regulations.
#
# DISCLAIMER: This software is provided "as-is," without warranty of any kind,
#             express or implied, including but not limited to the warranties
#             of merchantability, fitness for a particular purpose, and non-infringement.
#             In no event shall the authors or copyright holders be liable for any claim,
#             damages, or other liability, whether in an action of contract, tort, or otherwise,
#             arising from, out of, or in connection with the software or the use or other dealings
#             in the software.
#
# =============================================================================

from setuptools import setup, find_packages

setup(
    name="llm-security-framework",
    version="1.0.0",
    description="Comprehensive security testing framework for Large Language Models",
    packages=find_packages(),
    install_requires=[
        "requests>=2.25.0",
        "urllib3>=1.26.0", 
        "cryptography>=3.4.0",
        "pyyaml>=5.4.0",
    ],
    extras_require={
        "full": [
            "matplotlib>=3.3.0",
            "seaborn>=0.11.0", 
            "jinja2>=3.0.0",
            "pandas>=1.3.0",
        ],
        "charts": [
            "matplotlib>=3.3.0",
            "seaborn>=0.11.0",
        ],
        "templates": [
            "jinja2>=3.0.0",
        ],
    },
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "llm-security=llm_security_framework.__main__:main",
        ],
    },
)