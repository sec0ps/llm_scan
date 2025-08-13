# LLM Security Testing Framework

A security assessment toolkit for Large Language Models (LLMs) designed for red team and blue team operations.

## Overview

The LLM Security Testing Framework is a Python-based tool that provides systematic security testing capabilities for AI systems. It includes automated vulnerability detection, business logic bypass testing, data extraction analysis, and comprehensive reporting.

## Quick Start

### Prerequisites

- Python 3.7 or higher
- Git

### Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd llm-security-framework
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the framework:**
   ```bash
   python main.py
   ```

## Features

### Core Testing Capabilities

- **Prompt Injection Testing** - Direct and indirect injection attack detection
- **Jailbreak Testing** - Safety restriction bypass attempts
- **Data Extraction Testing** - System prompt and training data leakage detection
- **Business Logic Bypass** - Authentication, authorization, and workflow bypass testing
- **Model Manipulation** - Adversarial prompts and output steering tests

### Target Support

- **API-Based LLMs** - OpenAI, Anthropic, Azure OpenAI
- **Self-Hosted Models** - Ollama, vLLM, local deployments
- **Web Interfaces** - ChatGPT, custom chatbots (with browser automation)

### Reporting & Analysis

- **Executive Summaries** - Risk assessments for leadership
- **Technical Reports** - Detailed findings for security teams
- **Multiple Formats** - HTML, JSON, Markdown output
- **Compliance Mapping** - NIST, ISO 27001, SOC 2 alignment

## Usage

### Basic Security Scan

1. **Configure Target:**
   ```
   Select option 1: Configure Target
   Choose your LLM type (OpenAI, Anthropic, etc.)
   Enter API credentials
   ```

2. **Run Quick Scan:**
   ```
   Select option 2: Run Quick Security Scan
   ```

3. **View Results:**
   ```
   Review findings and generate reports
   ```

### Advanced Configuration

```python
from llm_security_framework import (
    TargetConfig, 
    LLMSecurityTestingFramework,
    ConfigurationManager
)

# Configure target
target = TargetConfig(
    target_type=TargetType.API_BASED,
    base_url="https://api.openai.com",
    api_key="your-api-key",
    model_name="gpt-3.5-turbo"
)

# Run comprehensive assessment
framework = LLMSecurityTestingFramework()
results = framework.run_comprehensive_assessment(target)
```

## Test Categories

### 1. Prompt Injection Tests
- Direct instruction override attempts
- System prompt extraction
- Context manipulation
- Encoding-based bypasses

### 2. Jailbreak Tests
- DAN (Do Anything Now) techniques
- Role-playing scenarios
- Safety restriction bypasses
- Character impersonation

### 3. Data Extraction Tests
- Training data leakage detection
- PII disclosure testing
- System information extraction
- Configuration detail exposure

### 4. Business Logic Tests
- Authentication bypass attempts
- Authorization escalation
- Rate limit circumvention
- Workflow manipulation

### 5. Model Manipulation Tests
- Adversarial prompt injection
- Output steering attacks
- Denial of service testing
- Hallucination induction

## ⚙Configuration

### Target Templates

The framework includes built-in templates for popular LLM providers:

```python
# OpenAI
target = ConfigurationTemplate.create_openai_target(
    api_key="sk-...",
    model="gpt-4"
)

# Anthropic
target = ConfigurationTemplate.create_anthropic_target(
    api_key="sk-ant-...",
    model="claude-3-sonnet-20240229"
)

# Local/Self-hosted
target = ConfigurationTemplate.create_local_target(
    base_url="http://localhost:11434",
    model="llama2"
)
```

### Security Settings

```python
# Production security configuration
security_settings = SecuritySettings(
    encrypt_sensitive_data=True,
    anonymize_targets=True,
    audit_logging=True,
    session_timeout=1800
)
```

## 📊 Sample Report Output

```
================================
LLM Security Assessment Report
================================

Target: OpenAI GPT-3.5-Turbo
Tests Executed: 156
Vulnerabilities Found: 12
Success Rate: 7.7%

Severity Breakdown:
- Critical: 2
- High: 4  
- Medium: 5
- Low: 1

Key Findings:
• System prompt extraction possible
• Business logic bypass detected
• Rate limiting ineffective

Risk Score: 6.2/10.0 (HIGH)
```

## Command Line Interface

```bash
# Run specific test category
python main.py --category prompt_injection

# Generate JSON report
python main.py --output report.json --format json

# Run with custom configuration
python main.py --config custom_config.yaml

# Verbose output
python main.py --verbose
```

## Advanced Features

### Custom Test Development

```python
from llm_scan import BaseSecurityTest, AttackCategory, Severity

class CustomSecurityTest(BaseSecurityTest):
    def __init__(self):
        super().__init__(
            name="Custom Test",
            category=AttackCategory.PROMPT_INJECTION,
            description="Custom security test"
        )
    
    def generate_payloads(self):
        return ["test payload 1", "test payload 2"]
    
    def analyze_response(self, payload, response):
        # Custom analysis logic
        pass
```

### Integration with CI/CD

```yaml
# GitHub Actions example
- name: Run LLM Security Tests
  run: |
    python main.py --config ci_config.json
    python -c "
    import sys
    from llm_security_framework import load_results
    results = load_results('results.json')
    if results['critical_count'] > 0:
        sys.exit(1)
    "
```

### Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Code formatting
black llm_security_framework/
```

## Troubleshooting

### Common Issues

**Connection Errors:**
```bash
# Check target URL and credentials
python -c "from llm_client import LLMClient; print('Connection test...')"
```

**Authentication Failures:**
```bash
# Verify API key format and permissions
export OPENAI_API_KEY="your-key"
```

**Rate Limiting:**
```bash
# Adjust rate limiting in configuration
# Default: 1 request per second
```

## Disclaimer

This LLM Security Testing Framework is for authorized security testing, educational, and research purposes only. Users are solely responsible for how they deploy and use this security assessment tool. Always obtain explicit written authorization before testing any Large Language Model system, API, or AI service. This framework must only be used against systems you own or have been granted permission to test. Unauthorized testing of AI systems may violate terms of service, computer fraud laws, and other applicable regulations. Users must ensure compliance with all local, state, and federal laws when conducting security assessments.

## Contact
For professional services, integrations, or support contact: operations@redcellsecurity.org

## License

**Author**: Keith Pachulski  
**Company**: Red Cell Security, LLC  
**Email**: keith@redcellsecurity.org  
**Website**: www.redcellsecurity.org  

© 2025 Keith Pachulski. All rights reserved.

**License**: This software is licensed under the MIT License. You are free to use, modify, and distribute this software in accordance with the terms of the license.

## Support My Work

If you find my work useful and want to support continued development, you can donate here:

[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/sec0ps)

---

** Security Reminder**: This tool is designed for authorized security testing only. Always ensure you have proper permission before testing any LLM system.
