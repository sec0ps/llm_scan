# LLM Security Testing Framework

A comprehensive security assessment toolkit for Large Language Models (LLMs) designed for red team and blue team operations.

## 🔒 Overview

The LLM Security Testing Framework is a Python-based tool that provides systematic security testing capabilities for AI systems. It includes automated vulnerability detection, business logic bypass testing, data extraction analysis, and comprehensive reporting.

## ⚡ Quick Start

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

## 🎯 Features

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

## 🚀 Usage

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

## 📋 Test Categories

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

## ⚙️ Configuration

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

## 🔧 Command Line Interface

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

## 🛡️ Ethical Use & Legal Compliance

### ⚠️ Important Disclaimers

- **Authorization Required**: Only test systems you own or have explicit permission to test
- **Responsible Disclosure**: Report vulnerabilities through proper channels
- **Legal Compliance**: Ensure testing complies with local laws and regulations
- **No Malicious Use**: This tool is for defensive security purposes only

### Ethical Guidelines

1. **Obtain proper authorization** before testing any LLM system
2. **Respect rate limits** and terms of service
3. **Protect sensitive data** discovered during testing
4. **Report findings responsibly** to system owners
5. **Document your testing** for compliance purposes

## 📁 Project Structure

```
llm-security-framework/
├── main.py                    # Main CLI interface
├── llm_scan.py               # Core security testing engine
├── config_manager.py         # Configuration management
├── llm_client.py             # LLM communication client
├── prompt_injection.py       # Prompt injection tests
├── data_extraction.py        # Data extraction tests
├── business_logic_bypass.py  # Business logic tests
├── model_manipulation.py     # Model manipulation tests
├── report_writer.py          # Report generation
├── response_analysis.py      # Advanced response analysis
├── requirements.txt          # Python dependencies
├── setup.py                 # Package setup
└── README.md                # This file
```

## 🔍 Advanced Features

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

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

### Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Code formatting
black llm_security_framework/
```

## 📖 Documentation

- [API Documentation](docs/api.md)
- [Test Development Guide](docs/custom_tests.md)
- [Configuration Reference](docs/configuration.md)
- [Integration Examples](docs/examples.md)

## 🐛 Troubleshooting

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

### Getting Help

- Check the [FAQ](docs/faq.md)
- Review [example configurations](examples/)
- Open an issue on GitHub
- Join our community discussions

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Related Projects

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [LLM Security Research](https://github.com/llm-security)
- [AI Red Team Tools](https://github.com/ai-redteam)

## 📞 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/your-org/llm-security-framework/issues)
- **Security**: [security@yourorg.com](mailto:security@yourorg.com)

---

**⚠️ Security Reminder**: This tool is designed for authorized security testing only. Always ensure you have proper permission before testing any LLM system.
