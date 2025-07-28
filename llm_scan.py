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

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union, Any
from enum import Enum
import json
import logging
from datetime import datetime
#from llm_client import LLMClient

class TargetType(Enum):
    """Supported LLM target types"""
    API_BASED = "api_based"
    SELF_HOSTED = "self_hosted" 
    CHATBOT_INTERFACE = "chatbot_interface"

class AttackCategory(Enum):
    """LLM Attack Categories"""
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXTRACTION = "data_extraction"
    MODEL_MANIPULATION = "model_manipulation"
    INFO_DISCLOSURE = "info_disclosure"
    BUSINESS_LOGIC_BYPASS = "business_logic_bypass"

class Severity(Enum):
    """Finding severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class TargetConfig:
    """Configuration for LLM target"""
    target_type: TargetType
    base_url: str
    api_key: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    model_name: Optional[str] = None
    max_tokens: int = 1000
    temperature: float = 0.7
    timeout: int = 30
    rate_limit_delay: float = 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'target_type': self.target_type.value,
            'base_url': self.base_url,
            'api_key': self.api_key,
            'headers': self.headers,
            'model_name': self.model_name,
            'max_tokens': self.max_tokens,
            'temperature': self.temperature,
            'timeout': self.timeout,
            'rate_limit_delay': self.rate_limit_delay
        }

@dataclass
class TestResult:
    """Result of a security test"""
    test_id: str
    attack_category: AttackCategory
    test_name: str
    payload: str
    response: str
    success: bool
    severity: Severity
    timestamp: datetime = field(default_factory=datetime.now)
    details: Dict[str, Any] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for reporting"""
        return {
            'test_id': self.test_id,
            'attack_category': self.attack_category.value,
            'test_name': self.test_name,
            'payload': self.payload,
            'response': self.response,
            'success': self.success,
            'severity': self.severity.value,
            'timestamp': self.timestamp.isoformat(),
            'details': self.details,
            'evidence': self.evidence
        }

class SecurityLogger:
    """Centralized logging for security testing"""
    
    def __init__(self, log_file: str = "llm_security_test.log"):
        self.logger = logging.getLogger("LLMSecurityTesting")
        self.logger.setLevel(logging.INFO)
        
        # File handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def log_test_start(self, test_name: str, target: str):
        """Log test initiation"""
        self.logger.info(f"Starting test: {test_name} against {target}")
    
    def log_test_result(self, result: TestResult):
        """Log test result"""
        status = "SUCCESS" if result.success else "FAILED"
        self.logger.info(
            f"Test {result.test_id} ({result.test_name}): {status} - "
            f"Severity: {result.severity.value}"
        )
    
    def log_error(self, error: str, context: str = ""):
        """Log error with context"""
        self.logger.error(f"{context}: {error}" if context else error)
    
    def log_warning(self, warning: str):
        """Log warning"""
        self.logger.warning(warning)

class BaseSecurityTest:
    """Base class for all LLM security tests"""
    
    def __init__(self, name: str, category: AttackCategory, description: str):
        self.name = name
        self.category = category
        self.description = description
        self.logger = SecurityLogger()
    
    def generate_payloads(self) -> List[str]:
        """Generate test payloads - to be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement generate_payloads")
    
    def analyze_response(self, payload: str, response: str) -> TestResult:
        """Analyze response for vulnerabilities - to be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement analyze_response")
    
    def run_test(self, target_config: TargetConfig) -> List[TestResult]:
        """Run the security test against target"""
        results = []
        payloads = self.generate_payloads()
        
        self.logger.log_test_start(self.name, target_config.base_url)
        
        for i, payload in enumerate(payloads):
            try:
                # This will be implemented by the LLMClient class
                response = self._send_request(target_config, payload)
                result = self.analyze_response(payload, response)
                result.test_id = f"{self.name}_{i+1}"
                
                results.append(result)
                self.logger.log_test_result(result)
                
            except Exception as e:
                self.logger.log_error(str(e), f"Test {self.name} payload {i+1}")
                # Create failed result
                failed_result = TestResult(
                    test_id=f"{self.name}_{i+1}",
                    attack_category=self.category,
                    test_name=self.name,
                    payload=payload,
                    response=f"ERROR: {str(e)}",
                    success=False,
                    severity=Severity.INFO
                )
                results.append(failed_result)
        
        return results

    def _send_request(self, target_config: TargetConfig, payload: str) -> str:
        """Send request to target using LLMClient"""
        # Import here to avoid circular dependency
        from llm_client import LLMClient
        client = LLMClient(target_config, self.logger)
        return client.send_prompt(payload)