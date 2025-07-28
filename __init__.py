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

__version__ = "1.0.0"
__author__ = "LLM Security Testing Framework Team"

# Import main classes for easy access
from llm_scan import TargetConfig, TargetType, SecurityLogger, BaseSecurityTest, AttackCategory, Severity
from config_manager import ConfigurationManager, ConfigurationTemplate
from llm_client import LLMClient
from report_writer import ReportGenerator, ReportMetadata, ReportScope

# Import test orchestrators
from data_extraction import DataExtractionOrchestrator
from business_logic_bypass import BusinessLogicOrchestrator
from model_manipulation import ModelManipulationOrchestrator

# Import individual test classes
from prompt_injection import DirectPromptInjectionTest, JailbreakTest, IndirectPromptInjectionTest

__all__ = [
    # Core classes
    "TargetConfig", "TargetType", "SecurityLogger", "BaseSecurityTest", 
    "AttackCategory", "Severity", "LLMClient",
    
    # Configuration
    "ConfigurationManager", "ConfigurationTemplate",
    
    # Reporting
    "ReportGenerator", "ReportMetadata", "ReportScope",
    
    # Orchestrators
    "DataExtractionOrchestrator", "BusinessLogicOrchestrator", "ModelManipulationOrchestrator",
    
    # Individual tests
    "DirectPromptInjectionTest", "JailbreakTest", "IndirectPromptInjectionTest"
]