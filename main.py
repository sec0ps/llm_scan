#!/usr/bin/env python3
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

import sys
import os
from typing import Dict, List, Any, Optional
import json
from pathlib import Path

# Import all the modules
from llm_scan import TargetConfig, TargetType, SecurityLogger
from config_manager import ConfigurationManager, ConfigurationTemplate
from prompt_injection import DirectPromptInjectionTest, JailbreakTest, IndirectPromptInjectionTest
from data_extraction import DataExtractionOrchestrator
from business_logic_bypass import BusinessLogicOrchestrator
from model_manipulation import ModelManipulationOrchestrator
from report_writer import ReportGenerator, ReportMetadata, ReportScope
from llm_client import LLMClient

class LLMSecurityTestingFramework:
    """Main framework class that orchestrates all security tests"""
    
    def __init__(self):
        self.config_manager = ConfigurationManager()
        self.logger = SecurityLogger()
        self.report_generator = ReportGenerator()
        self.current_target = None
        
        # Initialize test orchestrators
        self.data_extraction_orchestrator = DataExtractionOrchestrator()
        self.business_logic_orchestrator = BusinessLogicOrchestrator()
        self.model_manipulation_orchestrator = ModelManipulationOrchestrator()
        
        # Individual test classes
        self.prompt_injection_tests = [
            DirectPromptInjectionTest(),
            JailbreakTest(),
            IndirectPromptInjectionTest()
        ]
    
    def display_banner(self):
        """Display program banner"""
        print("=" * 70)
        print("         LLM Security Testing Framework v1.0")
        print("    Comprehensive Security Assessment for AI Systems")
        print("=" * 70)
        print()
    
    def display_main_menu(self):
        """Display main menu options"""
        print("\n?? MAIN MENU")
        print("-" * 30)
        print("1. Configure Target")
        print("2. Run Quick Security Scan")
        print("3. Run Comprehensive Security Assessment")
        print("4. Run Specific Test Category")
        print("5. View Configuration")
        print("6. Generate Report")
        print("7. Exit")
        print("-" * 30)
    
    def configure_target_menu(self):
        """Handle target configuration"""
        while True:
            print("\n?? TARGET CONFIGURATION")
            print("-" * 30)
            print("1. Create New Target (Manual)")
            print("2. Use Template (OpenAI)")
            print("3. Use Template (Anthropic)")
            print("4. Use Template (Azure OpenAI)")
            print("5. Use Template (Local/Self-hosted)")
            print("6. Load Existing Target")
            print("7. Back to Main Menu")
            print("-" * 30)
            
            choice = input("Select option (1-7): ").strip()
            
            if choice == "1":
                self.create_manual_target()
            elif choice == "2":
                self.create_openai_target()
            elif choice == "3":
                self.create_anthropic_target()
            elif choice == "4":
                self.create_azure_target()
            elif choice == "5":
                self.create_local_target()
            elif choice == "6":
                self.load_existing_target()
            elif choice == "7":
                break
            else:
                print("? Invalid option. Please try again.")
    
    def create_manual_target(self):
        """Create target configuration manually"""
        print("\n?? Manual Target Configuration")
        print("-" * 30)
        
        # Get target type
        print("Target Types:")
        print("1. API-based (OpenAI, Anthropic, etc.)")
        print("2. Self-hosted (Local models)")
        print("3. Chatbot Interface (Custom API)")
        
        type_choice = input("Select target type (1-3): ").strip()
        
        if type_choice == "1":
            target_type = TargetType.API_BASED
        elif type_choice == "2":
            target_type = TargetType.SELF_HOSTED
        elif type_choice == "3":
            target_type = TargetType.CHATBOT_INTERFACE
        else:
            print("? Invalid target type.")
            return
        
        # Get basic configuration
        base_url = input("Enter base URL: ").strip()
        if not base_url:
            print("? Base URL is required.")
            return
        
        api_key = input("Enter API key (press Enter to skip): ").strip()
        model_name = input("Enter model name (press Enter for default): ").strip()
        
        # Create target config
        target_config = TargetConfig(
            target_type=target_type,
            base_url=base_url,
            api_key=api_key if api_key else None,
            model_name=model_name if model_name else None
        )
        
        # Save target
        target_name = input("Enter name for this target: ").strip()
        if target_name:
            self.config_manager.add_target(target_name, target_config)
            self.current_target = target_config
            print(f"? Target '{target_name}' configured successfully!")
        else:
            print("? Target name is required.")
    
    def create_openai_target(self):
        """Create OpenAI target using template"""
        print("\n?? OpenAI Target Configuration")
        print("-" * 30)
        
        api_key = input("Enter OpenAI API key: ").strip()
        if not api_key:
            print("? API key is required.")
            return
        
        model = input("Enter model name (default: gpt-3.5-turbo): ").strip()
        if not model:
            model = "gpt-3.5-turbo"
        
        target_config = ConfigurationTemplate.create_openai_target(api_key, model)
        
        target_name = input("Enter name for this target: ").strip()
        if target_name:
            self.config_manager.add_target(target_name, target_config)
            self.current_target = target_config
            print(f"? OpenAI target '{target_name}' configured successfully!")
        else:
            print("? Target name is required.")
    
    def create_anthropic_target(self):
        """Create Anthropic target using template"""
        print("\n?? Anthropic Target Configuration")
        print("-" * 30)
        
        api_key = input("Enter Anthropic API key: ").strip()
        if not api_key:
            print("? API key is required.")
            return
        
        model = input("Enter model name (default: claude-3-sonnet-20240229): ").strip()
        if not model:
            model = "claude-3-sonnet-20240229"
        
        target_config = ConfigurationTemplate.create_anthropic_target(api_key, model)
        
        target_name = input("Enter name for this target: ").strip()
        if target_name:
            self.config_manager.add_target(target_name, target_config)
            self.current_target = target_config
            print(f"? Anthropic target '{target_name}' configured successfully!")
        else:
            print("? Target name is required.")
    
    def create_azure_target(self):
        """Create Azure OpenAI target using template"""
        print("\n?? Azure OpenAI Target Configuration")
        print("-" * 30)
        
        api_key = input("Enter Azure API key: ").strip()
        if not api_key:
            print("? API key is required.")
            return
        
        base_url = input("Enter Azure endpoint URL: ").strip()
        if not base_url:
            print("? Endpoint URL is required.")
            return
        
        deployment_name = input("Enter deployment name: ").strip()
        if not deployment_name:
            print("? Deployment name is required.")
            return
        
        target_config = ConfigurationTemplate.create_azure_openai_target(
            api_key, deployment_name, base_url
        )
        
        target_name = input("Enter name for this target: ").strip()
        if target_name:
            self.config_manager.add_target(target_name, target_config)
            self.current_target = target_config
            print(f"? Azure OpenAI target '{target_name}' configured successfully!")
        else:
            print("? Target name is required.")
    
    def create_local_target(self):
        """Create local/self-hosted target using template"""
        print("\n?? Local/Self-hosted Target Configuration")
        print("-" * 30)
        
        base_url = input("Enter base URL (default: http://localhost:11434): ").strip()
        if not base_url:
            base_url = "http://localhost:11434"
        
        model = input("Enter model name (default: llama2): ").strip()
        if not model:
            model = "llama2"
        
        target_config = ConfigurationTemplate.create_local_target(base_url, model)
        
        target_name = input("Enter name for this target: ").strip()
        if target_name:
            self.config_manager.add_target(target_name, target_config)
            self.current_target = target_config
            print(f"? Local target '{target_name}' configured successfully!")
        else:
            print("? Target name is required.")
    
    def load_existing_target(self):
        """Load an existing target configuration"""
        targets = self.config_manager.list_targets()
        
        if not targets:
            print("? No saved targets found.")
            return
        
        print("\n?? Existing Targets:")
        print("-" * 30)
        for i, target_name in enumerate(targets, 1):
            print(f"{i}. {target_name}")
        
        try:
            choice = int(input(f"Select target (1-{len(targets)}): ")) - 1
            if 0 <= choice < len(targets):
                target_name = targets[choice]
                self.current_target = self.config_manager.get_target(target_name)
                print(f"? Loaded target '{target_name}'")
            else:
                print("? Invalid selection.")
        except ValueError:
            print("? Invalid input.")
    
    def check_target_configured(self) -> bool:
        """Check if target is configured"""
        if not self.current_target:
            print("? No target configured. Please configure a target first.")
            return False
        return True

    def run_quick_scan(self):
        """Run quick security scan"""
        if not self.check_target_configured():
            return
        
        print("\n? Running Quick Security Scan...")
        print("-" * 40)
        print("?? Testing connection to target...")
        
        # Test connection first
        try:
            client = LLMClient(self.current_target, self.logger)
            if not client.test_connection():
                print("? Connection test failed. Check your target configuration.")
                return
            print("? Connection successful")
        except Exception as e:
            print(f"? Connection failed: {str(e)}")
            return
        
        all_results = []
        total_tests = len(self.prompt_injection_tests)
        
        # Run prompt injection tests with progress
        print(f"\n?? Testing Prompt Injection ({total_tests} test categories)...")
        for i, test in enumerate(self.prompt_injection_tests, 1):
            try:
                print(f"   [{i}/{total_tests}] Running {test.name}...", end="", flush=True)
                results = test.run_test(self.current_target)
                all_results.extend(results)
                successful = len([r for r in results if r.success])
                print(f" ? {successful}/{len(results)} vulnerabilities found")
            except Exception as e:
                print(f" ? Failed: {str(e)}")
                self.logger.log_error(f"Test {test.name} failed: {str(e)}")
        
        print(f"\n?? Quick scan completed - {len(all_results)} total tests executed")
        
        # Display summary
        self.display_results_summary(all_results)

    def run_comprehensive_assessment(self):
        """Run comprehensive security assessment"""
        if not self.check_target_configured():
            return
        
        print("\n?? Running Comprehensive Security Assessment...")
        print("-" * 50)
        
        # Test connection first
        print("?? Testing connection to target...")
        try:
            client = LLMClient(self.current_target, self.logger)
            if not client.test_connection():
                print("? Connection test failed. Check your target configuration.")
                return
            print("? Connection successful")
        except Exception as e:
            print(f"? Connection failed: {str(e)}")
            return
        
        all_results = []
        phase_count = 4
        current_phase = 0
        
        # Prompt Injection Tests
        current_phase += 1
        print(f"\n?? Phase {current_phase}/{phase_count}: Prompt Injection Testing...")
        total_tests = len(self.prompt_injection_tests)
        for i, test in enumerate(self.prompt_injection_tests, 1):
            try:
                print(f"   [{i}/{total_tests}] {test.name}...", end="", flush=True)
                results = test.run_test(self.current_target)
                all_results.extend(results)
                successful = len([r for r in results if r.success])
                print(f" ? {successful}/{len(results)} vulnerabilities")
            except Exception as e:
                print(f" ? Failed: {str(e)}")
        
        # Data Extraction Tests
        current_phase += 1
        print(f"\n??? Phase {current_phase}/{phase_count}: Data Extraction Testing...")
        try:
            print("   Running comprehensive data extraction tests...", end="", flush=True)
            extraction_summary = self.data_extraction_orchestrator.run_comprehensive_extraction(
                self.current_target
            )
            # Add results to all_results if available
            if hasattr(self.data_extraction_orchestrator, 'extraction_history') and self.data_extraction_orchestrator.extraction_history:
                latest_results = self.data_extraction_orchestrator.extraction_history[-1].get('detailed_results', [])
                all_results.extend(latest_results)
            print(f" ? {extraction_summary['successful_extractions']}/{extraction_summary['total_tests']} vulnerabilities")
        except Exception as e:
            print(f" ? Failed: {str(e)}")
        
        # Business Logic Tests
        current_phase += 1
        print(f"\n?? Phase {current_phase}/{phase_count}: Business Logic Testing...")
        try:
            print("   Running business logic bypass tests...", end="", flush=True)
            business_summary = self.business_logic_orchestrator.run_comprehensive_bypass_tests(
                self.current_target
            )
            # Add results to all_results if available
            if hasattr(self.business_logic_orchestrator, 'bypass_history') and self.business_logic_orchestrator.bypass_history:
                latest_results = self.business_logic_orchestrator.bypass_history[-1].get('detailed_results', [])
                all_results.extend(latest_results)
            print(f" ? {business_summary['successful_bypasses']}/{business_summary['total_tests']} vulnerabilities")
        except Exception as e:
            print(f" ? Failed: {str(e)}")
        
        # Model Manipulation Tests
        current_phase += 1
        print(f"\n?? Phase {current_phase}/{phase_count}: Model Manipulation Testing...")
        try:
            print("   Running model manipulation tests...", end="", flush=True)
            manipulation_summary = self.model_manipulation_orchestrator.run_comprehensive_manipulation_tests(
                self.current_target
            )
            # Add results to all_results if available
            if hasattr(self.model_manipulation_orchestrator, 'manipulation_history') and self.model_manipulation_orchestrator.manipulation_history:
                latest_results = self.model_manipulation_orchestrator.manipulation_history[-1].get('detailed_results', [])
                all_results.extend(latest_results)
            print(f" ? {manipulation_summary['successful_manipulations']}/{manipulation_summary['total_tests']} vulnerabilities")
        except Exception as e:
            print(f" ? Failed: {str(e)}")
        
        print(f"\n?? Comprehensive assessment completed!")
        print(f"?? Total tests executed: {len(all_results)}")
        
        # Display summary
        self.display_results_summary(all_results)
        
        # Offer to generate report
        generate_report = input("\n?? Generate detailed report? (y/n): ").strip().lower()
        if generate_report == 'y':
            self.generate_comprehensive_report(all_results)
    
    def run_specific_category(self):
        """Run specific test category"""
        if not self.check_target_configured():
            return
        
        print("\n?? Select Test Category:")
        print("-" * 30)
        print("1. Prompt Injection")
        print("2. Data Extraction")
        print("3. Business Logic Bypass")
        print("4. Model Manipulation")
        print("5. Back to Main Menu")
        
        choice = input("Select category (1-5): ").strip()
        
        if choice == "1":
            self.run_prompt_injection_tests()
        elif choice == "2":
            self.run_data_extraction_tests()
        elif choice == "3":
            self.run_business_logic_tests()
        elif choice == "4":
            self.run_model_manipulation_tests()
        elif choice == "5":
            return
        else:
            print("? Invalid option.")
    
    def run_prompt_injection_tests(self):
        """Run prompt injection tests"""
        print("\n?? Running Prompt Injection Tests...")
        all_results = []
        
        for test in self.prompt_injection_tests:
            try:
                results = test.run_test(self.current_target)
                all_results.extend(results)
                successful = len([r for r in results if r.success])
                print(f"? {test.name}: {successful}/{len(results)} vulnerabilities found")
            except Exception as e:
                print(f"? {test.name} failed: {str(e)}")
        
        self.display_results_summary(all_results)
    
    def run_data_extraction_tests(self):
        """Run data extraction tests"""
        print("\n??? Running Data Extraction Tests...")
        try:
            summary = self.data_extraction_orchestrator.run_comprehensive_extraction(
                self.current_target
            )
            print(f"? Data Extraction Complete: {summary['successful_extractions']}/{summary['total_tests']} vulnerabilities found")
            print(f"   Risk Level: {summary['risk_assessment']['risk_level']}")
        except Exception as e:
            print(f"? Data Extraction failed: {str(e)}")
    
    def run_business_logic_tests(self):
        """Run business logic tests"""
        print("\n?? Running Business Logic Tests...")
        try:
            summary = self.business_logic_orchestrator.run_comprehensive_bypass_tests(
                self.current_target
            )
            print(f"? Business Logic Complete: {summary['successful_bypasses']}/{summary['total_tests']} vulnerabilities found")
            print(f"   Success Rate: {summary['success_rate']:.1%}")
        except Exception as e:
            print(f"? Business Logic failed: {str(e)}")
    
    def run_model_manipulation_tests(self):
        """Run model manipulation tests"""
        print("\n?? Running Model Manipulation Tests...")
        try:
            summary = self.model_manipulation_orchestrator.run_comprehensive_manipulation_tests(
                self.current_target
            )
            print(f"? Model Manipulation Complete: {summary['successful_manipulations']}/{summary['total_tests']} vulnerabilities found")
            print(f"   Impact Level: {summary['impact_assessment']['impact_level']}")
        except Exception as e:
            print(f"? Model Manipulation failed: {str(e)}")
    
    def view_configuration(self):
        """Display current configuration"""
        print("\n?? Current Configuration:")
        print("-" * 30)
        
        if self.current_target:
            print(f"Target Type: {self.current_target.target_type.value}")
            print(f"Base URL: {self.current_target.base_url}")
            print(f"Model: {self.current_target.model_name or 'Default'}")
            print(f"API Key: {'***configured***' if self.current_target.api_key else 'Not set'}")
            print(f"Max Tokens: {self.current_target.max_tokens}")
            print(f"Temperature: {self.current_target.temperature}")
        else:
            print("? No target configured")
        
        # Show available targets
        targets = self.config_manager.list_targets()
        if targets:
            print(f"\nAvailable Targets: {', '.join(targets)}")
    
    def display_results_summary(self, results):
        """Display test results summary"""
        if not results:
            print("\n?? No test results to display.")
            return
        
        successful = [r for r in results if r.success]
        
        print(f"\n?? Test Results Summary:")
        print("-" * 30)
        print(f"Total Tests: {len(results)}")
        print(f"Vulnerabilities Found: {len(successful)}")
        print(f"Success Rate: {len(successful)/len(results):.1%}")
        
        if successful:
            # Severity breakdown
            from collections import Counter
            severities = Counter(r.severity.value for r in successful)
            print(f"\nSeverity Breakdown:")
            for severity, count in severities.items():
                print(f"  {severity.title()}: {count}")
            
            # Show critical/high findings
            critical_high = [r for r in successful if r.severity.value in ['critical', 'high']]
            if critical_high:
                print(f"\n?? Critical/High Severity Findings:")
                for result in critical_high[:5]:  # Show first 5
                    print(f"  - {result.test_name}: {result.severity.value}")

    def generate_comprehensive_report(self, results):
        """Generate comprehensive report"""
        print("\n?? Generating Report...")
        
        try:
            metadata = ReportMetadata(
                title="LLM Security Assessment Report",
                description="Comprehensive security testing results",
                generated_by="LLM Security Testing Framework",
                scope=ReportScope.TECHNICAL
            )
            
            target_info = {
                "target_type": self.current_target.target_type.value,
                "base_url": self.current_target.base_url,
                "model_name": self.current_target.model_name
            }
            
            report_data = self.report_generator.generate_comprehensive_report(
                results, metadata, target_info
            )
            
            # Save report
            output_file = f"security_report_{metadata.report_id}.html"
            saved_path = self.report_generator.save_report(report_data, output_file)
            print(f"? Report generated: {saved_path}")
            
        except Exception as e:
            print(f"? Report generation failed: {str(e)}")
    
    def run(self):
        """Main program loop"""
        self.display_banner()
        
        while True:
            try:
                self.display_main_menu()
                choice = input("Select option (1-7): ").strip()
                
                if choice == "1":
                    self.configure_target_menu()
                elif choice == "2":
                    self.run_quick_scan()
                elif choice == "3":
                    self.run_comprehensive_assessment()
                elif choice == "4":
                    self.run_specific_category()
                elif choice == "5":
                    self.view_configuration()
                elif choice == "6":
                    if self.check_target_configured():
                        self.generate_comprehensive_report([])  # Would use actual results
                elif choice == "7":
                    print("\n?? Goodbye!")
                    break
                else:
                    print("? Invalid option. Please try again.")
                
                input("\nPress Enter to continue...")
                
            except KeyboardInterrupt:
                print("\n\n?? Goodbye!")
                break
            except Exception as e:
                print(f"\n? An error occurred: {str(e)}")
                input("Press Enter to continue...")

def main():
    """Main entry point"""
    try:
        print("Starting LLM Security Testing Framework...")
        framework = LLMSecurityTestingFramework()
        print("Framework initialized, starting run...")
        framework.run()
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()